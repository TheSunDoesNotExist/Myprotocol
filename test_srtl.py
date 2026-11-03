"""SRTL budgets, independent direction settings, liveness and replay safety."""

import asyncio
import base64
import json
import struct
import unittest
from unittest.mock import patch

import test_adaptive as adaptive
import test_tunnel as base
from srtl import SRTL, COVER_SIZES, MAX_PADDING, RX_COVER_BURST, TAIL_MAX_BYTES, collect
from transports import open_channel, quic_config, serve_udp, shutdown_channels
from tunnel import ProtocolError, Session, Stream, connect, read_frame, write_frame


class Recorder:
    def __init__(self):
        self.transport = self
        self.kind = "tcp"
        self.frames = []
        self.closing = False

    def write(self, data):
        self.frames.append(data)

    async def drain(self):
        pass

    def abort(self):
        self.closing = True

    close = abort


def data_frame(seq=1, data=b"x" * 8192):
    return dict(type="data", seq=seq, stream=1, offset=0, data=base64.b64encode(data).decode())


def encoded(frame, size=None):
    body = json.dumps(frame, separators=(",", ":")).encode()
    if size:
        body = body.ljust(size - 4, b" ")
    return struct.pack("!I", len(body)) + body


class SrtlPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_padding_budget_replays_and_plaintext_roundtrip(self):
        policy = SRTL(True)
        recorder = Recorder()
        useful = 0
        for seq in range(1, 101):
            payload = b"x" * (seq * 37)
            frame = data_frame(seq, payload)
            useful += len(payload)
            await write_frame(recorder, frame, srtl=policy)
            packet = recorder.frames[-1]
            original = encoded(frame)
            extra = len(packet) - len(original)
            self.assertLessEqual(extra, MAX_PADDING)
            if extra:
                self.assertEqual(len(packet) % 128, 0)
            reader = asyncio.StreamReader()
            reader.feed_data(packet)
            self.assertEqual(await read_frame(reader), frame)
        self.assertGreater(policy.padding_bytes, 0)
        self.assertLessEqual(policy.padding_bytes, useful / 10)
        policy.credit = 0
        before = policy.padding_bytes
        await write_frame(recorder, data_frame(1), srtl=policy)
        self.assertEqual(policy.credit, 0, "replay must not mint padding credits")
        self.assertEqual(policy.padding_bytes, before)
        plain = SRTL(False)
        await write_frame(recorder, data_frame(), srtl=plain)
        self.assertEqual(recorder.frames[-1], encoded(data_frame()))

    async def test_cover_schema_and_padding_are_bounded(self):
        invalid = [encoded(dict(type="cover")), encoded(dict(type="cover", seq=1), 256),
                   encoded(dict(type="ping"), 1024)]
        for packet in invalid:
            reader = asyncio.StreamReader()
            reader.feed_data(packet)
            with self.assertRaises(ProtocolError):
                await read_frame(reader)
        reader = asyncio.StreamReader()
        reader.feed_data(encoded(dict(type="cover"), 384))
        self.assertEqual((await read_frame(reader))["_wire_size"], 384)

    async def test_coalescing_obeys_credit_and_control_is_not_delayed(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"bc")
        reader.feed_eof()
        self.assertEqual(await collect(reader, b"a", 2, SRTL(True)), b"ab")
        self.assertEqual(await reader.read(), b"c")
        policy = SRTL(True)
        reader = asyncio.StreamReader()
        self.assertEqual(await collect(reader, b"a", 10, policy), b"a")
        entered = asyncio.Event()

        class Source(asyncio.StreamReader):
            async def read(self, size=-1):
                if not self._buffer:
                    entered.set()
                return await super().read(size)

        session, recorder = Session(srtl=True), Recorder()
        source = Source()
        source.feed_data(b"a")
        stream = session.streams[1] = Stream(session, 1, source, Recorder())
        session.attach(recorder, "test")
        try:
            with patch("srtl.BATCH_MIN", 0.1), patch("srtl.BATCH_MAX", 0.1):
                stream.start()
                await asyncio.wait_for(entered.wait(), 1)
                await session.send(dict(type="ack", seq=1, stream=1, offset=1))
                self.assertEqual(json.loads(recorder.frames[0][4:])["type"], "ack")
                source.feed_data(b"bc")
                source.feed_eof()
                await base.eventually(lambda: stream.local_fin)
                self.assertEqual(stream.tx, 3)
                self.assertGreater(session.srtl.merged_reads, 0)
        finally:
            session.close()
            await session.wait_closed()

    async def test_tail_stops_in_idle_on_disable_and_on_transport_change(self):
        session, writer = Session(srtl=True), Recorder()
        session.attach(writer, "first")
        try:
            await session.send(data_frame())
            await base.eventually(lambda: session.srtl.cover_tx >= 4, timeout=3)
            await asyncio.sleep(1.5)
            count = session.srtl.cover_tx
            self.assertLessEqual(count, 8)
            self.assertLessEqual(session.srtl.cover_bytes_tx, TAIL_MAX_BYTES)
            self.assertEqual(session.tx_seq, 0)
            self.assertFalse(session.inflight)
            self.assertTrue(session.pending.empty())
            await session.send(data_frame(2))
            await asyncio.sleep(0.3)
            self.assertEqual(session.srtl.cover_tx, count, "new burst cannot bypass the cooldown")
            session.detach(writer)
            replacement = Recorder()
            session.attach(replacement, "second")
            await asyncio.sleep(0.25)
            self.assertFalse(replacement.frames, "old tail must not replay on a new channel")
            session.set_srtl(False)
            await session.send(data_frame(3))
            await asyncio.sleep(0.3)
            self.assertEqual(session.srtl.cover_tx, count)
        finally:
            session.close()
            await session.wait_closed()
        self.assertTrue(session.shaping.done())

    async def test_cover_receive_budget_is_enforced_even_when_tx_disabled(self):
        session, writer = Session(), Recorder()
        reader = asyncio.StreamReader()
        reader.feed_data(encoded(dict(type="cover"), 512) * (RX_COVER_BURST // 512 + 2))
        session.attach(writer, "test")
        try:
            await session.run_transport(reader, writer)
            self.assertEqual(session.reason, "SRTL cover budget exceeded")
            self.assertGreater(session.srtl.cover_rx, 0)
            self.assertEqual(session.rx_seq, 0)
            self.assertFalse(writer.frames, "cover must not elicit ACKs or echo")
        finally:
            session.close()
            await session.wait_closed()

    async def test_cover_cannot_keep_a_dead_path_alive(self):
        with patch("tunnel.DEAD_TRANSPORT", 0.15), patch("tunnel.HEARTBEAT", 0.03):
            session, writer, reader = Session(grace=1), Recorder(), asyncio.StreamReader()
            session.attach(writer, "test")

            async def cover_only():
                while True:
                    reader.feed_data(encoded(dict(type="cover"), 256))
                    await asyncio.sleep(0.02)

            producer = asyncio.create_task(cover_only())
            receiver = asyncio.create_task(session.run_transport(reader, writer))
            try:
                await base.eventually(lambda: session.writer is None, timeout=1)
                self.assertGreater(session.srtl.cover_rx, 0)
                self.assertFalse(session.closed)
            finally:
                session.close()
                producer.cancel()
                receiver.cancel()
                await asyncio.gather(producer, receiver, return_exceptions=True)
                await session.wait_closed()


class SrtlNetworkTests(unittest.IsolatedAsyncioTestCase):
    setUpClass = classmethod(base.TunnelTests.setUpClass.__func__)
    tearDownClass = classmethod(base.TunnelTests.tearDownClass.__func__)

    async def asyncSetUp(self):
        await base.TunnelTests.asyncSetUp(self)
        self.reconnector.cancel()
        await asyncio.gather(self.reconnector, return_exceptions=True)
        self.udp, self.udp_tasks = await serve_udp(self.manager, ("127.0.0.1", 0),
                                                   quic_config(cert=self.cert, key=self.keyfile))
        self.endpoints = {"tcp": self.endpoint, "udp": self.udp._transport.get_extra_info("sockname")[:2]}
        self.runners = []

    async def asyncTearDown(self):
        self.session.close()
        self.manager.close()
        await self.udp.aclose()
        for task in [*self.runners, *self.udp_tasks]:
            task.cancel()
        await asyncio.gather(*self.runners, *self.udp_tasks, return_exceptions=True)
        await base.TunnelTests.asyncTearDown(self)
        await shutdown_channels()

    async def test_independent_settings_and_live_toggles_across_tcp_udp_tcp(self):
        source = writer = None
        sid = self.session.sid
        peer = next(iter(self.manager.sessions.values()))
        try:
            for client_on, server_on in ((True, False), (False, True), (True, True), (False, False)):
                self.session.set_srtl(client_on)
                self.manager.set_srtl(server_on)
                before = (self.session.srtl.padding_bytes, peer.srtl.padding_bytes)
                for kind in ("tcp", "udp", "tcp"):
                    reader, secured = await connect(self.session, self.endpoints[kind], "a" * 64,
                        self.context, "localhost", kind=kind, quic=quic_config(ca=self.cert, hostname="localhost"))
                    self.runners.append(asyncio.create_task(self.session.run_transport(reader, secured)))
                    if writer is None:
                        source, writer = await base.TunnelTests.local_connect(self)
                    payload = b"protected application bytes" * 3000
                    writer.write(payload)
                    await writer.drain()
                    self.assertEqual(await asyncio.wait_for(source.readexactly(len(payload)), 4), payload)
                    self.assertEqual(self.session.sid, sid)
                self.assertEqual(self.session.srtl.padding_bytes > before[0], client_on)
                self.assertEqual(peer.srtl.padding_bytes > before[1], server_on)
                if client_on and not server_on:
                    await base.eventually(lambda: peer.srtl.cover_rx > 0, timeout=2)
                    self.assertEqual(peer.srtl.cover_tx, 0)
                if server_on and not client_on:
                    try:
                        await base.eventually(lambda: self.session.srtl.cover_rx > 0, timeout=2)
                    except TimeoutError:
                        self.fail(f"tail tx={peer.srtl.cover_tx}, data={bool(peer.srtl.last_data)}, "
                                  f"cooldown={peer.srtl.next_tail - asyncio.get_running_loop().time():.3f}, "
                                  f"worker_done={peer.shaping.done()}, sends={peer.data_sends}, "
                                  f"pending={peer.pending.qsize()}, windows={len(peer.windows)}")
            writer.write_eof()
            self.assertEqual(await asyncio.wait_for(source.read(), 3), b"")
            self.assertEqual(self.connections, 1)
        finally:
            if writer:
                writer.close()

    async def test_cover_before_private_hello_cannot_allocate_session(self):
        before = len(self.manager.sessions)
        reader, writer = await open_channel("tcp", self.endpoint, self.context, "localhost", key="a" * 64)
        try:
            await write_frame(writer, dict(type="cover"), srtl=SRTL(True))
            self.assertEqual((await read_frame(reader))["type"], "rejected")
            self.assertEqual(len(self.manager.sessions), before)
        finally:
            writer.close()
            await writer.wait_closed()


class SrtlReplayTests(unittest.IsolatedAsyncioTestCase):
    setUpClass = classmethod(base.TunnelTests.setUpClass.__func__)
    tearDownClass = classmethod(base.TunnelTests.tearDownClass.__func__)
    asyncSetUp = adaptive.AdaptiveTests.asyncSetUp
    asyncTearDown = adaptive.AdaptiveTests.asyncTearDown
    local_connect = base.TunnelTests.local_connect
    round_trip = base.TunnelTests.round_trip

    async def test_lost_ack_replay_remains_exact_with_srtl(self):
        self.session.set_srtl(True)
        self.manager.set_srtl(True)
        await adaptive.AdaptiveTests.test_tcp_to_quic_after_data_delivery_before_ack(self)


if __name__ == "__main__":
    unittest.main()
