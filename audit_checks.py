"""Audit regression checks; SNI remains visible without ECH."""

import asyncio
import base64
import contextlib
import json
import logging
import secrets
import ssl
import struct
import unittest
from unittest.mock import patch

from aioquic.buffer import Buffer
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.packet import QuicFrameType, QuicPacketType, pull_quic_header
from aioquic.quic.packet_builder import QuicPacketBuilder

import test_tunnel as base
import tunnel
from transports import (ALPN, SecurityError, open_channel, quic_config,
                        serve_udp, shutdown_channels, tls_client)


def encoded(frame):
    data = json.dumps(frame).encode()
    return struct.pack("!I", len(data)) + data


class ScriptedWriter:
    def __init__(self, reader=None, gate=None):
        self.transport = self
        self.reader, self.gate = reader, gate
        self.blocked = asyncio.Event()
        self.closing = False
        self.last = None
        self.carrier_ready = True  # Scripted TLS fixture starts after HTTP CONNECT.

    def get_extra_info(self, name, default=None):
        return self if name == "ssl_object" else default

    def version(self):
        return "TLSv1.3"

    def selected_alpn_protocol(self):
        return ALPN

    def cipher(self):
        return ("test_cipher", "TLSv1.3", 256)

    def write(self, data):
        self.last = json.loads(data[4:])
        if self.last["type"] == "welcome":
            self.reader.feed_data(encoded(dict(type="ready", generation=self.last["generation"],
                                               transport=self.last["transport"])))

    async def drain(self):
        if self.gate and self.last["type"] == "ready_ok":
            self.blocked.set()
            await self.gate.wait()

    def abort(self):
        self.closing = True

    close = abort

    async def wait_closed(self):
        pass


class InitialClosePeer(asyncio.DatagramProtocol):
    """A peer with NO server certificate and NO application credentials."""
    def __init__(self):
        self.received = 0
        self.closed = asyncio.Event()

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        self.closed.set()

    def datagram_received(self, data, addr):
        header = pull_quic_header(Buffer(data=data), host_cid_length=8)
        self.received += 1
        crypto = CryptoPair()
        # QUIC Initial protection keys are public, derived from the observed CID.
        crypto.setup_initial(cid=header.destination_cid, is_client=False, version=header.version)
        builder = QuicPacketBuilder(host_cid=secrets.token_bytes(8), peer_cid=header.source_cid,
                                    version=header.version, is_client=False, max_datagram_size=1200)
        builder.start_packet(QuicPacketType.INITIAL, crypto)
        buf = builder.start_frame(QuicFrameType.TRANSPORT_CLOSE, capacity=16)
        buf.push_uint_var(0x12A)  # An untrusted peer can choose a TLS-like error code.
        buf.push_uint_var(0)
        buf.push_uint_var(0)
        for packet in builder.flush()[0]:
            self.transport.sendto(packet, addr)


class StateAudit(unittest.IsolatedAsyncioTestCase):
    async def test_client_ignores_superseded_ready_ok(self):
        session = tunnel.Session()
        session.established = True
        session.generation = session.next_generation = 1
        release, blocked = asyncio.Event(), asyncio.Event()
        tasks = []

        class ReplyReader(asyncio.StreamReader):
            def __init__(self, pause):
                super().__init__()
                self.pause, self.headers = pause, 0

            async def readexactly(self, n):
                if n == 4:
                    self.headers += 1
                    if self.pause and self.headers == 2:
                        blocked.set()
                        await release.wait()
                return await super().readexactly(n)

        class ReplyWriter(ScriptedWriter):
            def write(self, data):
                frame = json.loads(data[4:])
                if frame["type"] == "hello":
                    self.reader.feed_data(encoded(dict(type="welcome", version=tunnel.VERSION,
                                                       session=session.sid, secret=session.secret,
                                                       generation=frame["generation"], transport="a" * 32)))
                elif frame["type"] == "ready":
                    self.reader.feed_data(encoded(dict(type="ready_ok", generation=frame["generation"])))

        old_reader, new_reader = ReplyReader(True), ReplyReader(False)
        old, new = ReplyWriter(old_reader), ReplyWriter(new_reader)

        try:
            with patch("tunnel.open_channel") as opening:
                opening.side_effect = [(old_reader, old), (new_reader, new)]
                first = asyncio.create_task(tunnel.connect(session, ("unused", 1), "a" * 64, None, "unused"))
                tasks.append(first)
                await asyncio.wait_for(blocked.wait(), 1)
                await tunnel.connect(session, ("unused", 1), "a" * 64, None, "unused")
                release.set()
                with self.assertRaises(tunnel.SupersededError):
                    await first
                self.assertIs(session.writer, new)
                self.assertEqual(session.generation, 3)
                self.assertTrue(old.closing)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            session.close()

    async def test_old_generation_cannot_win_during_ready_ok_drain(self):
        session = tunnel.Session(target=("127.0.0.1", 1))
        session.generation = 1
        manager = tunnel.Server("a" * 64, session.target)
        session.client_id = "legacy"
        manager.sessions[session.sid] = session
        release, hold = asyncio.Event(), asyncio.Event()
        tasks = []

        async def parked(*args):
            await hold.wait()

        def candidate(generation, gate=None):
            reader = asyncio.StreamReader()
            reader.feed_data(encoded(dict(type="hello", version=tunnel.VERSION,
                                          key="a" * 64, session=session.sid,
                                          secret=session.secret, generation=generation)))
            return reader, ScriptedWriter(reader, gate)

        old_reader, old = candidate(2, release)
        new_reader, new = candidate(3)
        try:
            with patch.object(tunnel.Session, "run_transport", parked):
                tasks.append(asyncio.create_task(manager.accept(old_reader, old)))
                await asyncio.wait_for(old.blocked.wait(), 1)
                tasks.append(asyncio.create_task(manager.accept(new_reader, new)))
                await base.eventually(lambda: session.writer is new)
                release.set()
                await asyncio.wait_for(tasks[0], 1)
                self.assertEqual(session.generation, 3)
                self.assertIs(session.writer, new)
                self.assertTrue(old.closing)
                self.assertFalse(new.closing)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            session.close()

    async def test_failed_session_resets_application_instead_of_clean_eof(self):
        session = tunnel.Session()
        server = await asyncio.start_server(session.accept_local, "127.0.0.1", 0)
        reader, writer = await asyncio.open_connection(*server.sockets[0].getsockname()[:2])
        try:
            await base.eventually(lambda: bool(session.streams))
            downstream = session.streams[1].writer
            downstream.write(b"partial result")
            await downstream.drain()
            self.assertEqual(await reader.readexactly(14), b"partial result")
            session.close("unrecoverable failure")
            with self.assertRaises(ConnectionError):
                await asyncio.wait_for(reader.read(), 1)
        finally:
            session.close()
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            server.close()
            await server.wait_closed()

    async def test_rejected_local_connection_is_reset(self):
        session = tunnel.Session()
        session.close("already expired")
        server = await asyncio.start_server(session.accept_local, "127.0.0.1", 0)
        writer = None
        try:
            with self.assertRaises(ConnectionError):
                reader, writer = await asyncio.open_connection(*server.sockets[0].getsockname()[:2])
                await asyncio.wait_for(reader.read(), 1)
        finally:
            if writer:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
            server.close()
            await server.wait_closed()

    async def test_initial_connection_does_not_wait_for_alternative_probes(self):
        session = tunnel.Session(grace=1)

        async def samples(kind, *args):
            self.assertTrue(connected.is_set(), "a probe must not gate the initial handshake")
            await asyncio.sleep(2)
            raise TimeoutError

        controller = tunnel.AdaptiveClient(session, {"tcp": ("unused", 1), "udp": ("unused", 2)},
                                           "a" * 64, None, "unused", None)
        connected = asyncio.Event()

        async def attach(*args, **kwargs):
            writer = ScriptedWriter()
            session.attach(writer, "healthy")
            connected.set()
            return asyncio.StreamReader(), writer

        with patch("tunnel.probe", side_effect=samples), patch("tunnel.connect", side_effect=attach) as connector:
            task = asyncio.create_task(controller.run())
            try:
                await asyncio.wait_for(connected.wait(), 0.5)
                self.assertFalse(session.closed)
                self.assertEqual(controller.active, "tcp")
                connector.assert_awaited_once()
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_stalled_stream_does_not_block_other_stream_or_ack(self):
        session = tunnel.Session()
        entered, release = asyncio.Event(), asyncio.Event()

        class SlowSink:
            def __init__(self):
                self.data = bytearray()

            def write(self, data):
                self.data.extend(data)

            async def drain(self):
                entered.set()
                await release.wait()

            def abort(self):
                pass

            @property
            def transport(self):
                return self

        class FastSink(SlowSink):
            async def drain(self):
                pass

        slow, fast = SlowSink(), FastSink()
        session.streams[1] = tunnel.Stream(session, 1, writer=slow)
        session.streams[2] = tunnel.Stream(session, 2, writer=fast)
        try:
            session.receive(dict(type="data", stream=1, seq=1, offset=0,
                                 data=base64.b64encode(b"blocked").decode()))
            await asyncio.wait_for(entered.wait(), 1)
            delivery = session.streams[1].delivery
            session.attach(ScriptedWriter(), "replacement")
            session.receive(dict(type="data", stream=2, seq=2, offset=0,
                                 data=base64.b64encode(b"other stream").decode()))
            await base.eventually(lambda: session.rx_seq == 2 and fast.data == b"other stream")
            self.assertIs(session.streams[1].delivery, delivery)
            self.assertFalse(delivery.done())
            self.assertEqual(session.last_ack["seq"], 2)
            self.assertEqual(session.streams[1].rx_delivered, 0)
            release.set()
            await base.eventually(lambda: session.streams[1].rx_delivered == 7)
            self.assertEqual(slow.data, b"blocked", "migration must not write the chunk twice")
        finally:
            session.close()


class NetworkAudit(unittest.IsolatedAsyncioTestCase):
    setUpClass = classmethod(base.TunnelTests.setUpClass.__func__)
    tearDownClass = classmethod(base.TunnelTests.tearDownClass.__func__)
    asyncSetUp = base.TunnelTests.asyncSetUp
    asyncTearDown = base.TunnelTests.asyncTearDown

    async def test_private_alpn_removed_but_sni_remains_visible_without_ech(self):
        context = tls_client(self.cert)
        outgoing = ssl.MemoryBIO()
        connection = context.wrap_bio(ssl.MemoryBIO(), outgoing, server_hostname="private.example")
        with self.assertRaises(ssl.SSLWantReadError):
            connection.do_handshake()
        initial_wire = outgoing.read()
        self.assertNotIn(b"myownvpn", initial_wire)
        self.assertIn(ALPN.encode(), initial_wire)
        self.assertIn(b"private.example", initial_wire)

    async def test_unauthenticated_udp_close_preserves_working_tcp_session(self):
        logging.getLogger("quic").setLevel(logging.CRITICAL)
        transport, attacker = await asyncio.get_running_loop().create_datagram_endpoint(
            InitialClosePeer, local_addr=("127.0.0.1", 0))
        endpoint = transport.get_extra_info("sockname")[:2]
        controller = tunnel.AdaptiveClient(self.session, {"tcp": self.endpoint, "udp": endpoint},
                                           "a" * 64, self.context, "localhost",
                                           quic_config(ca=self.cert, hostname="localhost"))
        controller.active = "tcp"
        controller.runner = self.reconnector
        self.assertIsNotNone(self.session.writer)
        self.assertEqual(self.session.path, "tcp")
        self.session.grace = 12
        task = asyncio.create_task(controller.run())
        try:
            await base.eventually(lambda: controller.selector.stats["udp"].attempts > 0, timeout=7)
            self.assertGreater(attacker.received, 0)
            self.assertFalse(self.session.closed)
            self.assertEqual(self.session.path, "tcp")
            reader, application = await asyncio.open_connection(*self.local.sockets[0].getsockname()[:2])
            try:
                application.write(b"trusted tcp survives")
                await application.drain()
                self.assertEqual(await reader.readexactly(20), b"trusted tcp survives")
            finally:
                application.close()
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            transport.abort()
            await attacker.closed.wait()
            await shutdown_channels()

    async def test_quic_peer_without_access_key_cannot_keep_handshake_slot(self):
        with patch("transports.AUTH_TIMEOUT", 0.3):
            udp, tasks = await serve_udp(self.manager, ("127.0.0.1", 0),
                                        quic_config(cert=self.cert, key=self.keyfile))
            # The deadline is captured when the connection is created, too.
            endpoint = udp._transport.get_extra_info("sockname")[:2]
            reader, writer = await open_channel("udp", endpoint, self.context, "localhost",
                                                quic_config(ca=self.cert, hostname="localhost"))
        initial_sessions = len(self.manager.sessions)
        try:
            async def keepalive():
                while not writer.protocol._closed.is_set():
                    with contextlib.suppress(ConnectionError):
                        await writer.protocol.ping()
                    await asyncio.sleep(0.03)

            pings = asyncio.create_task(keepalive())
            await asyncio.wait_for(writer.protocol.wait_closed(), 2)
            await base.eventually(lambda: not udp._protocols)
            pings.cancel()
            await asyncio.gather(pings, return_exceptions=True)
            self.assertEqual(len(self.manager.sessions), initial_sessions)
            self.assertFalse(udp._protocols)
            self.assertFalse(tasks)
        finally:
            writer.close()
            await shutdown_channels()
            await udp.aclose()
            for task in list(tasks):
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_quic_reassembly_is_bounded_before_access_key(self):
        udp, tasks = await serve_udp(self.manager, ("127.0.0.1", 0),
                                    quic_config(cert=self.cert, key=self.keyfile))
        endpoint = udp._transport.get_extra_info("sockname")[:2]
        reader, writer = await open_channel("udp", endpoint, self.context, "localhost",
                                            quic_config(ca=self.cert, hostname="localhost"))
        try:
            connection = writer.protocol._quic
            # Leave byte 0 missing: valid out-of-order STREAM data is reassembled
            # below StreamDataReceived, before our adapter's 96 KiB check runs.
            connection.send_stream_data(0, b"")
            sender = connection._streams[0].sender
            sender._buffer_start = sender._buffer_stop = 1
            connection.send_stream_data(0, b"x" * (256 * 1024))
            writer.protocol.transmit()

            def buffered():
                protocols = list(set(udp._protocols.values()))
                if not protocols:
                    return 0
                stream = protocols[0]._quic._streams.get(0)
                return len(stream.receiver._buffer) if stream else 0

            await base.eventually(lambda: buffered() >= 96 * 1024, timeout=5)
            await asyncio.sleep(0.2)
            self.assertLessEqual(buffered(), 96 * 1024)
            remote = writer.protocol._quic._streams[0].max_stream_data_remote
            self.assertEqual(remote, 96 * 1024, "sparse reception must not grant more credits")
            self.assertFalse(tasks, "no PSK-authenticated application handler was ever started")
        finally:
            writer.close()
            await shutdown_channels()
            await udp.aclose()
            for task in list(tasks):
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
