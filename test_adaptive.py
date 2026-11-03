import asyncio
import io
import json
import logging
import os
import ssl
import unittest
from unittest.mock import patch

from diagnostics import JsonFormatter, event
from selection import Selector
import test_tunnel as base
from transports import (BUFFER_LIMIT, SecurityError, open_channel, quic_config, serve_tcp, serve_udp,
                        shutdown_channels, tls_client)
from tunnel import AdaptiveClient, Session, connect, read_frame, write_frame, VERSION


class PolicyTests(unittest.TestCase):
    def test_recovered_tcp_wins_when_paths_are_close(self):
        selector = Selector(cooldown=0, wins=3)
        for now in (100, 101, 102):
            selector.stats["tcp"].update([1, 1, 1], now=now)
            selector.stats["udp"].update([0.5, 0.5, 0.5], now=now)
            selected, _ = selector.choose("udp", now=now)
            self.assertEqual(selected, "tcp" if now == 102 else "udp")

    def test_tcp_preference_and_hysteresis(self):
        selector = Selector(cooldown=10, wins=3)
        selector.stats["tcp"].update([20, 21, 19], now=100)
        selector.stats["udp"].update([12, 13, 11], now=100)
        self.assertEqual(selector.choose(now=100)[0], "tcp")
        selector.stats["tcp"].rtt_ms = 200
        selector.switched = 95
        self.assertEqual(selector.choose("tcp", now=100)[0], "tcp")
        selector.stats["udp"].update([12, 13, 11], now=101)
        self.assertEqual(selector.choose("tcp", now=101)[0], "tcp")
        self.assertEqual(selector.streak, 2)
        self.assertEqual(selector.choose("tcp", now=102)[0], "tcp")
        self.assertEqual(selector.streak, 2, "the same measurement cannot count twice")
        selector.stats["udp"].update([12, 13, 11], now=106)
        self.assertEqual(selector.choose("tcp", now=106)[0], "udp")
        selector.stats["tcp"].update(now=107)
        self.assertEqual(selector.choose("tcp", now=107)[0], "udp")
        self.assertIsNone(selector.choose(now=130)[0], "stale probes are unusable")

    def test_metadata_logs_do_not_include_secrets_or_payload(self):
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        handler.setFormatter(JsonFormatter())
        logger = logging.getLogger("tunnel")
        before = logger.level
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        try:
            event("test", key="private-key-value", secret="resume-secret-value",
                  data="private-payload-value", reason="network_error", rtt_ms=10)
        finally:
            logger.removeHandler(handler)
            logger.setLevel(before)
        record = json.loads(output.getvalue())
        self.assertEqual(record["reason"], "network_error")
        self.assertEqual(record["rtt_ms"], 10)
        for value in ("private-key-value", "resume-secret-value", "private-payload-value"):
            self.assertNotIn(value, output.getvalue())

    def test_no_key_logging_and_no_quic_zero_rtt(self):
        config = quic_config(ca="unused", hostname="localhost")
        self.assertEqual(config.verify_mode, ssl.CERT_REQUIRED)
        self.assertIsNone(config.secrets_log_file)
        self.assertIsNone(config.session_ticket)


class UdpRelay(asyncio.DatagramProtocol):
    def __init__(self, server):
        self.server = server
        self.client = None
        self.drop = False
        self.received = []
        self.count = 0
        self.drop_every = 0
        self.corrupt = False

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.count += 1
        if len(self.received) < 300:
            self.received.append(data)
        if self.drop or (self.drop_every and self.count % self.drop_every == 0):
            return
        if addr == self.server:
            destination = self.client
        else:
            self.client = addr
            destination = self.server
        if destination:
            if self.corrupt:
                data = data[:-1] + bytes([data[-1] ^ 1])
            self.transport.sendto(data, destination)


class BlackholeTransport:
    def __init__(self, transport):
        self.transport = transport

    def sendto(self, data, address):
        pass

    def abort(self):
        self.transport.abort()


class AdaptiveTests(unittest.IsolatedAsyncioTestCase):
    setUpClass = classmethod(base.TunnelTests.setUpClass.__func__)
    tearDownClass = classmethod(base.TunnelTests.tearDownClass.__func__)
    local_connect = base.TunnelTests.local_connect
    round_trip = base.TunnelTests.round_trip

    async def asyncSetUp(self):
        logging.getLogger("quic").setLevel(logging.CRITICAL)
        await base.TunnelTests.asyncSetUp(self)
        self.reconnector.cancel()
        await asyncio.gather(self.reconnector, return_exceptions=True)
        self.session.grace = self.manager.grace = 12
        for session in self.manager.sessions.values():
            session.grace = 12
        self.quic = quic_config(ca=self.cert, hostname="localhost")
        self.udp, self.udp_tasks = await serve_udp(
            self.manager, ("127.0.0.1", 0), quic_config(cert=self.cert, key=self.keyfile))
        self.udp_endpoint = self.udp._transport.get_extra_info("sockname")[:2]
        self.relay_transport, self.relay = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: UdpRelay(self.udp_endpoint), local_addr=("127.0.0.1", 0))
        self.relay_endpoint = self.relay_transport.get_extra_info("sockname")[:2]
        self.controller = AdaptiveClient(self.session, {"tcp": self.endpoint, "udp": self.udp_endpoint},
                                         "a" * 64, self.context, "localhost", self.quic,
                                         interval=0.3)
        self.controller.selector.cooldown = 0
        self.controller.selector.wins = 2
        self.reconnector = asyncio.create_task(self.controller.run())
        await base.eventually(lambda: self.controller.active is not None)

    async def asyncTearDown(self):
        self.reconnector.cancel()
        await asyncio.gather(self.reconnector, return_exceptions=True)
        await self.udp.aclose()
        tasks = list(self.udp_tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.relay_transport.abort()
        await base.TunnelTests.asyncTearDown(self)
        await shutdown_channels()

    async def test_auto_tcp_to_udp_and_back_preserves_live_socket(self):
        reader, writer = await self.local_connect()
        try:
            for phase in range(3):
                payload = b"secret application bytes" + os.urandom(200_000)
                writer.write(payload)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 12), payload)
                if phase == 0:
                    self.assertEqual(self.controller.active, "tcp")
                    self.tls.close()  # TCP becomes unavailable; UDP remains reachable.
                    server_session = next(iter(self.manager.sessions.values()))
                    server_session.detach(server_session.writer)
                    await base.eventually(lambda: self.controller.active == "udp", timeout=8)
                elif phase == 1:
                    await self.tls.wait_closed()
                    self.tls = await serve_tcp(self.manager, self.endpoint, self.server_context)
                    await base.eventually(lambda: self.controller.active == "tcp", timeout=12)
            self.assertEqual(self.connections, 1)
            self.assertEqual(len(self.manager.sessions), 1)
        finally:
            writer.close()

    async def test_quic_loss_and_encryption(self):
        # Stop automatic changes; keep this test on the encrypted UDP relay.
        self.reconnector.cancel()
        await asyncio.gather(self.reconnector, return_exceptions=True)
        # Cancellation closes the session; use a fresh one for this isolated path.
        self.session = Session(grace=12)
        self.local.close()
        await self.local.wait_closed()
        self.local = await asyncio.start_server(self.session.accept_local, "127.0.0.1", 0)
        reader, writer = await connect(self.session, self.relay_endpoint, "a" * 64,
                                       self.context, "localhost", kind="udp", quic=self.quic)
        self.reconnector = asyncio.create_task(self.session.run_transport(reader, writer))
        self.relay.drop_every = 7
        marker = b"THIS-PLAINTEXT-MUST-NOT-APPEAR-ON-THE-UDP-WIRE-" * 400
        self.assertEqual(await self.round_trip(marker), marker)
        wire = b"".join(self.relay.received)
        self.assertNotIn(marker[:80], wire)
        self.assertNotIn(b"a" * 64, wire)
        self.assertNotIn(self.session.secret.encode(), wire)
        self.assertGreater(self.relay.count, 7)
        self.assertEqual(self.connections, 1)
        self.relay.drop_every = 0
        self.relay.corrupt = True
        transfer = asyncio.create_task(self.round_trip(b"authenticated-data" * 1000))
        await asyncio.sleep(0.2)
        self.assertFalse(transfer.done(), "tampered packets must not deliver data")
        self.relay.corrupt = False
        self.assertEqual(await transfer, b"authenticated-data" * 1000)

    async def test_silent_udp_blackhole_falls_back_without_data_loss(self):
        await self.controller.switch("udp", "test_udp_path")
        self.controller.selector.cooldown = 1000
        reader, writer = await self.local_connect()
        try:
            writer.write(b"before blackhole")
            await writer.drain()
            self.assertEqual(await reader.readexactly(16), b"before blackhole")
            protocol = self.session.writer.protocol
            protocol._transport = BlackholeTransport(protocol._transport)
            protocol.datagram_received = lambda data, addr: None
            data = os.urandom(200_000)
            writer.write(data)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(data)), 12), data)
            self.assertEqual(self.controller.active, "tcp")
            self.assertEqual(self.connections, 1)
            self.assertGreater(self.session.replayed, 0)
        finally:
            writer.close()

    async def test_quic_wrong_host_and_key_are_rejected(self):
        with patch.dict(os.environ, {"SSLKEYLOGFILE": "should-not-exist.log"}):
            self.assertIsNone(tls_client(self.cert).keylog_filename)
        with self.assertRaises(SecurityError):
            await open_channel("udp", self.udp_endpoint, self.context, "wrong-host",
                               quic_config(ca=self.cert, hostname="wrong-host"))
        fresh = Session(grace=12)
        try:
            with self.assertRaises(SecurityError):
                await connect(fresh, self.udp_endpoint, "b" * 64, self.context,
                              "localhost", kind="udp", quic=self.quic)
        finally:
            fresh.close()

    async def test_stale_generation_cannot_steal_session(self):
        original = self.session.transport_id
        reader, writer = await open_channel("udp", self.udp_endpoint, self.context,
                                            "localhost", self.quic, key="a" * 64)
        try:
            await write_frame(writer, dict(type="hello", version=VERSION, key="a" * 64,
                                          session=self.session.sid, secret=self.session.secret,
                                          generation=self.session.generation))
            self.assertEqual((await read_frame(reader))["type"], "rejected")
            self.assertEqual(self.session.transport_id, original)
            self.assertEqual(await self.round_trip(b"still live"), b"still live")
        finally:
            writer.close()

    async def test_unconfirmed_candidate_does_not_interrupt_active_path(self):
        original = self.session.transport_id
        reader, writer = await open_channel("udp", self.udp_endpoint, self.context,
                                            "localhost", self.quic, key="a" * 64)
        try:
            await write_frame(writer, dict(type="hello", version=VERSION, key="a" * 64,
                                          session=self.session.sid, secret=self.session.secret,
                                          generation=self.session.generation + 1))
            self.assertEqual((await read_frame(reader))["type"], "welcome")
            # No READY: the server must retain the existing authenticated channel.
            self.assertEqual(await self.round_trip(b"old channel stays alive"), b"old channel stays alive")
            self.assertEqual(self.session.transport_id, original)
        finally:
            writer.close()

    async def test_tcp_to_quic_after_data_delivery_before_ack(self):
        server_session = next(iter(self.manager.sessions.values()))
        send = server_session.send
        dropped = False

        async def lose_ack(frame):
            nonlocal dropped
            if frame["type"] == "ack" and frame["offset"] > 0 and not dropped:
                dropped = True
                self.tls.close()
                server_session.detach(server_session.writer)
                return
            await send(frame)

        server_session.send = lose_ack
        payload = os.urandom(512 * 1024)
        self.assertEqual(await self.round_trip(payload), payload)
        self.assertTrue(dropped)
        self.assertEqual(self.controller.active, "udp")
        self.assertEqual(self.connections, 1)
        self.assertGreater(self.session.replayed, 0)
        self.assertGreater(self.session.writer.protocol.receive_window.consumed, BUFFER_LIMIT)

    async def test_candidate_certificate_failure_preserves_authenticated_path(self):
        async def bad_probe(kind, *args):
            if kind == "udp":
                raise SecurityError("certificate verification failed")
            return [1, 1, 1]

        with patch("tunnel.probe", side_effect=bad_probe):
            await self.controller.measure()
        self.assertIn("udp", self.controller.quarantined)
        self.assertFalse(self.controller.selector.stats["udp"].available)
        self.assertEqual(await self.round_trip(b"trusted path survives"), b"trusted path survives")
        self.assertFalse(self.session.closed)

    async def test_all_candidates_rejected_stops_without_plaintext_fallback(self):
        self.reconnector.cancel()
        await asyncio.gather(self.reconnector, return_exceptions=True)
        session = Session(grace=12)
        controller = AdaptiveClient(session, {"tcp": self.endpoint, "udp": self.udp_endpoint},
                                    "a" * 64, self.context, "localhost", self.quic)
        with patch("tunnel.probe") as probing, \
                patch("tunnel.connect", side_effect=SecurityError("verification failed")) as connector:
            await asyncio.wait_for(controller.run(), 3)
            self.assertEqual(connector.await_count, 2)
            probing.assert_not_called()
        self.assertTrue(session.closed)
        self.assertEqual(session.reason, "no_authenticated_path")

    async def test_initial_handshake_succeeds_when_all_standalone_probes_fail(self):
        self.reconnector.cancel()
        await asyncio.gather(self.reconnector, return_exceptions=True)
        session = Session(grace=5)
        controller = AdaptiveClient(session, {"tcp": self.endpoint, "udp": self.udp_endpoint},
                                    "a" * 64, self.context, "localhost", self.quic, interval=.1)
        measured = asyncio.Event()
        async def failed_probe(*args):
            self.assertTrue(session.connected_once)
            measured.set()
            raise TimeoutError
        task = local = writer = None
        try:
            with patch("tunnel.probe", side_effect=failed_probe):
                task = asyncio.create_task(controller.run())
                await base.eventually(lambda: controller.active == "tcp")
                await asyncio.wait_for(measured.wait(), 2)
                local = await asyncio.start_server(session.accept_local, "127.0.0.1", 0)
                reader, writer = await asyncio.open_connection(*local.sockets[0].getsockname()[:2])
                writer.write(b"connected without prerequisite probes")
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(37), 3), b"connected without prerequisite probes")
                self.assertEqual(controller.active, "tcp")
                self.assertNotIn("tcp", controller.quarantined)
        finally:
            if writer:
                writer.close()
            if task:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            if local:
                local.close()
                await local.wait_closed()
            session.close()
            await session.wait_closed()

    async def test_reconnect_uses_protocol_even_when_probe_scores_are_unavailable(self):
        reader, writer = await self.local_connect()
        try:
            writer.write(b"before")
            await writer.drain()
            self.assertEqual(await reader.readexactly(6), b"before")
            with patch("tunnel.probe", side_effect=TimeoutError):
                self.tls.close()
                server_session = next(iter(self.manager.sessions.values()))
                server_session.detach(server_session.writer)
                await base.eventually(lambda: self.controller.active == "udp", timeout=8)
                payload = os.urandom(100_000)
                writer.write(payload)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 5), payload)
                self.assertEqual(self.connections, 1)
        finally:
            writer.close()

    async def test_initial_tcp_tls_timeout_falls_back_to_authenticated_udp(self):
        self.reconnector.cancel()
        await asyncio.gather(self.reconnector, return_exceptions=True)
        pending = set()
        async def blackhole(reader, writer):
            task = asyncio.current_task()
            pending.add(task)
            try:
                await reader.read()
            finally:
                writer.close()
                pending.discard(task)
        blocked = await asyncio.start_server(blackhole, "127.0.0.1", 0)
        session = Session(grace=10)
        controller = AdaptiveClient(session, {"tcp": blocked.sockets[0].getsockname()[:2], "udp": self.udp_endpoint},
                                    "a" * 64, self.context, "localhost", self.quic)
        async def failed_probe(*args):
            self.assertTrue(session.connected_once)
            raise TimeoutError
        task = None
        try:
            with patch("tunnel.probe", side_effect=failed_probe):
                task = asyncio.create_task(controller.run())
                await base.eventually(lambda: controller.active == "udp", timeout=7)
                self.assertTrue(session.established)
                self.assertIsNotNone(self.manager.sessions.get(session.sid))
                self.assertEqual(session.writer.kind, "udp")
        finally:
            if task:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            session.close()
            await session.wait_closed()
            blocked.close()
            await blocked.wait_closed()
            for task in list(pending):
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    async def test_slow_alternative_probe_cannot_hide_active_channel_rtt(self):
        self.reconnector.cancel()
        await asyncio.gather(self.reconnector, return_exceptions=True)
        session = Session(grace=5)
        controller = AdaptiveClient(session, {"tcp": self.endpoint, "udp": self.udp_endpoint},
                                    "a" * 64, self.context, "localhost", self.quic)
        measured = asyncio.Event()
        async def slow_probe(*args):
            await asyncio.sleep(1.2)
            measured.set()
            return [1000, 1000, 1000]
        with patch("tunnel.probe", side_effect=slow_probe):
            task = asyncio.create_task(controller.run())
            try:
                await asyncio.wait_for(measured.wait(), 4)
                await asyncio.sleep(.15)
                self.assertEqual(controller.active, "tcp")
                self.assertTrue(controller.selector.stats["tcp"].available)
                self.assertLess(controller.selector.stats["tcp"].rtt_ms, 1000)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_probe_cleanup_cannot_delay_actual_reconnection(self):
        self.reconnector.cancel()
        await asyncio.gather(self.reconnector, return_exceptions=True)
        session = Session(grace=8)
        controller = AdaptiveClient(session, {"tcp": self.endpoint, "udp": self.udp_endpoint},
                                    "a" * 64, self.context, "localhost", self.quic)
        entered, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def stalled_measure():
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaning.set()
                await release.wait()
        with patch.object(controller, "measure", side_effect=stalled_measure):
            task = asyncio.create_task(controller.run())
            try:
                await asyncio.wait_for(entered.wait(), 3)
                measurement = controller.probing
                self.tls.close()
                server_session = self.manager.sessions[session.sid]
                server_session.detach(server_session.writer)
                await asyncio.wait_for(cleaning.wait(), 3)
                await base.eventually(lambda: controller.active == "udp", timeout=3)
                self.assertFalse(release.is_set())
                self.assertIs(controller.probing, measurement, "only one measurement group may remain outstanding")
                self.assertFalse(measurement.done())
            finally:
                release.set()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
