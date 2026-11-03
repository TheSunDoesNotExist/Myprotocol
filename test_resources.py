"""Connection budgets, bounded QUIC output and cancellation ownership."""

import asyncio
import contextlib
import unittest
from unittest.mock import patch

import test_tunnel as base
import transports
from transports import (SEND_LIMIT, open_channel, quic_config, serve_tcp, serve_udp,
                        shutdown_channels, tls_client, tls_server)
from tunnel import CHUNK, VERSION, AdaptiveClient, Server, Session, Stream, read_frame, write_frame


class ResourceTests(unittest.IsolatedAsyncioTestCase):
    setUpClass = classmethod(base.TunnelTests.setUpClass.__func__)
    tearDownClass = classmethod(base.TunnelTests.tearDownClass.__func__)

    async def asyncSetUp(self):
        self.manager = Server("a" * 64, ("127.0.0.1", 1))
        self.server = await serve_tcp(self.manager, ("127.0.0.1", 0),
                                      tls_server(self.cert, self.keyfile))
        self.endpoint = self.server.sockets[0].getsockname()[:2]
        self.context = tls_client(self.cert)

    async def asyncTearDown(self):
        self.manager.close()
        self.server.close()
        await self.server.wait_closed()
        await self.manager.wait_closed()
        await shutdown_channels()

    async def test_tcp_budgets_apply_before_tls_and_release_slots(self):
        for quota in ("MAX_CONNECTIONS", "MAX_PENDING", "MAX_PENDING_PER_IP"):
            writers = []
            with self.subTest(quota=quota), patch.object(transports, quota, 2):
                try:
                    for _ in range(2):
                        _, writer = await asyncio.open_connection(*self.endpoint)
                        writers.append(writer)
                    await base.eventually(lambda: len(self.server.clients) == 2)
                    reader, writer = await asyncio.open_connection(*self.endpoint)
                    writers.append(writer)
                    self.assertEqual(await asyncio.wait_for(reader.read(1), 1), b"")
                    self.assertFalse(self.manager.connections, "no TLS handshake has completed")
                    self.assertEqual(len(self.server.clients), 2)
                finally:
                    for writer in writers:
                        writer.close()
                    await asyncio.gather(*(w.wait_closed() for w in writers), return_exceptions=True)
                    await base.eventually(lambda: not self.server.clients)

    async def test_tcp_authentication_deadline_includes_tls_and_http(self):
        with patch.object(transports, "AUTH_TIMEOUT", 0.4):
            reader, writer = await asyncio.open_connection(*self.endpoint, ssl=self.context,
                                                           server_hostname="localhost")
        try:
            # Repeated incomplete headers cannot extend the accept-time deadline.
            writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(1), 1), b"")
            await base.eventually(lambda: not self.server.clients)
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def test_new_session_without_ready_is_reclaimed_immediately(self):
        reader, writer = await open_channel("tcp", self.endpoint, self.context, "localhost", key="a" * 64)
        await write_frame(writer, dict(type="hello", version=VERSION, key="a" * 64, generation=1))
        welcome = await read_frame(reader)
        session = self.manager.sessions[welcome["session"]]
        writer.close()
        await writer.wait_closed()
        await base.eventually(lambda: not self.manager.sessions)
        self.assertTrue(session.closed)
        await session.wait_closed()
        self.assertTrue(session.sender.done() and session.timer.done())

    async def test_shutdown_closes_pending_tls_and_authorized_connections(self):
        raw_reader, raw_writer = await asyncio.open_connection(*self.endpoint)
        reader, writer = await open_channel("tcp", self.endpoint, self.context, "localhost", key="a" * 64)
        try:
            await base.eventually(lambda: len(self.server.clients) == 2)
            self.manager.close()
            self.server.close()
            await asyncio.wait_for(self.server.wait_closed(), 2)
            await self.manager.wait_closed()
            self.assertFalse(self.server.clients)
            self.assertFalse(self.manager.connections)
            self.assertTrue(self.server.acceptor.done())
            self.assertTrue(all(task.done() for task in self.server.tasks))
            self.assertEqual(await asyncio.wait_for(raw_reader.read(1), 1), b"")
            self.assertEqual(await asyncio.wait_for(reader.read(1), 1), b"")
        finally:
            raw_writer.close()
            writer.close()
            await asyncio.gather(raw_writer.wait_closed(), writer.wait_closed(), return_exceptions=True)

    async def test_quic_send_buffer_blocks_then_resumes_and_shutdown_stops_timers(self):
        release = asyncio.Event()
        received = 0

        class Consumer:
            key = "a" * 64

            async def accept(self, reader, writer):
                nonlocal received
                try:
                    await release.wait()
                    while data := await reader.read(CHUNK):
                        received += len(data)
                finally:
                    writer.close()

        udp, tasks = await serve_udp(Consumer(), ("127.0.0.1", 0),
                                    quic_config(cert=self.cert, key=self.keyfile))
        writer = drainer = None
        try:
            endpoint = udp._transport.get_extra_info("sockname")[:2]
            reader, writer = await open_channel("udp", endpoint, self.context, "localhost",
                                          quic_config(ca=self.cert, hostname="localhost"), key="a" * 64)
            sent = 0
            while writer.protocol.send_buffered() + CHUNK + 32 <= SEND_LIMIT:
                writer.write(b"x" * CHUNK)
                sent += CHUNK
            drainer = asyncio.create_task(writer.drain())
            await asyncio.sleep(0.15)
            self.assertFalse(drainer.done(), "a peer that stops reading must block drain")
            self.assertLessEqual(writer.protocol.send_buffered(), SEND_LIMIT)
            with self.assertRaises(ConnectionError):
                writer.write(b"x" * SEND_LIMIT)
            release.set()
            await asyncio.wait_for(drainer, 3)
            await base.eventually(lambda: received == sent)
            protocols = set(udp._protocols.values())
            peer = next(iter(protocols))
            peer._quic.stop_stream(0, error_code=0)
            peer.transmit()
            with self.assertRaises(ConnectionError):
                await asyncio.wait_for(reader.read(1), 1)
            self.assertFalse(writer.protocol.security_failure)
            await udp.aclose()
            for protocol in protocols:
                self.assertTrue(protocol.disposed and protocol._closed.is_set())
                self.assertIsNone(protocol.auth_timer)
                self.assertIsNone(protocol._timer)
                self.assertIsNone(protocol._transmit_task)
        finally:
            if drainer and not drainer.done():
                drainer.cancel()
                await asyncio.gather(drainer, return_exceptions=True)
            if writer:
                writer.close()
            await udp.aclose()
            for task in list(tasks):
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await shutdown_channels()

    async def test_target_connection_finishing_after_reset_cannot_leak_socket(self):
        session = Session(target=("127.0.0.1", 1))
        entered, release = asyncio.Event(), asyncio.Event()

        class Socket:
            def __init__(self):
                self.transport = self
                self.aborted = False

            def abort(self):
                self.aborted = True

        socket = Socket()

        async def late_connection(*args, **kwargs):
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                await release.wait()
            return asyncio.StreamReader(), socket

        stream = session.streams[1] = Stream(session, 1)
        try:
            with patch("tunnel.asyncio.open_connection", side_effect=late_connection):
                stream.connector = asyncio.create_task(stream.open_target())
                await entered.wait()
                stream.stop()
                release.set()
                await stream.connector
            self.assertTrue(socket.aborted)
            self.assertIsNone(stream.reader)
            self.assertIsNone(stream.writer)
            self.assertIsNone(stream.task)
        finally:
            session.close()
            await session.wait_closed()

    async def test_handover_publishes_owner_before_cleanup_and_serializes_attempts(self):
        session = Session()
        controller = AdaptiveClient(session, {"tcp": self.endpoint}, "a" * 64,
                                    self.context, "localhost", None)
        cleaning, release = asyncio.Event(), asyncio.Event()

        async def old_reader():
            try:
                await asyncio.Event().wait()
            finally:
                cleaning.set()
                await release.wait()

        old = controller.runner = asyncio.create_task(old_reader())
        controller.active = "udp"
        await asyncio.sleep(0)
        first = asyncio.create_task(controller.switch("tcp", "test_handover"))
        second = None
        try:
            await asyncio.wait_for(cleaning.wait(), 3)
            self.assertEqual(controller.active, session.path)
            self.assertEqual(controller.active, "tcp")
            self.assertIsNot(controller.runner, old)
            second = asyncio.create_task(controller.switch("tcp", "same_path"))
            await asyncio.sleep(0)
            self.assertFalse(second.done())
            release.set()
            self.assertTrue(await first)
            self.assertTrue(await second)
            self.assertEqual(session.next_generation, 1, "same-path calls must not open duplicate channels")
            # An automatic selection queued before the explicit switch is stale.
            self.assertFalse(await controller.switch("tcp", "stale_plan", expected_generation=0))
        finally:
            release.set()
            for task in (first, second, controller.runner, old):
                if task:
                    task.cancel()
            await asyncio.gather(*(t for t in (first, second, controller.runner, old) if t),
                                 return_exceptions=True)
            session.close()
            await session.wait_closed()


if __name__ == "__main__":
    unittest.main()
