import asyncio
import base64
import hashlib
import os
import pathlib
import ssl
import struct
import tempfile
import unittest

from dev_cert import generate
from tunnel import (CHUNK, MAX_FRAME, QUEUE, ProtocolError, Server,
                    Session, connect, read_frame, reconnect)
from transports import ALPN, SecurityError, serve_tcp, tls_client, tls_server


async def eventually(predicate, timeout=5):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


class TunnelTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_root = pathlib.Path(__file__).resolve().parent / ".local"
        cls.temp_root.mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(dir=cls.temp_root)
        assert pathlib.Path(cls.temp.name).resolve().is_relative_to(cls.temp_root)
        cls.cert, cls.keyfile = generate(cls.temp.name)

    @classmethod
    def tearDownClass(cls):
        assert pathlib.Path(cls.temp.name).resolve().is_relative_to(cls.temp_root)
        cls.temp.cleanup()

    async def asyncSetUp(self):
        self.connections = 0
        self.target_tasks = set()

        async def echo(reader, writer):
            task = asyncio.current_task()
            self.target_tasks.add(task)
            self.connections += 1
            try:
                while data := await reader.read(CHUNK):
                    await asyncio.sleep(0.001)
                    writer.write(data)
                    await writer.drain()
                writer.write_eof()
            except (OSError, ConnectionError):
                pass
            finally:
                writer.close()
                self.target_tasks.discard(task)

        self.target = await asyncio.start_server(echo, "127.0.0.1", 0)
        target_address = self.target.sockets[0].getsockname()[:2]
        self.manager = Server("a" * 64, target_address, grace=2)
        self.server_context = tls_server(self.cert, self.keyfile)
        self.tls = await serve_tcp(self.manager, ("127.0.0.1", 0), self.server_context)
        self.endpoint = self.tls.sockets[0].getsockname()[:2]
        self.context = tls_client(self.cert)
        self.session = Session(grace=2)
        self.reconnector = asyncio.create_task(reconnect(
            self.session, self.endpoint, "a" * 64, self.context, "localhost"))
        self.local = await asyncio.start_server(self.session.accept_local, "127.0.0.1", 0)
        await eventually(lambda: self.session.writer is not None)

    async def asyncTearDown(self):
        self.reconnector.cancel()
        self.session.close()
        self.manager.close()
        for server in (self.local, self.tls, self.target):
            server.close()
            await server.wait_closed()
        tasks = list(self.target_tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(self.reconnector, *tasks, return_exceptions=True)
        await self.session.wait_closed()
        await self.manager.wait_closed()
        await asyncio.sleep(0.05)

    async def local_connect(self):
        return await asyncio.open_connection(*self.local.sockets[0].getsockname()[:2])

    async def round_trip(self, data, timeout=20):
        reader, writer = await self.local_connect()

        async def upload():
            for start in range(0, len(data), CHUNK):
                writer.write(data[start:start + CHUNK])
                await writer.drain()
            writer.write_eof()

        task = asyncio.create_task(upload())
        try:
            result = await asyncio.wait_for(reader.read(), timeout)
            await task
            return result
        finally:
            task.cancel()
            writer.close()

    async def test_large_transfer_survives_repeated_transport_loss(self):
        data = os.urandom(3 * 1024 * 1024)
        transfer = asyncio.create_task(self.round_trip(data))
        await eventually(lambda: self.session.tx_seq > 8)
        sid = self.session.sid
        for _ in range(3):
            previous = self.session.transport_id
            self.session.detach(self.session.writer)
            await eventually(lambda: self.session.transport_id != previous)
        result = await transfer
        self.assertEqual(hashlib.sha256(data).digest(), hashlib.sha256(result).digest())
        self.assertEqual(len(result), len(data))
        self.assertEqual(self.connections, 1, "target socket must survive")
        self.assertEqual(self.session.sid, sid)
        self.assertEqual(len(self.manager.sessions), 1)

    async def test_loss_after_delivery_before_ack_does_not_duplicate(self):
        server_session = next(iter(self.manager.sessions.values()))
        send = server_session.send
        dropped = asyncio.Event()

        async def drop_ack(frame):
            if (frame["type"] == "ack" and frame["offset"] > 0
                    and not dropped.is_set()):
                dropped.set()
                server_session.detach(server_session.writer)
                return
            await send(frame)

        server_session.send = drop_ack
        data = os.urandom(100_000)
        self.assertEqual(await self.round_trip(data), data)
        self.assertTrue(dropped.is_set())
        self.assertEqual(self.connections, 1)

    async def test_lost_credit_is_replayed_after_resume(self):
        server_session = next(iter(self.manager.sessions.values()))
        send = server_session.send
        dropped = False

        async def lose_window(frame):
            nonlocal dropped
            if frame["type"] == "window" and not dropped:
                dropped = True
                server_session.detach(server_session.writer)
                return
            await send(frame)

        server_session.send = lose_window
        data = os.urandom(200_000)
        self.assertEqual(await self.round_trip(data), data)
        self.assertTrue(dropped)
        self.assertEqual(self.connections, 1)

    async def test_http_download_keeps_same_application_connection(self):
        data = os.urandom(3 * 1024 * 1024)
        downloads = 0

        async def http(reader, writer):
            nonlocal downloads
            task = asyncio.current_task()
            self.target_tasks.add(task)
            downloads += 1
            try:
                await reader.readuntil(b"\r\n\r\n")
                writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(data)}\r\n"
                             "Connection: close\r\n\r\n".encode())
                for offset in range(0, len(data), CHUNK):
                    writer.write(data[offset:offset + CHUNK])
                    await writer.drain()
                    await asyncio.sleep(0.002)
            finally:
                writer.close()
                self.target_tasks.discard(task)

        http_server = await asyncio.start_server(http, "127.0.0.1", 0)
        server_session = next(iter(self.manager.sessions.values()))
        server_session.target = http_server.sockets[0].getsockname()[:2]
        reader, writer = await self.local_connect()
        try:
            writer.write(b"GET /large.bin HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            self.assertIn(b"200 OK", header)
            first = await reader.readexactly(128 * 1024)
            previous = self.session.transport_id
            server_session.detach(server_session.writer)
            tail = await asyncio.wait_for(reader.readexactly(len(data) - len(first)), 15)
            self.assertEqual(hashlib.sha256(first + tail).digest(), hashlib.sha256(data).digest())
            self.assertNotEqual(previous, self.session.transport_id)
            self.assertEqual(downloads, 1)
        finally:
            writer.close()
            http_server.close()
            await http_server.wait_closed()

    async def test_replayed_open_and_fin_are_idempotent(self):
        server_session = next(iter(self.manager.sessions.values()))
        send = server_session.send
        dropped = set()

        async def drop_ack(frame):
            if frame["type"] == "ack":
                stage = "open" if frame["seq"] == 1 else None
                stream = server_session.streams.get(frame["stream"])
                if stream and stream.remote_fin:
                    stage = "fin"
                if stage and stage not in dropped:
                    dropped.add(stage)
                    server_session.detach(server_session.writer)
                    return
            await send(frame)

        server_session.send = drop_ack
        self.assertEqual(await self.round_trip(b"one connection"), b"one connection")
        await eventually(lambda: len(dropped) == 2 and self.session.current is None)
        self.assertEqual(dropped, {"open", "fin"})
        self.assertEqual(self.connections, 1)

    async def test_multiple_streams_and_half_close(self):
        payloads = [os.urandom(70_000), b"SSH example\n", os.urandom(120_000)]
        results = await asyncio.gather(*(self.round_trip(data) for data in payloads))
        self.assertEqual(results, payloads)
        self.assertEqual(self.connections, 3)

    async def test_grace_expiry_closes_application_and_refuses_resume(self):
        reader, writer = await self.local_connect()
        writer.write(b"before expiry")
        await writer.drain()
        self.assertEqual(await reader.readexactly(13), b"before expiry")
        self.reconnector.cancel()
        await asyncio.gather(self.reconnector, return_exceptions=True)
        await eventually(lambda: self.session.closed, timeout=4)
        await eventually(lambda: all(s.closed for s in self.manager.sessions.values()), timeout=4)
        with self.assertRaises(ConnectionError):
            await asyncio.wait_for(reader.read(), 1)
        writer.close()
        stale = Session(grace=2)
        stale.established = True
        stale.sid, stale.secret = self.session.sid, self.session.secret
        try:
            with self.assertRaisesRegex(ProtocolError, "expired"):
                await connect(stale, self.endpoint, "a" * 64, self.context, "localhost")
        finally:
            stale.close()

    async def test_wrong_resume_secret_does_not_replace_transport(self):
        original = self.session.transport_id
        stale = Session(grace=2)
        stale.established = True
        stale.sid = self.session.sid
        try:
            with self.assertRaisesRegex(ProtocolError, "expired"):
                await connect(stale, self.endpoint, "a" * 64, self.context, "localhost")
            self.assertEqual(await self.round_trip(b"still works"), b"still works")
            self.assertEqual(self.session.transport_id, original)
        finally:
            stale.close()

    async def test_untrusted_certificate_and_wrong_key_rejected(self):
        fresh = Session(grace=2)
        try:
            untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            untrusted.minimum_version = ssl.TLSVersion.TLSv1_3
            untrusted.load_default_certs()
            untrusted.set_alpn_protocols([ALPN])
            with self.assertRaises(SecurityError):
                await connect(fresh, self.endpoint, "a" * 64,
                              untrusted, "localhost")
            with self.assertRaises(SecurityError):
                await connect(fresh, self.endpoint, "a" * 64, self.context, "wrong-host")
            with self.assertRaises(SecurityError):
                await connect(fresh, self.endpoint, "b" * 64, self.context, "localhost")
        finally:
            fresh.close()

    async def test_oversized_frame_and_bad_offsets_rejected(self):
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack("!I", MAX_FRAME + 1))
        with self.assertRaises(ProtocolError):
            await read_frame(reader)
        self.assertEqual(await self.round_trip(b"abc"), b"abc")
        with self.assertRaises(ProtocolError):
            await self.session.apply(dict(type="data", stream=1, offset=999,
                                          data=base64.b64encode(b"x").decode()))
        with self.assertRaises(ProtocolError):
            self.session.acknowledge(dict(type="ack", seq=99999))

    async def test_bounded_queue_wakes_blocked_producer_on_close(self):
        session = Session(grace=2)
        # No await: sender cannot consume the queue during setup.
        for _ in range(QUEUE):
            await session.enqueue("reset", 1)
        session.sender.cancel()
        blocked = asyncio.create_task(session.enqueue("reset", 2))
        await asyncio.sleep(0)
        self.assertFalse(blocked.done())
        session.close()
        with self.assertRaises(ConnectionError):
            await asyncio.wait_for(blocked, 1)

    async def test_duplicate_records_schedule_only_one_ack_task(self):
        session = Session(grace=2)
        blocked = asyncio.Event()
        calls = 0

        async def slow_send(frame):
            nonlocal calls
            calls += 1
            await blocked.wait()

        session.send = slow_send
        session.rx_seq = 1
        session.last_ack = dict(type="ack", seq=1, stream=1, offset=0)
        try:
            for _ in range(1000):
                session.receive(dict(type="open", seq=1, stream=1))
            await asyncio.sleep(0)
            self.assertEqual(calls, 1)
            self.assertIsNotNone(session.ack_sender)
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
