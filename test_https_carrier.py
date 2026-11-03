import asyncio
import contextlib
import socket
import unittest
from unittest.mock import patch

from aioquic.asyncio import QuicConnectionProtocol, connect as quic_connect
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived

import test_tunnel as base
import transports
from http_carrier import AUTHORITY, HEADER_LIMIT, PAGE, read_head
from transports import SecurityError, open_channel, quic_config, serve_udp, shutdown_channels


class StandardHttp3Client(QuicConnectionProtocol):
    """Independent aioquic HTTP/3 client: no tunnel protocol adapter."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.response = asyncio.get_running_loop().create_future()
        self.response.add_done_callback(transports.observe_future)
        self.headers = {}
        self.body = bytearray()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            for item in self.http.handle_event(event):
                if isinstance(item, HeadersReceived):
                    self.headers.update(item.headers)
                elif isinstance(item, DataReceived):
                    self.body.extend(item.data)
                if getattr(item, "stream_ended", False) and not self.response.done():
                    self.response.set_result((self.headers, bytes(self.body)))
        elif isinstance(event, ConnectionTerminated) and not self.response.done():
            self.response.set_exception(ConnectionError("HTTP/3 closed"))

    async def get(self):
        self.http.send_headers(0, [(b":method", b"GET"), (b":scheme", b"https"),
                                   (b":authority", b"localhost"), (b":path", b"/")], end_stream=True)
        self.transmit()
        return await asyncio.wait_for(asyncio.shield(self.response), 3)


class HttpsCarrierTests(unittest.IsolatedAsyncioTestCase):
    setUpClass = classmethod(base.TunnelTests.setUpClass.__func__)
    tearDownClass = classmethod(base.TunnelTests.tearDownClass.__func__)

    async def asyncSetUp(self):
        await base.TunnelTests.asyncSetUp(self)
        self.udp, self.udp_tasks = await serve_udp(self.manager, ("127.0.0.1", 0),
                                                   quic_config(cert=self.cert, key=self.keyfile))
        self.udp_endpoint = self.udp._transport.get_extra_info("sockname")[:2]

    async def asyncTearDown(self):
        await self.udp.aclose()
        for task in list(self.udp_tasks):
            task.cancel()
        await asyncio.gather(*self.udp_tasks, return_exceptions=True)
        await base.TunnelTests.asyncTearDown(self)
        await shutdown_channels()

    async def test_ordinary_https_get_returns_page_without_creating_session(self):
        count = len(self.manager.sessions)
        reader, writer = await asyncio.open_connection(*self.endpoint, ssl=self.context,
                                                       server_hostname="localhost")
        try:
            self.assertEqual(writer.get_extra_info("ssl_object").selected_alpn_protocol(), "http/1.1")
            writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            status, headers = await read_head(reader)
            self.assertEqual(status, b"HTTP/1.1 200 OK")
            self.assertEqual(await reader.readexactly(int(headers[b"content-length"])), PAGE)
            self.assertEqual(len(self.manager.sessions), count)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_standard_http3_client_gets_page_without_tunnel_credentials(self):
        count = len(self.manager.sessions)
        async with quic_connect(*self.udp_endpoint,
                                configuration=quic_config(ca=self.cert, hostname="localhost"),
                                create_protocol=StandardHttp3Client) as client:
            headers, body = await client.get()
            self.assertEqual(headers[b":status"], b"200")
            self.assertEqual(body, PAGE)
        self.assertEqual(len(self.manager.sessions), count)

    async def test_bad_authorization_is_not_an_open_proxy(self):
        count = len(self.manager.sessions)
        for kind, endpoint in (("tcp", self.endpoint), ("udp", self.udp_endpoint)):
            with self.subTest(kind=kind), self.assertRaises(SecurityError):
                await open_channel(kind, endpoint, self.context, "localhost",
                                   quic_config(ca=self.cert, hostname="localhost"), key="b" * 64)
        self.assertEqual(len(self.manager.sessions), count)

        # Even the correct owner key cannot turn CONNECT into an arbitrary proxy.
        reader, writer = await asyncio.open_connection(*self.endpoint, ssl=self.context,
                                                       server_hostname="localhost")
        try:
            writer.write(b"CONNECT arbitrary.invalid:80 HTTP/1.1\r\nHost: arbitrary.invalid:80\r\n"
                         b"Proxy-Authorization: Bearer " + b"a" * 64 + b"\r\n\r\n")
            await writer.drain()
            status, _ = await read_head(reader)
            self.assertEqual(status, b"HTTP/1.1 404 Not Found")
        finally:
            writer.close()
            await writer.wait_closed()
        async with quic_connect(*self.udp_endpoint,
                                configuration=quic_config(ca=self.cert, hostname="localhost"),
                                create_protocol=StandardHttp3Client) as client:
            client.http.send_headers(0, [(b":method", b"CONNECT"),
                                         (b":authority", b"arbitrary.invalid:80"),
                                         (b"proxy-authorization", b"Bearer " + b"a" * 64)])
            client.transmit()
            headers, _ = await asyncio.wait_for(asyncio.shield(client.response), 3)
            self.assertEqual(headers[b":status"], b"404")
        self.assertEqual(len(self.manager.sessions), count)

    async def test_duplicate_and_oversized_http_headers_are_rejected(self):
        requests = [
            b"CONNECT " + AUTHORITY + b" HTTP/1.1\r\nHost: " + AUTHORITY
            + b"\r\nProxy-Authorization: Bearer " + b"a" * 64
            + b"\r\nProxy-Authorization: Bearer " + b"b" * 64 + b"\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: " + b"x" * HEADER_LIMIT + b"\r\n\r\n",
        ]
        count = len(self.manager.sessions)
        for request in requests:
            reader, writer = await asyncio.open_connection(*self.endpoint, ssl=self.context,
                                                           server_hostname="localhost")
            try:
                writer.write(request)
                await writer.drain()
                status, _ = await read_head(reader)
                self.assertEqual(status, b"HTTP/1.1 400 Bad Request")
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
        self.assertEqual(len(self.manager.sessions), count)

    async def test_http3_rejects_oversized_decoded_headers_before_session(self):
        count = len(self.manager.sessions)
        async with quic_connect(*self.udp_endpoint,
                                configuration=quic_config(ca=self.cert, hostname="localhost"),
                                create_protocol=StandardHttp3Client) as client:
            client.http.send_headers(0, [(b":method", b"CONNECT"), (b":authority", AUTHORITY),
                                         (b"proxy-authorization", b"Bearer " + b"a" * 64),
                                         (b"x-large", b"x" * (HEADER_LIMIT + 1))])
            client.transmit()
            with self.assertRaises(ConnectionError):
                await asyncio.wait_for(asyncio.shield(client.response), 3)
        self.assertEqual(len(self.manager.sessions), count)

    async def test_udp_tries_ipv4_while_first_ipv6_address_is_blackholed(self):
        loop = asyncio.get_running_loop()
        original_resolve = loop.getaddrinfo

        async def addresses(host, port, *args, **kwargs):
            if host == "dual-stack.test":
                return [(socket.AF_INET6, socket.SOCK_DGRAM, 17, "", ("::1", port, 0, 0)),
                        (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", port))]
            return await original_resolve(host, port, *args, **kwargs)

        started = loop.time()
        with patch.object(loop, "getaddrinfo", side_effect=addresses):
            reader, writer = await open_channel("udp", ("dual-stack.test", self.udp_endpoint[1]),
                                                self.context, "localhost",
                                                quic_config(ca=self.cert, hostname="localhost"), key="a" * 64)
        try:
            self.assertTrue(writer.carrier_ready)
            self.assertLess(loop.time() - started, 2, "verified IPv4 must not await the IPv6 timeout")
        finally:
            writer.close()

    async def test_cancelling_address_race_cleans_all_attempts(self):
        entered, cancelled = asyncio.Event(), asyncio.Event()

        async def pending(*args):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        with patch("transports.open_udp_address", side_effect=pending):
            task = asyncio.create_task(transports.race_udp_addresses(
                [(socket.AF_INET6, ("::1", 1, 0, 0)), (socket.AF_INET, ("127.0.0.1", 1))],
                quic_config(ca=self.cert, hostname="localhost"), "a" * 64))
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await shutdown_channels()
        self.assertTrue(cancelled.is_set())


if __name__ == "__main__":
    unittest.main()
