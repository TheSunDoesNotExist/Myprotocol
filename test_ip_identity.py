"""IP-only certificates retain peer verification while omitting SNI."""

import asyncio
import logging
import pathlib
import ssl
import tempfile
import unittest

from aioquic.buffer import Buffer
from aioquic.tls import pull_client_hello
from cryptography import x509

from ip_cert import generate
from test_adaptive import UdpRelay
from test_ech_gateway import initial_client_hello
from transports import SecurityError, open_channel, quic_config, serve_tcp, serve_udp, shutdown_channels, tls_client, tls_server
from tunnel import CHUNK, Server, Session, connect


class IPIdentityTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        root = pathlib.Path(__file__).resolve().parent / ".local"
        root.mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(dir=root)
        cls.files = generate(cls.temp.name, ["127.0.0.1"])

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    async def asyncSetUp(self):
        logging.getLogger("quic").setLevel(logging.CRITICAL)
        self.target_tasks = set()

        async def echo(reader, writer):
            task = asyncio.current_task()
            self.target_tasks.add(task)
            try:
                while data := await reader.read(CHUNK):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                self.target_tasks.discard(task)

        self.target = await asyncio.start_server(echo, "127.0.0.1", 0)
        self.manager = Server("a" * 64, self.target.sockets[0].getsockname()[:2])
        self.tcp = await serve_tcp(self.manager, ("127.0.0.1", 0),
                                   tls_server(self.files["server-cert.pem"], self.files["server-key.pem"]))
        self.udp, self.udp_tasks = await serve_udp(self.manager, ("127.0.0.1", 0),
            quic_config(cert=self.files["server-cert.pem"], key=self.files["server-key.pem"]))
        self.endpoints = {"tcp": self.tcp.sockets[0].getsockname()[:2],
                          "udp": self.udp._transport.get_extra_info("sockname")[:2]}
        self.context = tls_client(self.files["ca-cert.pem"])

    async def asyncTearDown(self):
        self.manager.close()
        self.tcp.close()
        self.target.close()
        await self.udp.aclose()
        for task in list(self.udp_tasks | self.target_tasks):
            task.cancel()
        await asyncio.gather(*self.udp_tasks, *self.target_tasks, return_exceptions=True)
        await self.tcp.wait_closed()
        await self.target.wait_closed()
        await self.manager.wait_closed()
        await shutdown_channels()

    async def test_tcp_and_udp_clienthellos_omit_server_name(self):
        outgoing = ssl.MemoryBIO()
        client = self.context.wrap_bio(ssl.MemoryBIO(), outgoing, server_side=False, server_hostname="127.0.0.1")
        with self.assertRaises(ssl.SSLWantReadError):
            client.do_handshake()
        wire = outgoing.read()
        hello = pull_client_hello(Buffer(data=wire[5:]))
        self.assertIsNone(hello.server_name)
        transport, relay = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: UdpRelay(self.endpoints["udp"]), local_addr=("127.0.0.1", 0))
        writer = None
        try:
            _, writer = await open_channel("udp", transport.get_extra_info("sockname")[:2], self.context,
                "127.0.0.1", quic_config(ca=self.files["ca-cert.pem"], hostname="127.0.0.1"), key="a" * 64)
            hello = pull_client_hello(Buffer(data=initial_client_hello(relay.received)))
            self.assertIsNone(hello.server_name)
        finally:
            if writer:
                writer.close()
            transport.abort()

    async def test_wrong_ip_is_rejected_on_both_transports(self):
        for kind, remote in self.endpoints.items():
            with self.subTest(kind=kind), self.assertRaises(SecurityError):
                await open_channel(kind, remote, self.context, "127.0.0.2",
                    quic_config(ca=self.files["ca-cert.pem"], hostname="127.0.0.2"), key="a" * 64)
        self.assertFalse(self.manager.sessions)

    async def test_ip_only_identity_preserves_data_across_tcp_udp_tcp(self):
        certificate = x509.load_pem_x509_certificate(self.files["server-cert.pem"].read_bytes())
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertFalse(names.get_values_for_type(x509.DNSName))
        session = Session()
        local = await asyncio.start_server(session.accept_local, "127.0.0.1", 0)
        tasks, writer = [], None
        try:
            for kind in ("tcp", "udp", "tcp"):
                reader, secured = await connect(session, self.endpoints[kind], "a" * 64, self.context, "127.0.0.1",
                    kind=kind, quic=quic_config(ca=self.files["ca-cert.pem"], hostname="127.0.0.1"))
                tasks.append(asyncio.create_task(session.run_transport(reader, secured)))
                if writer is None:
                    source, writer = await asyncio.open_connection(*local.sockets[0].getsockname()[:2])
                data = b"private bytes" * 3000
                writer.write(data)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(source.readexactly(len(data)), 3), data)
        finally:
            if writer:
                writer.close()
            local.close()
            await local.wait_closed()
            session.close()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await session.wait_closed()


if __name__ == "__main__":
    unittest.main()
