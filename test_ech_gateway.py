"""Real native ECH wrapping the unchanged TLS/session protocol."""

import asyncio
import json
import os
import pathlib
import socket
import subprocess
import sys
import unittest

from aioquic.buffer import Buffer
from aioquic.quic.crypto import CryptoError, CryptoPair
from aioquic.quic.packet import QuicPacketType, pull_ack_frame, pull_quic_header

import test_tunnel as base
from ech_gateway import DEFAULT_BINARY, EchGateway, address, endpoint
from transports import open_channel, serve_tcp, shutdown_channels, tls_client, tls_server
from tunnel import AdaptiveClient, CHUNK, SecurityError, Server, Session


def initial_client_hello(datagrams):
    """Decode publicly derivable QUIC Initial protection, then reassemble CRYPTO."""
    chunks = {}
    for datagram in datagrams:
        while datagram:
            if not datagram[0] & 0x80:
                break  # Short-header 1-RTT packets are irrelevant, including a greased fixed bit.
            buf = Buffer(data=datagram)
            header = pull_quic_header(buf, host_cid_length=8)
            packet, datagram = datagram[:header.packet_length], datagram[header.packet_length:]
            if header.packet_type != QuicPacketType.INITIAL:
                continue
            crypto = CryptoPair()
            crypto.setup_initial(cid=header.destination_cid, is_client=False, version=header.version)
            try:
                _, payload, _ = crypto.decrypt_packet(packet, buf.tell(), 0)
            except CryptoError:
                continue  # Server Initial uses the other direction's keys.
            frame = Buffer(data=payload)
            while not frame.eof():
                kind = frame.pull_uint_var()
                if kind in (0, 1):  # PADDING/PING
                    continue
                if kind in (2, 3):
                    pull_ack_frame(frame)
                    if kind == 3:
                        for _ in range(3):
                            frame.pull_uint_var()
                elif kind == 6:
                    offset, size = frame.pull_uint_var(), frame.pull_uint_var()
                    chunks[offset] = frame.pull_bytes(size)
                else:
                    raise AssertionError(f"unexpected Initial frame {kind}")
    end = max((offset + len(data) for offset, data in chunks.items()), default=0)
    hello, present = bytearray(end), bytearray(end)
    for offset, data in chunks.items():
        hello[offset:offset + len(data)] = data
        present[offset:offset + len(data)] = b"\1" * len(data)
    if not hello or not all(present) or hello[0] != 1 or int.from_bytes(hello[1:4]) + 4 != len(hello):
        raise AssertionError("incomplete captured ClientHello")
    return bytes(hello)


@unittest.skipUnless(DEFAULT_BINARY.is_file(), "Build native/ ECH gateway first")
class EchGatewayTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        base.TunnelTests.setUpClass.__func__(cls)
        cls.ech_keys = pathlib.Path(cls.temp.name) / "ech-keys.json"
        cls.ech_config = pathlib.Path(cls.temp.name) / "ech-config.bin"
        subprocess.run([str(DEFAULT_BINARY)], input=json.dumps(dict(mode="keygen", public_name="cover.test",
            keys_file=str(cls.ech_keys), config_file=str(cls.ech_config))).encode(),
            check=True, capture_output=True)

    tearDownClass = classmethod(base.TunnelTests.tearDownClass.__func__)

    async def asyncSetUp(self):
        self.connections = 0
        self.target_tasks = set()

        async def echo(reader, writer):
            task = asyncio.current_task()
            self.target_tasks.add(task)
            self.connections += 1
            try:
                while data := await reader.read(CHUNK):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                self.target_tasks.discard(task)

        self.target = await asyncio.start_server(echo, "127.0.0.1", 0)
        self.manager = Server("a" * 64, self.target.sockets[0].getsockname()[:2], grace=5)
        self.tcp = await serve_tcp(self.manager, ("127.0.0.1", 0), tls_server(self.cert, self.keyfile), ech=True)
        self.udp = await serve_tcp(self.manager, ("127.0.0.1", 0), tls_server(self.cert, self.keyfile), kind="udp", ech=True)
        self.server_gateway = await EchGateway.start(dict(mode="server", tcp="127.0.0.1:0", udp="127.0.0.1:0",
            backend_tcp=address(self.tcp.sockets[0].getsockname()[:2]),
            backend_udp=address(self.udp.sockets[0].getsockname()[:2]),
            cert=str(self.cert), cert_key=str(self.keyfile), keys_file=str(self.ech_keys)), key="a" * 64)
        self.client_config = dict(mode="client", tcp="127.0.0.1:0", udp="127.0.0.1:0",
            remote_tcp=self.server_gateway.endpoints["tcp"], remote_udp=self.server_gateway.endpoints["udp"],
            ca=str(self.cert), server_name="localhost", config_file=str(self.ech_config))
        self.client_gateway = await EchGateway.start(self.client_config, key="a" * 64)
        self.context = tls_client(self.cert)
        self.context.ech_gateway = self.client_gateway

    async def asyncTearDown(self):
        self.manager.close()
        for server in (self.tcp, self.udp, self.target):
            server.close()
        await self.client_gateway.close()
        await self.server_gateway.close()
        await asyncio.gather(self.tcp.wait_closed(), self.udp.wait_closed(), self.target.wait_closed(),
                             self.manager.wait_closed())
        tasks = list(self.target_tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await shutdown_channels()

    async def test_ech_tcp_udp_tcp_keeps_application_socket_and_session(self):
        session = Session(grace=5)
        controller = AdaptiveClient(session, {k: endpoint(v) for k, v in self.server_gateway.endpoints.items()},
                                    "a" * 64, self.context, "localhost", None)
        controller.selector.cooldown = 1000
        local = await asyncio.start_server(session.accept_local, "127.0.0.1", 0)
        task = asyncio.create_task(controller.run())
        writer = None
        try:
            await base.eventually(lambda: session.writer is not None)
            reader, writer = await asyncio.open_connection(*local.sockets[0].getsockname()[:2])
            sid = session.sid
            for kind in ("tcp", "udp", "tcp"):
                self.assertTrue(await controller.switch(kind, "ech_test_handover"))
                payload = os.urandom(200_000)
                writer.write(payload)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 5), payload)
                self.assertEqual(session.path, kind)
                self.assertTrue(session.writer.ech)
                self.assertEqual(session.sid, sid)
            self.assertEqual(self.connections, 1)
        finally:
            if writer:
                writer.close()
            local.close()
            await local.wait_closed()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            session.close()
            await session.wait_closed()

    async def test_dead_ech_backend_never_falls_back_to_direct_server(self):
        await self.client_gateway.close()
        for kind, remote in self.server_gateway.endpoints.items():
            with self.subTest(kind=kind), self.assertRaises(SecurityError):
                await open_channel(kind, endpoint(remote), self.context, "localhost", key="a" * 64)
        self.assertFalse(self.manager.sessions)

    async def test_guard_stops_work_when_ech_backend_exits(self):
        work = asyncio.create_task(asyncio.Event().wait())
        guard = asyncio.create_task(self.client_gateway.guard(work))
        await self.client_gateway.close()
        with self.assertRaisesRegex(RuntimeError, "direct fallback is prohibited"):
            await guard
        self.assertTrue(work.cancelled())

    async def test_udp_clienthello_hides_inner_sni_even_after_initial_decryption(self):
        from test_adaptive import UdpRelay
        transport, relay = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: UdpRelay(endpoint(self.server_gateway.endpoints["udp"])), local_addr=("127.0.0.1", 0))
        gateway = writer = None
        try:
            config = dict(self.client_config, tcp="", remote_udp=address(transport.get_extra_info("sockname")[:2]))
            gateway = await EchGateway.start(config, key="a" * 64)
            context = tls_client(self.cert)
            context.ech_gateway = gateway
            _, writer = await open_channel("udp", endpoint(config["remote_udp"]), context, "localhost", key="a" * 64)
            hello = initial_client_hello(relay.received)
            self.assertIn(b"cover.test", hello)
            for value in (b"localhost", b"myownvpn", b"a" * 64):
                self.assertNotIn(value, hello)
            self.assertIn(b"\xfe\x0d", hello)  # Real ECH extension, acceptance verified by Go.
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()
            if gateway:
                await gateway.close()
            transport.abort()

    async def test_cli_ech_udp_forwards_encrypted_application_bytes(self):
        def free_port():
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                return sock.getsockname()[1]

        async def started(process, name):
            async with asyncio.timeout(10):
                while line := await process.stderr.readline():
                    if json.loads(line).get("event") == name:
                        return
            raise AssertionError("CLI exited before readiness")

        server_port, client_port = free_port(), free_port()
        env = dict(os.environ, MYVPN_KEY="a" * 64)
        common = dict(stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
                      env=env, creationflags=0x08000000 if os.name == "nt" else 0)
        server = client = writer = None
        try:
            server = await asyncio.create_subprocess_exec(sys.executable, "tunnel.py", "server",
                "--listen", f"127.0.0.1:{server_port}", "--target", address(self.target.sockets[0].getsockname()[:2]),
                "--cert", str(self.cert), "--cert-key", str(self.keyfile), "--ech-keys", str(self.ech_keys),
                "--no-srtl", **common)
            await started(server, "server_started")
            client = await asyncio.create_subprocess_exec(sys.executable, "tunnel.py", "client",
                "--listen", f"127.0.0.1:{client_port}", "--server", f"127.0.0.1:{server_port}",
                "--server-name", "localhost", "--ca", str(self.cert), "--ech-config", str(self.ech_config),
                "--transport", "udp", "--srtl", **common)
            await started(client, "connect_success")
            reader, writer = await asyncio.open_connection("127.0.0.1", client_port)
            data = os.urandom(200_000)
            writer.write(data)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(data)), 5), data)
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()
            for process in (client, server):
                if process:
                    if process.returncode is None:
                        process.terminate()
                    await process.communicate()


if __name__ == "__main__":
    unittest.main()
