"""Client security boundaries and actual GUI-adapter transport integration."""

import asyncio
import contextlib
from dataclasses import replace
import gzip
import io
import json
import logging
import os
import pathlib
import queue
import secrets
import socket
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from desktop.engine import Engine, Events
from desktop.profiles import Profile, Profiles, import_package
from desktop.vault import Vault, VaultError
from ip_cert import generate
from transports import quic_config, serve_tcp, serve_udp, tls_server
from tunnel import Server

ROOT = pathlib.Path(__file__).resolve().parent / ".local"
ROOT.mkdir(exist_ok=True)


def make_package(path, ca, *, server="127.0.0.1:8443", key="a" * 64, extra=None, protocol=5):
    files = {"ca-cert.pem": ca, "access-key": key.encode(),
             "client.json": json.dumps(dict(server=server, protocol=protocol, ca="ca-cert.pem", srtl_client=False)).encode()}
    if extra:
        files.update(extra)
    with tarfile.open(path, "w:gz") as archive:
        for name, data in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))


class ClientProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.root = pathlib.Path(self.temp.name)
        self.files = generate(self.root / "identity", ["127.0.0.1"])
        self.ca = self.files["ca-cert.pem"].read_bytes()
        self.archive = self.root / "client.tar.gz"
        make_package(self.archive, self.ca)

    def tearDown(self):
        self.temp.cleanup()

    def test_export_import_compatible_and_public_profile_never_saves_key(self):
        imported = import_package(self.archive)
        self.assertEqual(imported.key, "a" * 64)
        self.assertNotIn(imported.key, repr(imported))
        store = Profiles(self.root / "profiles")
        store.install_ca(imported)
        store.save([imported.profile])
        self.assertEqual(store.load(), [imported.profile])
        self.assertNotIn(imported.key, (store.root / "profiles.json").read_text())
        if os.name == "posix":
            self.assertEqual(store.root.stat().st_mode & 0o777, 0o700)
            self.assertEqual((store.root / "profiles.json").stat().st_mode & 0o777, 0o600)

    def test_untrusted_archives_are_bounded_and_cannot_extract_paths(self):
        for name in ("../outside", "/tmp/outside", "server-key.pem", "ca-key.pem"):
            with self.subTest(name=name):
                make_package(self.archive, self.ca, extra={name: b"not allowed"})
                with self.assertRaises(ValueError):
                    import_package(self.archive)
        self.archive.write_bytes(gzip.compress(b"z" * (256 * 1024 + 1)))
        with self.assertRaises(ValueError):
            import_package(self.archive)
        self.archive.write_bytes(b"bad archive")
        with self.assertRaises(ValueError):
            import_package(self.archive)
        with tarfile.open(self.archive, "w:gz") as archive:
            member = tarfile.TarInfo("access-key")
            member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
            archive.addfile(member)
        with self.assertRaises(ValueError):
            import_package(self.archive)

    def test_wrong_version_domain_or_key_fail_closed(self):
        for options in (dict(protocol=4), dict(server="example.com:443"), dict(key="bad")):
            with self.subTest(options=options):
                make_package(self.archive, self.ca, **options)
                with self.assertRaises(ValueError):
                    import_package(self.archive)

    def test_profile_rejects_filesystem_escape_and_malformed_metadata(self):
        store = Profiles(self.root / "profiles")
        profile = import_package(self.archive).profile
        with self.assertRaises(ValueError):
            store.ca_path(replace(profile, id="../../outside"))
        store.save([replace(profile, ca_sha256="wrong")])
        with self.assertRaises(ValueError):
            store.load()

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI")
    def test_windows_dpapi_encrypts_at_rest_and_detects_tampering(self):
        imported = import_package(self.archive)
        vault = Vault(self.root)
        vault.save(imported.profile.id, imported.key)
        path = self.root / (imported.profile.id + ".dpapi")
        ciphertext = path.read_bytes()
        self.assertNotIn(imported.key.encode(), ciphertext)
        self.assertEqual(vault.load(imported.profile.id), imported.key)
        path.write_bytes(ciphertext[:-20] + b"x" * 20)
        with self.assertRaises(VaultError):
            vault.load(imported.profile.id)

    def test_secret_service_uses_stdin_and_never_falls_back_to_plaintext(self):
        imported = import_package(self.archive)
        vault = Vault(self.root)
        with patch("desktop.vault.shutil.which", return_value="/usr/bin/secret-tool"), patch("desktop.vault.subprocess.run") as run:
            run.return_value.returncode = 0
            vault._secret_tool("store", imported.profile.id, imported.key.encode())
            self.assertNotIn(imported.key, " ".join(run.call_args.args[0]))
            self.assertEqual(run.call_args.kwargs["input"], imported.key.encode())
        with patch("desktop.vault.shutil.which", return_value=None), self.assertRaises(VaultError):
            vault._secret_tool("store", imported.profile.id, imported.key.encode())
        self.assertFalse(list(self.root.glob("*.key")))

    def test_gui_log_bridge_only_allows_protocol_metadata(self):
        messages = []
        handler = Events(lambda kind, data: messages.append((kind, data)))
        record = logging.LogRecord("tunnel", logging.INFO, "", 1, "secret log text", (), None)
        record.metadata = dict(event="path_probe", rtt_ms=1.2, key="secret", payload="private bytes")
        handler.emit(record)
        self.assertEqual(messages[0][1]["rtt_ms"], 1.2)
        self.assertNotIn("secret", json.dumps(messages))
        self.assertNotIn("private bytes", json.dumps(messages))
        del record.metadata
        handler.emit(record)
        self.assertEqual(len(messages), 1)


class DesktopServerCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.files = generate(self.temp.name, ["127.0.0.1"])
        self.target_count = 0
        self.target_tasks = set()
        async def echo(reader, writer):
            self.target_count += 1
            task = asyncio.current_task()
            self.target_tasks.add(task)
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
                self.target_tasks.discard(task)
        self.target = await asyncio.start_server(echo, "127.0.0.1", 0)
        self.server = Server("a" * 64, self.target.sockets[0].getsockname()[:2])
        # Windows may reserve different ephemeral ranges for TCP and UDP.
        # Choose a port legal for both protocols before creating async servers.
        for attempt in range(32):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_port, socket.socket() as tcp_port:
                    self.port = 20000 + secrets.randbelow(28000)
                    udp_port.bind(("127.0.0.1", self.port))
                    tcp_port.bind(("127.0.0.1", self.port))
                break
            except OSError:
                if attempt == 31:
                    raise
        self.tcp = await serve_tcp(self.server, ("127.0.0.1", self.port), tls_server(self.files["server-cert.pem"], self.files["server-key.pem"]))
        self.udp, self.udp_tasks = await serve_udp(self.server, ("127.0.0.1", self.port), quic_config(cert=self.files["server-cert.pem"], key=self.files["server-key.pem"]))
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            self.local_port = reserved.getsockname()[1]
        ca = x509.load_pem_x509_certificate(self.files["ca-cert.pem"].read_bytes())
        self.profile = Profile("a" * 24, "Local test", "127.0.0.1", self.port, ca.fingerprint(hashes.SHA256()).hex(), local_port=self.local_port)
        self.engine = Engine()

    async def asyncTearDown(self):
        self.engine.stop()
        if self.engine.thread:
            await asyncio.to_thread(self.engine.thread.join, 6)
        self.assertFalse(self.engine.running)
        self.server.close()
        self.tcp.close()
        self.target.close()
        await self.tcp.wait_closed()
        await self.target.wait_closed()
        await self.udp.aclose()
        for task in list(self.target_tasks | self.udp_tasks):
            task.cancel()
        await asyncio.gather(*self.target_tasks, *self.udp_tasks, return_exceptions=True)
        await self.server.wait_closed()
        self.temp.cleanup()

    async def wait_event(self, kind, predicate=lambda _: True):
        async with asyncio.timeout(12):
            while True:
                try:
                    actual, data = self.engine.events.get_nowait()
                    if actual == kind and predicate(data):
                        return data
                except queue.Empty:
                    pass
                await asyncio.sleep(.01)


class DesktopEngineTests(DesktopServerCase):
    async def test_adapter_transfers_data_and_toggles_srtl_on_same_application_socket(self):
        self.engine.start(self.profile, "a" * 64, self.files["ca-cert.pem"])
        await self.wait_event("state", lambda data: data["status"] == "connected")
        reader, writer = await asyncio.open_connection("127.0.0.1", self.local_port)
        try:
            for enabled in (True, False):
                self.engine.set_srtl(enabled)
                payload = os.urandom(128 * 1024)
                writer.write(payload)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 5), payload)
                state = await self.wait_event("state", lambda data: data.get("srtl") is enabled)
                self.assertEqual(state["status"], "connected")
            self.assertEqual(self.target_count, 1)
        finally:
            writer.close()

    async def test_rejected_key_never_reports_connected(self):
        self.engine.start(self.profile, "b" * 64, self.files["ca-cert.pem"])
        event = await self.wait_event("error")
        self.assertEqual(event["reason"], "security_verification_failed")
        self.assertEqual(self.target_count, 0)

    async def test_modified_ca_file_fails_before_network_authentication(self):
        other = generate(pathlib.Path(self.temp.name) / "other", ["127.0.0.1"])
        self.engine.start(self.profile, "a" * 64, other["ca-cert.pem"])
        event = await self.wait_event("error")
        self.assertEqual(event["reason"], "security_verification_failed")
        self.assertEqual(self.target_count, 0)

    async def test_tcp_loss_switches_to_udp_with_same_application_socket(self):
        self.engine.start(self.profile, "a" * 64, self.files["ca-cert.pem"])
        await self.wait_event("state", lambda data: data.get("path") == "tcp")
        reader, writer = await asyncio.open_connection("127.0.0.1", self.local_port)
        try:
            writer.write(b"before failure")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(14), 3), b"before failure")
            self.tcp.close()
            for task, channel in list(self.server.connections.items()):
                if channel.kind == "tcp":
                    channel.close()
            state = await self.wait_event("state", lambda data: data.get("path") == "udp")
            self.assertEqual(state["status"], "connected")
            payload = os.urandom(128 * 1024)
            writer.write(payload)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 5), payload)
            self.assertEqual(self.target_count, 1)
        finally:
            writer.close()

    async def test_stop_during_connect_releases_local_listener(self):
        self.engine.start(self.profile, "a" * 64, self.files["ca-cert.pem"])
        self.engine.stop()
        await self.wait_event("stopped")
        if self.engine.thread:
            await asyncio.to_thread(self.engine.thread.join, 5)
        with socket.socket() as selected:
            selected.bind(("127.0.0.1", self.local_port))


if __name__ == "__main__":
    unittest.main()
