"""Per-client authentication, revocation, traffic persistence and copy/paste boundaries."""

import asyncio
import contextlib
import io
import json
import pathlib
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from client_config import decode, encode
from desktop.profiles import import_text
from server import admin, clients
from server.runtime import watch_clients
import test_desktop as desktop_tests
from test_desktop import DesktopServerCase
from transports import tls_client, quic_config
from tunnel import Session, connect, probe, SecurityError, ProtocolError


class ConnectionTextTests(unittest.TestCase):
    setUp = desktop_tests.ClientProfileTests.setUp
    tearDown = desktop_tests.ClientProfileTests.tearDown
    def test_round_trip_and_distinct_credentials_on_one_server(self):
        token = encode("127.0.0.1:8443", self.ca, "a" * 64, "Домашний ПК")
        imported = import_text("\n " + token + " \n")
        self.assertEqual(imported.profile.name, "Домашний ПК")
        self.assertEqual(imported.key, "a" * 64)
        self.assertNotIn(imported.key, repr(imported))
        other = import_text(encode("127.0.0.1:8443", self.ca, "b" * 64, "Работа"))
        self.assertNotEqual(imported.profile.id, other.profile.id)
        self.assertEqual(imported.profile.ca_sha256, other.profile.ca_sha256)

    def test_invalid_text_is_bounded_and_errors_never_echo_secrets(self):
        import base64
        token = encode("127.0.0.1:8443", self.ca, "a" * 64, "ПК")
        cfg = decode(token)
        invalid = ["", "http://example.org", token + "?key=secret", token + "\nextra", "x" * 32769]
        for field, value in (("server", "example.com:443"), ("ca", "bad"), ("key", "SECRET"), ("schema", True), ("name", "bad\x1b[2J")):
            raw = json.dumps(dict(cfg, **{field: value})).encode()
            invalid.append("myownvpn://" + base64.urlsafe_b64encode(raw).decode().rstrip("="))
        invalid.append("myownvpn://" + base64.urlsafe_b64encode(("[" * 2000 + "]" * 2000).encode()).decode().rstrip("="))
        for value in invalid:
            with self.subTest(length=len(value)), self.assertRaises(ValueError) as error:
                import_text(value)
            self.assertNotIn("SECRET", str(error.exception))


class ClientRegistryTests(unittest.TestCase):
    def test_failed_acknowledgement_stops_service_without_restoring_revoked_key(self):
        import argparse
        with tempfile.TemporaryDirectory(dir=".local") as directory:
            root = pathlib.Path(directory)
            item = clients.record("PC", "b" * 64)
            (root / "clients.json").write_text(json.dumps(dict(clients.empty(), clients=[item])))
            with patch.object(admin, "ETC", root), patch.object(clients, "locked", side_effect=lambda _: contextlib.nullcontext()), patch.object(admin, "run", return_value=argparse.Namespace(returncode=0)) as run, patch.object(admin.time, "monotonic", side_effect=[0, 6]):
                with self.assertRaisesRegex(RuntimeError, "остановлена"):
                    admin.delete_client(item["id"])
            self.assertEqual(clients.load(root / "clients.json")["clients"], [])
            self.assertEqual(run.call_args.args[0], ("systemctl", "stop", "myownvpn.service"))

    def test_admin_create_show_delete_and_migrate_without_exporting_shared_health_key(self):
        with tempfile.TemporaryDirectory(dir=".local") as directory:
            root = pathlib.Path(directory)
            (root / "credentials").mkdir()
            (root / "credentials/access-key").write_text("a" * 64)
            (root / "ca-cert.pem").write_text("PUBLIC CA")
            cfg = dict(public_ips=["127.0.0.1"], port=8443)
            with patch.object(admin, "ETC", root), patch.object(admin, "load", return_value=cfg), patch.object(admin, "wait_clients") as applied, patch.object(clients, "locked", side_effect=lambda _: contextlib.nullcontext()):
                old = admin.ensure_clients()["clients"][0]
                self.assertNotEqual((root / "credentials/health-key").read_text().strip(), "a" * 64)
                first, second = admin.create_client("ПК"), admin.create_client("Ноутбук")
                self.assertNotEqual(first["key_hash"], second["key_hash"])
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    admin.show_client(first["id"])
                token = next(line for line in output.getvalue().splitlines() if line.startswith("myownvpn://"))
                key = decode(token)["key"]
                self.assertNotEqual(key, "a" * 64)
                self.assertNotIn(key, (root / "clients.json").read_text())
                with contextlib.redirect_stdout(io.StringIO()):
                    admin.delete_client(first["id"])
                data = clients.load(root / "clients.json")
                self.assertEqual({c["id"] for c in data["clients"]}, {old["id"], second["id"]})
                self.assertFalse((root / "credentials/clients" / first["id"]).exists())
                with self.assertRaises(ValueError):
                    admin.show_client(first["id"])
                self.assertEqual(applied.call_count, 3)
                (root / "clients.json").unlink()
                with self.assertRaisesRegex(ValueError, "отсутствует"):
                    admin.ensure_clients()

    def test_registry_rejects_duplicates_invalid_names_and_hashes(self):
        first = clients.record("PC", "a" * 64)
        for data in (dict(clients.empty(), clients=[first, first]), dict(clients.empty(), clients=[dict(first, name="x\n")]), dict(clients.empty(), clients=[dict(first, key_hash="short")])):
            with self.assertRaises(ValueError):
                clients.validate(data)


class ClientAccessTests(DesktopServerCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.first = clients.record("First", "a" * 64)
        self.second = clients.record("Second", "b" * 64)
        self.server.key = "c" * 64  # Dedicated health key; never a client's credential.
        self.server.set_clients({c["key_hash"]: c["id"] for c in (self.first, self.second)})
        self.extra_sessions = []

    async def asyncTearDown(self):
        for session in self.extra_sessions:
            session.close()
            await session.wait_closed()
        await super().asyncTearDown()

    async def channel(self, key, kind="tcp", session=None):
        if session is None:
            session = Session()
            self.extra_sessions.append(session)
        await connect(session, ("127.0.0.1", self.port), key,
                      tls_client(self.files["ca-cert.pem"]), "127.0.0.1", kind=kind,
                      quic=quic_config(ca=self.files["ca-cert.pem"], hostname="127.0.0.1"))
        return session

    async def test_revocation_closes_only_own_sessions_and_cannot_resume_or_reauthenticate(self):
        for kind in ("tcp", "udp"):
            first = await self.channel("a" * 64, kind)
            second = await self.channel("b" * 64, kind)
            own = next(s for s in self.server.sessions.values() if s.sid == first.sid)
            self.server.set_clients({self.second["key_hash"]: self.second["id"]})
            self.assertTrue(own.closed)
            self.assertEqual(own.reason, "client_revoked")
            self.assertFalse(self.server.sessions[second.sid].closed)
            for session in (first, None):
                with self.assertRaises((SecurityError, ConnectionError, asyncio.IncompleteReadError)):
                    await self.channel("a" * 64, kind, session)
            # Restore only for the next transport test, never as part of deletion itself.
            self.server.set_clients({c["key_hash"]: c["id"] for c in (self.first, self.second)})

    async def test_one_client_cannot_resume_another_clients_session(self):
        first = await self.channel("a" * 64)
        with self.assertRaises((ConnectionError, SecurityError, ProtocolError)):
            await self.channel("b" * 64, session=first)
        self.assertFalse(self.server.sessions[first.sid].closed)

    async def test_health_key_can_probe_but_never_create_a_data_session(self):
        for kind in ("tcp", "udp"):
            samples = await probe(kind, ("127.0.0.1", self.port), "c" * 64,
                                  tls_client(self.files["ca-cert.pem"]), "127.0.0.1",
                                  quic_config(ca=self.files["ca-cert.pem"], hostname="127.0.0.1"))
            self.assertEqual(len(samples), 3)
            with self.assertRaises(SecurityError):
                await self.channel("c" * 64, kind)
        self.assertFalse(self.server.sessions)

    async def test_another_client_can_continue_transferring_after_revocation(self):
        first = await self.channel("a" * 64)
        self.engine.start(self.profile, "b" * 64, self.files["ca-cert.pem"])
        await self.wait_event("state", lambda d: d["status"] == "connected")
        reader, writer = await asyncio.open_connection("127.0.0.1", self.local_port)
        try:
            for allowed in ({c["key_hash"]: c["id"] for c in (self.first, self.second)}, {self.second["key_hash"]: self.second["id"]}):
                self.server.set_clients(allowed)
                writer.write(b"other client remains connected" * 1000)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(30000), 5), b"other client remains connected" * 1000)
            self.assertTrue(self.server.sessions[first.sid].closed)
            self.assertEqual(self.target_count, 1)
        finally:
            writer.close()

    async def test_live_registry_reload_and_invalid_registry_fail_closed(self):
        root = pathlib.Path(self.temp.name)
        path = root / "clients.json"
        data = dict(clients.empty(), clients=[self.first, self.second])
        path.write_text(json.dumps(data))
        usage = clients.Usage(root / "usage.sqlite")
        monitor = asyncio.create_task(watch_clients(self.server, path, usage))
        try:
            first = await self.channel("a" * 64, "udp")
            second = await self.channel("b" * 64)
            data = dict(clients.empty(), clients=[self.second])
            path.write_text(json.dumps(data))
            async with asyncio.timeout(3):
                while not self.server.sessions[first.sid].closed:
                    await asyncio.sleep(.02)
            self.assertFalse(self.server.sessions[second.sid].closed)
            self.assertEqual(clients.snapshot(root / "usage.sqlite")[2], data["revision"])
            path.write_text("invalid")
            async with asyncio.timeout(3):
                while not self.server.sessions[second.sid].closed:
                    await asyncio.sleep(.02)
            self.assertIsNone(self.server.authenticate("b" * 64, probe=False))
        finally:
            monitor.cancel()
            await asyncio.gather(monitor, return_exceptions=True)
            usage.close()

    async def test_unique_payload_counters_persist_and_never_double_count_on_flush(self):
        self.engine.start(self.profile, "a" * 64, self.files["ca-cert.pem"])
        await self.wait_event("state", lambda d: d["status"] == "connected")
        reader, writer = await asyncio.open_connection("127.0.0.1", self.local_port)
        payload = b"accounted bytes" * 8000
        try:
            writer.write(payload)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 5), payload)
            async with asyncio.timeout(3):
                while sum(s.tx_bytes for s in self.server.sessions.values()) < len(payload):
                    await asyncio.sleep(.01)
            path = pathlib.Path(self.temp.name) / "usage.sqlite"
            usage = clients.Usage(path)
            try:
                usage.flush(self.server, "a" * 32)
                usage.flush(self.server, "a" * 32)
                counters, active, _, _ = clients.snapshot(path)
                self.assertEqual(counters[self.first["id"]], (len(payload), len(payload)))
                self.assertEqual(active[self.first["id"]], 1)
                self.server.set_clients({self.second["key_hash"]: self.second["id"]})
                usage.flush(self.server, "b" * 32)
                self.assertNotIn(self.first["id"], clients.snapshot(path)[1])
            finally:
                usage.close()
            reopened = clients.Usage(path)
            reopened.close()
            self.assertEqual(clients.snapshot(path)[0][self.first["id"]], (len(payload), len(payload)))
        finally:
            writer.close()
