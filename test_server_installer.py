"""Installer checks: package integrity, credential boundaries and failed reloads."""

import argparse
import contextlib
import io
import json
import os
import pathlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization

from ip_cert import generate
from server import admin, build, config, identity


TEMP_ROOT = pathlib.Path(__file__).resolve().parent / ".local"
TEMP_ROOT.mkdir(exist_ok=True)


def example():
    return dict(schema=1, protocol=5, public_ips=["198.51.100.10"], listen="0.0.0.0",
                port=443, target=["127.0.0.1", 9000], transport="auto", grace=30, srtl=False)


class ServerInstallerTests(unittest.TestCase):
    def test_debian_12_and_13_use_their_own_system_python(self):
        for version, expected in (("12", [3, 11]), ("12.15", [3, 11]), ("13", [3, 13])):
            with self.subTest(version=version), patch.object(config.platform, "freedesktop_os_release", return_value=dict(ID="debian", VERSION_ID=version)):
                self.assertEqual(config.debian_python(), expected)
        for release in (dict(ID="ubuntu", VERSION_ID="24.04"), dict(ID="debian", VERSION_ID="11"), dict(ID="debian", VERSION_ID="14"), dict(ID="debian", VERSION_ID="sid")):
            with self.subTest(release=release), patch.object(config.platform, "freedesktop_os_release", return_value=release), self.assertRaises(ValueError):
                config.debian_python()

    def test_config_rejects_unsafe_or_ambiguous_values(self):
        values = dict(port=[0, 65536, True], public_ips=[["example.org"], ["0.0.0.0"], [1234]],
                      listen=["0.0.0.0\nExecStart=/bin/sh", "::"], schema=[True, 2],
                      srtl=["false", 0], target=[["localhost", 9000], ["127.0.0.1", True]],
                      grace=[float("nan"), float("inf")])
        for key, invalid in values.items():
            for value in invalid:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    config.validate(dict(example(), **{key: value}))

    def test_systemd_has_no_key_in_environment_and_least_bind_capability(self):
        unit = config.unit_text(example())
        for required in ("User=myownvpn", "LoadCredential=access-key:", "NoNewPrivileges=yes",
                         "ProtectSystem=strict", "LimitCORE=0", " -I "):
            self.assertIn(required, unit)
        self.assertNotIn("Environment=", unit)
        self.assertIn("AmbientCapabilities=CAP_NET_BIND_SERVICE", unit)
        self.assertIn("AmbientCapabilities=\n", config.unit_text(dict(example(), port=8443)))

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_public_config_mode_survives_private_bootstrap_umask(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            root = pathlib.Path(directory)
            previous = os.umask(0o077)
            try:
                admin.atomic_write(root / "server.json", json.dumps(example()), 0o644)
                admin.atomic_write(root / "access-key", "a" * 64)
            finally:
                os.umask(previous)
            self.assertEqual((root / "server.json").stat().st_mode & 0o777, 0o644)
            self.assertEqual((root / "access-key").stat().st_mode & 0o777, 0o600)

    def test_package_is_reproducible_allowlisted_and_detects_tampering(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            root = pathlib.Path(directory)
            archive, digest = build.build(root / "a")
            second, second_digest = build.build(root / "b")
            self.assertEqual(digest, second_digest)
            self.assertEqual(archive.read_bytes(), second.read_bytes())
            with tarfile.open(archive) as bundle:
                members = bundle.getmembers()
                expected = set(config.APP_FILES + config.SERVER_FILES + ("install.sh", "MANIFEST.json"))
                self.assertEqual({str(pathlib.PurePosixPath(v.name).relative_to(v.name.split('/')[0])) for v in members}, expected)
                self.assertTrue(all(v.isfile() for v in members))
                # Debian 12's Python lacks extractall(filter=...). Write only the
                # regular, allowlisted members checked above, without tar extraction.
                for item in members:
                    destination = root / "unpacked" / item.name
                    self.assertTrue(destination.resolve().is_relative_to((root / "unpacked").resolve()))
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(bundle.extractfile(item).read())
            source = next((root / "unpacked").iterdir())
            self.assertEqual(admin.verify_package(source), source.resolve())
            (source / "tunnel.py").write_text("tampered")
            with self.assertRaisesRegex(ValueError, "tunnel.py"):
                admin.verify_package(source)
            for broken in ([], {"format": 1, "protocol": 5, "sha256": None}):
                (source / "MANIFEST.json").write_text(json.dumps(broken))
                with self.assertRaises(ValueError):
                    admin.verify_package(source)

    def test_export_excludes_private_identity_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            root = pathlib.Path(directory)
            (root / "credentials").mkdir()
            (root / "ca-cert.pem").write_bytes(b"public CA")
            (root / "credentials/access-key").write_bytes(b"a" * 64)
            (root / "credentials/server-key.pem").write_bytes(b"PRIVATE SERVER KEY")
            (root / "ca-key.pem").write_bytes(b"PRIVATE CA KEY")
            output = root / "client.tar.gz"
            with patch.object(admin, "ETC", root), patch.object(admin, "load", return_value=example()), contextlib.redirect_stdout(io.StringIO()):
                # Migrated shared keys are now an explicitly selected revocable client.
                data = admin.ensure_clients()
                with patch("server.clients.locked", side_effect=lambda _: contextlib.nullcontext()):
                    admin.export_client(output, data["clients"][0]["id"])
                with self.assertRaises(FileExistsError):
                    with patch("server.clients.locked", side_effect=lambda _: contextlib.nullcontext()):
                        admin.export_client(output, data["clients"][0]["id"])
            with tarfile.open(output) as bundle:
                self.assertEqual(set(bundle.getnames()), {"ca-cert.pem", "access-key", "client.json", "CONNECT.txt"})
                self.assertTrue(all(v.mode == 0o600 for v in bundle.getmembers()))
                content = b"\n".join(bundle.extractfile(v).read() for v in bundle.getmembers())
                self.assertNotIn(b"PRIVATE SERVER KEY", content)
                self.assertNotIn(b"PRIVATE CA KEY", content)

    def test_failed_srtl_reload_restores_configuration(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            root = pathlib.Path(directory)
            initial = example()
            path = root / "server.json"
            path.write_text(json.dumps(initial))
            with patch.object(admin, "ETC", root), patch.object(admin, "load", return_value=initial), patch.object(admin, "run", return_value=argparse.Namespace(returncode=1)):
                with self.assertRaises(RuntimeError):
                    admin.change_srtl("on")
            self.assertEqual(json.loads(path.read_text()), example())
            self.assertEqual(list(root.glob("*.tmp-*")), [])

    @unittest.skipIf(os.name == "nt", "POSIX service activation and symlinks")
    def test_activation_failure_rolls_back_code_unit_command_and_autostart(self):
        import pwd
        for updating, active in ((False, False), (True, True), (True, False)):
            with self.subTest(updating=updating, active=active), tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
                root = pathlib.Path(directory)
                previous, release = root / "old", root / "new"
                previous.mkdir()
                release.mkdir()
                unit, command = root / "service", root / "command"
                old_unit, old_command = config.MARKER + "\nold unit", "#!/bin/sh\n" + config.MARKER
                if updating:
                    (root / "current").symlink_to(previous)
                    unit.write_text(old_unit)
                    command.write_text(old_command)
                def run(args, **kwargs):
                    success = updating if args[1] == "is-enabled" else active if args[1] == "is-active" else True
                    return argparse.Namespace(returncode=0 if success else 1)
                account = argparse.Namespace(pw_uid=1001, pw_gid=1001, pw_shell="/usr/sbin/nologin")
                (root / "clients.json").write_text(json.dumps(admin.clients.empty()))
                with patch.multiple(admin, BASE=root, UNIT=unit, COMMAND=command,
                                    STATE_DIR=root / "state", LOG_DIR=root / "log", ETC=root), patch.object(pwd, "getpwnam", return_value=account), patch.object(admin.os, "chown"), patch.object(admin, "run", side_effect=run) as invoked, patch.object(admin, "health_check", side_effect=RuntimeError("health failure")), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(RuntimeError, "health failure"):
                        admin.activate(release, example())
                if updating:
                    self.assertEqual((root / "current").resolve(), previous)
                    self.assertEqual(unit.read_text(), old_unit)
                    self.assertEqual(command.read_text(), old_command)
                else:
                    self.assertFalse((root / "current").is_symlink())
                    self.assertFalse(unit.exists())
                    self.assertFalse(command.exists())
                    self.assertTrue(any(call.args[0][1] == "disable" for call in invoked.call_args_list))
                restarts = [call for call in invoked.call_args_list if call.args[0][1] == "restart"]
                self.assertEqual(len(restarts), 2 if updating and active else 1)

    def test_identity_rejects_wrong_ip_and_wrong_private_key(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            root = pathlib.Path(directory)
            files = generate(root / "one", ["198.51.100.10"])
            other = generate(root / "two", ["198.51.100.10"])
            self.assertIn("expires", identity.validate(files["ca-cert.pem"], files["server-cert.pem"], files["server-key.pem"], ["198.51.100.10"]))
            with self.assertRaises(ValueError):
                identity.validate(files["ca-cert.pem"], files["server-cert.pem"], files["server-key.pem"], ["198.51.100.11"])
            with self.assertRaises(ValueError):
                identity.validate(files["ca-cert.pem"], files["server-cert.pem"], other["server-key.pem"], ["198.51.100.10"])

    def test_generated_ca_backup_requires_password_and_omits_plaintext(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            root = pathlib.Path(directory)
            real_temp = tempfile.TemporaryDirectory
            def local_temp(**kwargs):
                return real_temp(dir=root, prefix=kwargs.get("prefix", ""))
            password = b"disposable-unit-test-password"
            with patch.object(identity.tempfile, "TemporaryDirectory", side_effect=local_temp), patch.object(identity.sys, "stdin", argparse.Namespace(buffer=io.BytesIO(password))):
                identity.create(root / "identity", ["198.51.100.10"])
            out = root / "identity"
            self.assertEqual(set(v.name for v in out.iterdir()), {"ca-cert.pem", "server-cert.pem", "server-key.pem", "ca-key.encrypted.pem"})
            encrypted = (out / "ca-key.encrypted.pem").read_bytes()
            self.assertIn(b"ENCRYPTED PRIVATE KEY", encrypted)
            serialization.load_pem_private_key(encrypted, password=password)
            with self.assertRaises((TypeError, ValueError)):
                serialization.load_pem_private_key(encrypted, password=None)
            self.assertEqual(set(v.name for v in root.iterdir()), {"identity"})


if __name__ == "__main__":
    unittest.main()
