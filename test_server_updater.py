"""Downloaded root code must pass version, size, hash, path and manifest checks."""

import argparse
import contextlib
import gzip
import hashlib
import io
import json
import os
import pathlib
import tarfile
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from server import admin, build, config, updater


def asset(name=updater.ARCHIVE):
    return dict(name=name, state="uploaded", digest="sha256:" + "a" * 64, size=1024)


def release(tag="server-v0.2.2"):
    return dict(tag_name=tag, draft=False, prerelease=True,
                assets=[asset(), asset(updater.ARCHIVE + ".sha256")])


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=".local")
        self.root = pathlib.Path(self.temp.name)
        self.archive, sha = build.build(self.root)
        self.data = self.archive.read_bytes()
        self.release = updater.Release(config.SERVER_VERSION, "server-v" + config.SERVER_VERSION, len(self.data), sha, True)

    def tearDown(self):
        self.temp.cleanup()

    def test_selects_highest_complete_server_version_not_github_list_order(self):
        items = [release("clients-v0.2.0"), release("server-v0.2.9"), release("server-v0.10.0")]
        missing = release("server-v99.0.0")
        missing["assets"] = []
        items += [missing, dict(release("server-v88.0.0"), draft=True), release("unrelated-v99.0.0"), release("server-v0.10.0-beta1")]
        with patch.object(updater, "download", return_value=json.dumps(items).encode()):
            chosen = updater.latest()
        self.assertEqual(chosen.version, "0.10.0")
        self.assertTrue(chosen.prerelease)
        self.assertTrue(chosen.url(updater.ARCHIVE).startswith("https://github.com/TheSunDoesNotExist/Myprotocol/releases/download/server-v0.10.0/"))

    def test_rejects_ambiguous_metadata_and_untrusted_redirects(self):
        for invalid in ["0.1", "01.2.3", "0.2.3\n", "1.2.3;reboot", None, "9" * 50 + ".0.0"]:
            with self.assertRaises(ValueError):
                updater.version(invalid)
        for url in ("http://github.com/a", "https://github.com.evil.example/a", "file:///etc/passwd", "https://user@github.com/a", "https://github.com:8080/a"):
            with self.assertRaises(ValueError):
                updater.secure_url(url)
        with self.assertRaises(ValueError):
            updater.parse_json(b'{"version":1,"version":2}')
        for body in (b'{}', b'[' * 2000 + b']' * 2000, json.dumps([dict(release(), assets=[dict(asset(), digest=None)])]).encode()):
            with patch.object(updater, "download", return_value=body), self.assertRaises(ValueError):
                updater.latest()

    def test_real_package_validates_before_writing(self):
        source = updater.unpack(self.data, self.root / "staged", self.release)
        self.assertEqual(admin.verify_package(source), source.resolve())
        self.assertEqual((source / "server/updater.py").read_bytes(), pathlib.Path("server/updater.py").read_bytes())
        self.assertFalse((source / "credentials").exists())
        with self.assertRaises(ValueError):
            updater.unpack(self.data, source, self.release)

    def test_future_package_can_add_files_when_manifest_covers_them(self):
        def add(files):
            content = b"# future server module\n"
            path = "server/future_module.py"
            result = []
            for item, data in files:
                if item.name.endswith("/MANIFEST.json"):
                    manifest = json.loads(data)
                    manifest["sha256"][path] = hashlib.sha256(content).hexdigest()
                    data = json.dumps(manifest).encode()
                result.append((item, data))
            result.append((tarfile.TarInfo(f"myownvpn-server-debian13-v{config.PROTOCOL}/" + path), content))
            return result
        data, rel = self.rewrite(add)
        source = updater.unpack(data, self.root / "future", rel)
        self.assertEqual((source / "server/future_module.py").read_bytes(), b"# future server module\n")

    def test_download_size_and_redirect_policy_are_enforced(self):
        response = argparse.Namespace(status=200, geturl=lambda: "https://github.com/test", read=lambda size: b"x" * size)
        opener = argparse.Namespace(open=lambda *args, **kwargs: contextlib.nullcontext(response))
        with patch.object(updater.urllib.request, "build_opener", return_value=opener), self.assertRaises(ValueError):
            updater.download("https://github.com/test", 10)
        request = updater.urllib.request.Request("https://github.com/test")
        with self.assertRaises(ValueError):
            updater.Redirect().redirect_request(request, None, 302, "", {}, "http://github.com/unsafe")

    def rewrite(self, change):
        with tarfile.open(fileobj=io.BytesIO(self.data), mode="r:gz") as archive:
            files = [(item, archive.extractfile(item).read()) for item in archive]
        files = change(files)
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as archive:
            for item, content in files:
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content) if item.isfile() else None)
        data = gzip.compress(raw.getvalue())
        return data, replace(self.release, size=len(data), sha256=hashlib.sha256(data).hexdigest())

    def test_corrupt_archive_and_wrong_manifest_never_produce_staged_code(self):
        wrong = replace(self.release, sha256="0" * 64)
        with self.assertRaises(ValueError):
            updater.unpack(self.data, self.root / "bad", wrong)
        with self.assertRaises(ValueError):
            updater.unpack(self.data, self.root / "bad", replace(self.release, version="9.9.9"))
        def tamper(files):
            return [(item, content + b"tampered" if item.name.endswith("tunnel.py") else content) for item, content in files]
        data, rel = self.rewrite(tamper)
        with self.assertRaises(ValueError):
            updater.unpack(data, self.root / "bad", rel)
        self.assertFalse((self.root / "bad").exists())

    def test_paths_links_duplicates_and_compressed_bombs_are_rejected(self):
        for path in ("../outside", "/etc/cron.d/evil", "server/../../outside", "server\\evil", "server/./evil"):
            def add(files):
                item = tarfile.TarInfo(f"myownvpn-server-debian13-v{config.PROTOCOL}/" + path)
                return files + [(item, b"bad")]
            data, rel = self.rewrite(add)
            with self.subTest(path=path), self.assertRaises(ValueError):
                updater.unpack(data, self.root / "bad", rel)
        def link(files):
            item = tarfile.TarInfo(f"myownvpn-server-debian13-v{config.PROTOCOL}/link")
            item.type, item.linkname = tarfile.SYMTYPE, "/etc/passwd"
            return files + [(item, b"")]
        for change in (link, lambda files: files + files[:1]):
            data, rel = self.rewrite(change)
            with self.assertRaises(ValueError):
                updater.unpack(data, self.root / "bad", rel)
        with patch.object(updater, "MAX_UNPACKED", 100):
            with self.assertRaises(ValueError):
                updater.unpack(self.data, self.root / "bad", self.release)
        self.assertFalse((self.root / "bad").exists())

    def test_sidecar_mismatch_prevents_archive_download(self):
        with patch.object(updater, "download", return_value=b"0" * 64 + b"  wrong.tar.gz\n") as download:
            with self.assertRaises(ValueError):
                updater.stage(self.release, self.root / "bad")
        self.assertEqual(download.call_count, 1)

    def test_menu_check_cancel_and_apply_use_verified_new_installer(self):
        (self.root / "server.json").write_text("{}")
        major, minor, patch_number = updater.version(config.SERVER_VERSION)
        future = f"{major}.{minor}.{patch_number + 1}"
        candidate = replace(self.release, version=future, tag="server-v" + future)
        args = argparse.Namespace(yes=False, no_start=False)
        with patch.object(admin, "ETC", self.root), patch.object(updater, "latest", return_value=candidate), patch.object(updater, "stage", return_value=self.root / "stage") as stage, patch.object(admin.subprocess, "run", return_value=argparse.Namespace(returncode=0)) as run, patch.object(admin, "yes", return_value=False), patch.object(admin.tempfile, "TemporaryDirectory", side_effect=lambda **kwargs: contextlib.nullcontext(str(self.root))), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(admin.online_update(args, check_only=True))
            stage.assert_not_called()
            self.assertFalse(admin.online_update(args))
            run.assert_not_called()
            args.yes = True
            self.assertTrue(admin.online_update(args))
            command = run.call_args.args[0]
            self.assertEqual(command[:2], ["/usr/bin/python3", "-I"])
            self.assertEqual(command[2], str(self.root / "stage/server/admin.py"))
            self.assertEqual(command[3:], ["update", "--source", str(self.root / "stage"), "--yes"])
            run.reset_mock()
            with patch.object(updater, "latest", return_value=self.release):
                self.assertFalse(admin.online_update(args))
            run.assert_not_called()

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0, "POSIX root installation lock")
    def test_concurrent_installs_cannot_change_active_version_together(self):
        path = self.root / "install.lock"
        with updater.installation_lock(path):
            with self.assertRaises(ValueError):
                with updater.installation_lock(path):
                    self.fail("a concurrent install must not acquire the lock")
        with updater.installation_lock(path):
            pass


if __name__ == "__main__":
    unittest.main()
