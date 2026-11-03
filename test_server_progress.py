"""Installer activity, private captured output and child-process cleanup."""

import contextlib
import io
import os
import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from server import admin, progress


class InstallerProgressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=".local")
        self.root = pathlib.Path(self.temp.name)
        self.output = io.StringIO()
        self.patches = [patch.object(admin, "LOG", self.root / "install.log"),
                        patch.object(admin, "COLOR", False), patch.object(progress, "POLL", .05),
                        patch.object(progress, "PLAIN_INTERVAL", 0)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def test_waiting_child_shows_activity_and_elapsed_time(self):
        code = "import time; print('Get:1 https://user:password@example.invalid/repo', flush=True); time.sleep(.2); print('Setting up python3-venv (3.11)', flush=True)"
        with contextlib.redirect_stdout(self.output):
            result = admin.run([sys.executable, "-u", "-c", code], progress="Установка пакетов", activity="apt")
        self.assertEqual(result.returncode, 0)
        text = self.output.getvalue()
        self.assertIn("Установка пакетов", text)
        self.assertIn("00:00", text)
        self.assertIn("Загрузка из репозитория", text)
        self.assertIn("Готово", text)
        self.assertNotIn("password", text)
        self.assertNotIn("example.invalid", text)
        self.assertNotIn("import time", text)

    def test_secret_stdin_and_captured_json_are_preserved_without_display(self):
        secret = b"disposable-sensitive-input"
        code = "import sys,time,json; value=sys.stdin.buffer.read(); print(json.dumps({'length':len(value)}),flush=True); time.sleep(.2)"
        with contextlib.redirect_stdout(self.output):
            result = admin.run([sys.executable, "-u", "-c", code], data=secret, capture=True, progress="Проверка сертификата")
        self.assertEqual(result.stdout.strip(), b'{"length": 26}')
        self.assertNotIn("length", self.output.getvalue())
        self.assertNotIn(secret.decode(), self.output.getvalue())
        self.assertNotIn(secret, (self.root / "install.log").read_bytes())

    def test_failure_reports_exit_code_and_private_log_path(self):
        code = "import sys; print('private diagnostic',file=sys.stderr); raise SystemExit(7)"
        with contextlib.redirect_stdout(self.output), self.assertRaises(RuntimeError) as error:
            admin.run([sys.executable, "-c", code], progress="Проверка пакетов")
        self.assertIn("код 7", self.output.getvalue())
        self.assertNotIn("private diagnostic", self.output.getvalue())
        self.assertIn("private diagnostic", (self.root / "install.log").read_text())
        self.assertIn("install.log", str(error.exception))

    def test_quiet_process_and_non_tty_have_no_fake_percentage_or_ansi(self):
        with contextlib.redirect_stdout(self.output):
            display = progress.Progress("Ожидание", None, None, False)
            display.started -= 31
            display.last_output -= 20
            display.update()
            display.update(final=0)
        text = self.output.getvalue()
        self.assertIn("00:31", text)
        self.assertIn("новых сообщений нет", text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("%", text)

    def test_parser_only_exposes_recognized_package_metadata(self):
        self.assertEqual(progress.activity_message("Collecting cryptography==50.0.2", "pip"), "Подготовка: cryptography")
        self.assertEqual(progress.activity_message("Waiting for cache lock: pid 123", "apt"), "Менеджер пакетов занят другим процессом")
        for line in ("secret=very-private", "-----BEGIN PRIVATE KEY-----", '{"access-key":"a"}'):
            for kind in ("apt", "pip", None):
                self.assertIsNone(progress.activity_message(line, kind))

    @unittest.skipUnless(os.name == "posix", "POSIX child groups")
    def test_interrupt_terminates_the_command_and_its_children(self):
        marker = self.root / "child.pid"
        code = "import pathlib,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']); pathlib.Path(sys.argv[1]).write_text(str(child.pid)); time.sleep(30)"
        def interrupt(*args, **kwargs):
            if marker.exists() and marker.read_text().isdigit():
                raise KeyboardInterrupt
        with patch.object(progress.Progress, "update", side_effect=interrupt), contextlib.redirect_stdout(self.output):
            with self.assertRaises(KeyboardInterrupt):
                admin.run([sys.executable, "-u", "-c", code, str(marker)], progress="Проверка остановки")
        pid = marker.read_text()
        state = pathlib.Path("/proc") / pid / "stat"
        deadline = time.monotonic() + 2
        while state.exists() and state.read_text().split()[2] != "Z" and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(not state.exists() or state.read_text().split()[2] == "Z")


if __name__ == "__main__":
    unittest.main()
