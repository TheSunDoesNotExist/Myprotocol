"""Qt interaction checks; optional when only server dependencies are installed."""

import asyncio
from concurrent.futures import Future
import logging
import pathlib
import unittest
from unittest.mock import patch

from test_desktop import DesktopServerCase, make_package

try:
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication
    from desktop.app import Window
except ImportError:
    QApplication = None


@unittest.skipIf(QApplication is None, "Install desktop/requirements.lock for Qt checks")
class DesktopGuiTests(DesktopServerCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.window = Window(pathlib.Path(self.temp.name) / "gui")
        self.engine = self.window.engine
        self.window.show()

    async def asyncTearDown(self):
        self.window.close()
        self.engine.stop()
        if self.engine.thread:
            await asyncio.to_thread(self.engine.thread.join, 6)
        self.window.poll()
        self.window.close()
        for handler in logging.getLogger("tunnel").handlers[:]:
            logging.getLogger("tunnel").removeHandler(handler)
            handler.close()
        await super().asyncTearDown()

    async def wait_ui(self, condition):
        async with asyncio.timeout(12):
            while not condition():
                self.app.processEvents()
                self.window.poll()
                await asyncio.sleep(.01)
            self.window.poll()

    async def test_empty_profile_disables_connect_and_shows_actual_local_port(self):
        self.assertFalse(self.window.connect_button.isEnabled())
        self.assertEqual(self.window.local_port.lineEdit().text(), "1080")
        self.assertEqual(self.window.status.text(), "Отключено")

    async def test_import_connect_srtl_and_disconnect_with_real_tunnel(self):
        archive = pathlib.Path(self.temp.name) / "client.tar.gz"
        make_package(archive, self.files["ca-cert.pem"].read_bytes(), server=f"127.0.0.1:{self.port}")
        with patch.object(self.window.vault, "save"):
            self.window.begin_import(archive)
            await self.wait_ui(lambda: self.window.pending is None)
        self.assertEqual(len(self.window.profiles), 1)
        self.window.local_port.setValue(self.local_port)
        QTest.mouseClick(self.window.connect_button, Qt.MouseButton.LeftButton)
        await self.wait_ui(lambda: self.window.current_snapshot.get("status") == "connected")
        self.assertIn("сертификат проверен", self.window.description.text())
        reader, writer = await asyncio.open_connection("127.0.0.1", self.local_port)
        try:
            QTest.mouseClick(self.window.srtl, Qt.MouseButton.LeftButton)
            await self.wait_ui(lambda: self.window.current_snapshot.get("srtl") is True)
            payload = b"GUI transport integration" * 3000
            writer.write(payload)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 5), payload)
            self.assertEqual(self.target_count, 1)
        finally:
            writer.close()
        QTest.mouseClick(self.window.connect_button, Qt.MouseButton.LeftButton)
        await self.wait_ui(lambda: not self.engine.running)
        self.assertEqual(self.window.status.text(), "Отключено")
        self.assertEqual(self.window.path_rows["tcp"].note.text(), "Не измерялся")
        self.assertTrue(self.window.connect_button.isEnabled())

    async def test_close_during_vault_operation_does_not_start_a_connection(self):
        future = Future()
        self.window.pending = ("connect", future)
        self.window.close()
        self.assertTrue(self.window.closing)
        future.set_result((self.profile, "a" * 64, self.files["ca-cert.pem"]))
        with patch.object(self.engine, "start") as start:
            self.window.poll()
            start.assert_not_called()
        self.assertFalse(self.engine.running)


if __name__ == "__main__":
    unittest.main()
