"""Qt interaction checks; optional when only server dependencies are installed."""

import asyncio
from concurrent.futures import Future
import logging
import json
import os
import pathlib
import unittest
from unittest.mock import patch

from test_desktop import DesktopServerCase, make_package

try:
    from PySide6.QtCore import Qt, QPoint
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QScrollArea
    from desktop.app import Window, configure_application
except ImportError:
    QApplication = None


@unittest.skipIf(QApplication is None, "Install desktop/requirements.lock for Qt checks")
class DesktopGuiTests(DesktopServerCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        configure_application(cls.app)

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
        self.app.processEvents()
        self.assertFalse(self.window.connect_button.isEnabled())
        self.assertEqual(self.window.local_port.lineEdit().text(), "1080")
        self.assertGreater(self.window.local_port.lineEdit().width(), 60)
        self.assertEqual(self.window.status.text(), "Отключено")
        for width, height in ((860, 600), (1200, 900)):
            self.window.resize(width, height)
            self.app.processEvents()
            scroll = self.window.pages.widget(0)
            self.assertIsInstance(scroll, QScrollArea)
            self.assertEqual(scroll.horizontalScrollBar().maximum(), 0)

    async def test_pasted_configuration_uses_vault_and_preserves_client_name(self):
        from client_config import encode
        text = encode(f"127.0.0.1:{self.port}", self.files["ca-cert.pem"].read_bytes(), "a" * 64, "Мой ПК")
        with patch.object(self.window.vault, "save") as save:
            self.window.begin_import(text, pasted=True)
            await self.wait_ui(lambda: self.window.pending is None)
        self.assertEqual(self.window.profile.name, "Мой ПК")
        save.assert_called_once_with(self.window.profile.id, "a" * 64)
        self.assertTrue(self.window.connect_button.isEnabled())
        self.assertTrue(self.window.paste_button.isEnabled())

    async def test_import_connect_srtl_and_disconnect_with_real_tunnel(self):
        archive = pathlib.Path(self.temp.name) / "client.tar.gz"
        make_package(archive, self.files["ca-cert.pem"].read_bytes(), server=f"127.0.0.1:{self.port}")
        with patch.object(self.window.vault, "save"):
            self.window.begin_import(archive)
            await self.wait_ui(lambda: self.window.pending is None)
        self.assertEqual(len(self.window.profiles), 1)
        self.window.resize(860, 600)
        self.app.processEvents()
        self.assertEqual(self.window.pages.widget(0).horizontalScrollBar().maximum(), 0)
        self.window.resize(1200, 900)
        self.window.local_port.setValue(self.local_port)
        QTest.mouseClick(self.window.connect_button, Qt.MouseButton.LeftButton)
        await self.wait_ui(lambda: self.window.current_snapshot.get("status") == "connected")
        self.assertIn("сертификат проверен", self.window.description.text())
        reader, writer = await asyncio.open_connection("127.0.0.1", self.local_port)
        try:
            QTest.mouseClick(self.window.srtl, Qt.MouseButton.LeftButton, pos=QPoint(10, self.window.srtl.height() // 2))
            await self.wait_ui(lambda: self.window.current_snapshot.get("srtl") is True)
            payload = b"GUI transport integration" * 3000
            writer.write(payload)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 5), payload)
            self.assertEqual(self.target_count, 1)
            if capture := os.environ.get("MYOWNVPN_TEST_CAPTURE"):
                await self.wait_ui(lambda: self.window.current_snapshot.get("rx_bytes", 0) >= len(payload))
                folder = pathlib.Path(capture)
                folder.mkdir(parents=True, exist_ok=True)
                self.window.grab().save(str(folder / "connected.png"))
                self.window.pages.setCurrentIndex(1)
                self.app.processEvents()
                self.window.log_table.selectRow(self.window.log_table.rowCount() - 1)
                self.window.grab().save(str(folder / "logs.png"))
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

    async def test_active_path_is_visible_before_first_measurement(self):
        self.window.show_snapshot(dict(status="connected", path="tcp",
                                       paths={"tcp": dict(available=False, rtt_ms=None)}))
        self.assertEqual(self.window.path_rows["tcp"].note.text(), "Активен · измеряем задержку")
        self.assertEqual(self.window.figures["rtt"].text(), "—")

    async def test_log_selection_survives_updates_and_clears_when_filtered_out(self):
        first = dict(time="2026-11-10T10:12:03+00:00", level="INFO", event="connect_attempt", path="tcp")
        second = dict(time="2026-11-10T10:12:04+00:00", level="ERROR", event="connect_failed", path="udp")
        self.window.logs.append(first)
        self.window.refresh_logs()
        self.window.log_table.selectRow(0)
        self.assertEqual(json.loads(self.window.log_detail.toPlainText()), first)
        self.window.logs.append(second)
        self.window.refresh_logs()
        self.assertEqual(json.loads(self.window.log_detail.toPlainText()), first)
        self.window.log_level.setCurrentIndex(2)
        self.assertEqual(self.window.log_table.rowCount(), 1)
        self.assertEqual(self.window.log_detail.toPlainText(), "")
        self.window.log_search.setText("tcp")
        self.assertEqual(self.window.log_table.rowCount(), 0)
        self.assertIn("Нет совпадений", self.window.log_empty.text())


if __name__ == "__main__":
    unittest.main()
