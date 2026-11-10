"""Native Qt client: real transport state, private profiles and readable event logs."""

import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import datetime
import json
import os
import pathlib
import queue
import signal
import sys

from PySide6.QtCore import QTimer, Qt, QPointF, QRectF, QSignalBlocker
from PySide6.QtGui import QColor, QFont, QFontDatabase, QIcon, QPainter, QPainterPath, QPen, QPalette
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QBoxLayout, QButtonGroup, QCheckBox,
    QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit,
    QPushButton, QScrollArea, QSpinBox, QStackedWidget, QTableWidget, QTableWidgetItem,
    QSplitter, QVBoxLayout, QWidget)

from desktop import VERSION
from desktop.engine import Engine, setup_logging
from desktop.profiles import Profiles, import_package, import_text, write_private
from desktop.vault import Vault, VaultError

ACCENT = "#65d6bf"
EVENT_NAMES = {
    "client_started": "Клиент запущен", "client_error": "Ошибка клиента",
    "connect_attempt": "Установка канала", "connect_failed": "Не удалось подключиться",
    "transport_attached": "Канал установлен", "transport_lost": "Канал прерван",
    "path_probe": "Проверка пути", "path_selected": "Выбран путь",
    "candidate_quarantined": "Путь отклонён проверкой безопасности",
    "session_metrics": "Показатели сессии", "session_closed": "Сессия завершена",
    "srtl_configured": "Настройка SRTL", "connection_rejected": "Соединение отклонено",
    "resume_rejected": "Восстановление отклонено", "client_stopped": "Клиент остановлен",
    "frame_replayed": "Повторная доставка", "connect_superseded": "Попытка заменена новой",
    "transport_handshake_started": "Начало TLS/QUIC", "transport_handshake_complete": "TLS установлен",
    "carrier_handshake_started": "Авторизация HTTPS", "carrier_handshake_complete": "HTTPS авторизован",
    "protocol_handshake_started": "Установка сессии протокола",
    "address_connected": "Адрес отвечает по протоколу", "secure_connection": "Защищённое соединение",
    "connect_success": "Сессия установлена", "stream_opened": "TCP-поток открыт",
    "stream_reset": "TCP-поток сброшен", "stream_closed": "TCP-поток закрыт",
}
ERRORS = {
    "security_verification_failed": "Не прошла проверка сертификата или ключа. Проверьте профиль и журнал",
    "session_expired": "Сессия завершилась. Подключитесь заново, чтобы открыть новый канал",
    "connection_timeout": "Не удалось установить защищённый канал за отведённое время. Проверьте адрес, порт и журнал",
    "port_unavailable": "Локальный порт занят или недоступен. Выберите другой порт",
    "connection_setup_failed": "Не удалось открыть канал. Проверьте сертификат, настройки и журнал",
    "internal_error": "Клиент остановил канал из-за внутренней ошибки. Сохраните журнал",
}


def mono_font():
    return QFont("Consolas" if os.name == "nt" else "DejaVu Sans Mono", 10)


def label(text="", role=None, mono=False):
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    if role:
        widget.setObjectName(role)
    if mono:
        widget.setFont(mono_font())
    return widget


def button(text, callback=None, role=None):
    widget = QPushButton(text)
    if role:
        widget.setObjectName(role)
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    if callback:
        widget.clicked.connect(callback)
    return widget


def panel():
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(24, 24, 24, 24)
    layout.setSpacing(16)
    return frame, layout


def human_bytes(number, rate=False):
    value = float(number)
    unit = "Б"
    for unit in ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ"):
        if value < 1024:
            break
        value /= 1024
    precision = 0 if unit == "Б" else 1
    return f"{value:.{precision}f} {unit}" + ("/с" if rate else "")


class Traffic(QWidget):
    def __init__(self):
        super().__init__()
        self.samples = deque(maxlen=61)
        self.setMinimumHeight(112)
        self.setAccessibleName("Трафик канала за последнюю минуту")
        self.setSizePolicy(self.sizePolicy().horizontalPolicy(), self.sizePolicy().verticalPolicy())

    def add(self, rx, tx):
        self.samples.append((rx, tx))
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        bounds = QRectF(0, 24, self.width(), self.height() - 48)
        painter.setPen(QPen(QColor("#303236"), 1))
        for fraction in (0, .5, 1):
            y = bounds.top() + bounds.height() * fraction
            painter.drawLine(QPointF(bounds.left(), y), QPointF(bounds.right(), y))
        peak = max((max(v) for v in self.samples), default=0)
        painter.setFont(mono_font())
        painter.setPen(QColor("#92989e"))
        painter.drawText(0, self.height() - 2, "−60 с")
        painter.drawText(self.width() - 56, self.height() - 2, "Сейчас")
        if not peak:
            painter.drawText(bounds, Qt.AlignmentFlag.AlignCenter, "Пока нет передачи данных")
            return
        painter.drawText(0, 14, human_bytes(peak, rate=True) + " · пик")
        peak *= 1.2
        for series, color in ((1, "#a1a7ad"), (0, ACCENT)):
            path = QPainterPath()
            count = len(self.samples)
            for index, sample in enumerate(self.samples):
                point = QPointF(bounds.left() + (60 - count + 1 + index) / 60 * bounds.width(),
                                bounds.bottom() - sample[series] / peak * bounds.height())
                path.moveTo(point) if index == 0 else path.lineTo(point)
            pen = QPen(QColor(color), 2)
            if series == 1:
                pen.setStyle(Qt.PenStyle.DashLine)
            painter.setPen(pen)
            painter.drawPath(path)


class PathRow(QWidget):
    def __init__(self, kind):
        super().__init__()
        self.kind = kind
        self.setObjectName("path")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)
        top = QHBoxLayout()
        top.setSpacing(12)
        self.name = label(kind.upper(), mono=True)
        self.name.setFixedWidth(48)
        self.line = QFrame()
        self.line.setFixedHeight(2)
        self.note = label("Не измерялся", "secondary")
        self.note.setWordWrap(True)
        top.addWidget(self.name)
        top.addWidget(self.line, 1)
        top.addWidget(label("TLS 1.3" if kind == "tcp" else "QUIC", "muted"))
        layout.addLayout(top)
        layout.addWidget(self.note)
        self.show_state({}, False)

    def show_state(self, state, active):
        color = ACCENT if active else "#e58c88" if state.get("quarantined") else "#44494f"
        self.line.setStyleSheet(f"background: {color}")
        self.name.setStyleSheet(f"color: {color if active else '#b1b7bd'}; background: transparent")
        rtt = state.get("rtt_ms")
        if state.get("quarantined"):
            text = "Проверка отклонена"
        elif active:
            text = "Активен · " + (f"{rtt:.1f} мс" if rtt is not None else "измеряем задержку")
        elif state.get("available"):
            text = "Доступен" + (f" · {rtt:.1f} мс" if rtt is not None else "")
        elif state.get("disabled"):
            text = "Выключен в настройках"
        else:
            text = "Нет ответа" if state.get("measured") else "Не измерялся"
        self.note.setText(text)
        self.setAccessibleName(f"{self.kind.upper()}: {text}")


class Window(QMainWindow):
    def __init__(self, data_dir=None):
        super().__init__()
        self.setWindowTitle("Myownvpn")
        available = QApplication.primaryScreen().availableGeometry()
        self.resize(min(1200, available.width() - 48), min(900, available.height() - 64))
        self.setMinimumSize(860, 600)
        self.store = Profiles(data_dir)
        self.vault = Vault(self.store.root)
        self.engine = Engine()
        setup_logging(self.store.root, self.engine.publish)
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="myownvpn-vault")
        self.pending = None
        self.session_keys = {}
        self.logs = deque(maxlen=2000)
        self.failed = False
        self.closing = False
        self.current_snapshot = {}
        self.updating = False
        try:
            self.profiles = self.store.load()
            load_error = None
        except (OSError, ValueError):
            self.profiles, load_error = [], "Список профилей повреждён. Импортируйте клиентский пакет заново"
        self._build()
        self._fill_profiles()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll)
        self.timer.start(100)
        if load_error:
            self.message.setText(load_error)

    @property
    def profile(self):
        row = self.profile_list.currentRow()
        return self.profiles[row] if 0 <= row < len(self.profiles) else None

    def _build(self):
        shell = QWidget()
        layout = QHBoxLayout(shell)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(240)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(20, 32, 20, 24)
        side.setSpacing(8)
        side.addWidget(label("Myownvpn", "brand"))
        side.addWidget(label("Управление каналом", "muted"))
        side.addSpacing(24)
        self.pages = QStackedWidget()
        group = QButtonGroup(self)
        for index, text in enumerate(("Подключение", "Журнал событий")):
            nav = button(text, role="nav")
            nav.setCheckable(True)
            nav.setChecked(index == 0)
            group.addButton(nav, index)
            side.addWidget(nav)
        group.idClicked.connect(self.pages.setCurrentIndex)
        self.pages.currentChanged.connect(lambda index: self.refresh_logs() if index == 1 else None)
        side.addSpacing(24)
        side.addWidget(label("Серверы", "secondary"))
        self.profiles_empty = label("Пока нет профилей\nДобавьте конфигурацию сервера", "muted")
        self.profiles_empty.setWordWrap(True)
        side.addWidget(self.profiles_empty)
        self.profile_list = QListWidget()
        self.profile_list.setAccessibleName("Профили серверов")
        self.profile_list.currentRowChanged.connect(self.select_profile)
        self.profile_list.itemChanged.connect(self.rename_profile)
        side.addWidget(self.profile_list, 1)
        self.import_button = button("Импортировать пакет", self.import_dialog, "quiet")
        self.import_button.setToolTip("Клиентский tar.gz, созданный командой myownvpn export на сервере")
        self.paste_button = button("Вставить конфигурацию", self.paste_dialog, "add")
        side.addWidget(self.paste_button)
        side.addWidget(self.import_button)
        side.addSpacing(12)
        side.addWidget(label(f"Клиент {VERSION} · протокол v5", "muted"))
        side.addWidget(label("TLS 1.3 · IP без SNI", "muted"))
        layout.addWidget(sidebar)
        layout.addWidget(self.pages, 1)
        self._connection_page()
        self._logs_page()
        self.setCentralWidget(shell)

    def _connection_page(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        body = QVBoxLayout(content)
        body.setContentsMargins(32, 32, 32, 24)
        body.setSpacing(16)
        header = QHBoxLayout()
        header.addWidget(label("Подключение", "title"), 1)
        header.addWidget(label("Протокол v5", "muted", mono=True))
        body.addLayout(header)
        self.context = label("Добавьте сервер, чтобы открыть канал", "secondary", mono=True)
        self.context.setWordWrap(True)
        body.addWidget(self.context)
        connection, box = panel()
        connection.setObjectName("connection")
        box.addWidget(label("Состояние канала", "muted"))
        top = QHBoxLayout()
        names = QVBoxLayout()
        names.setSpacing(8)
        self.status = label("Отключено", "status")
        self.status.setWordWrap(True)
        self.description = label("Вставьте конфигурацию или импортируйте пакет", "secondary")
        self.description.setWordWrap(True)
        names.addWidget(self.status)
        names.addWidget(self.description)
        top.addLayout(names, 1)
        self.connect_button = button("Подключить", self.toggle_connection, "primary")
        self.connect_button.setMinimumWidth(160)
        top.addWidget(self.connect_button, 0, Qt.AlignmentFlag.AlignVCenter)
        box.addLayout(top)
        paths = QHBoxLayout()
        paths.setSpacing(12)
        self.path_rows = {kind: PathRow(kind) for kind in ("tcp", "udp")}
        for row in self.path_rows.values():
            paths.addWidget(row, 1)
        box.addLayout(paths)
        body.addWidget(connection)
        traffic, box = panel()
        top = QHBoxLayout()
        top.addWidget(label("Трафик сессии", "section"), 1)
        top.addWidget(label("60 с", "muted"))
        box.addLayout(top)
        figures = QHBoxLayout()
        self.figures = {}
        for key, title in (("rx", "Получено"), ("tx", "Отправлено"), ("rtt", "Задержка")):
            column = QVBoxLayout()
            column.setSpacing(4)
            column.addWidget(label(title, "secondary"))
            value = label("0 Б" if key != "rtt" else "—", "number", mono=True)
            value.setWordWrap(True)
            column.addWidget(value)
            self.figures[key] = value
            figures.addLayout(column, 1)
        box.addLayout(figures)
        legend = QHBoxLayout()
        received = label("Приём ━", "muted")
        received.setStyleSheet("color: #65d6bf; background: transparent")
        legend.addWidget(received)
        legend.addWidget(label("Передача ┄", "muted"))
        legend.addStretch()
        box.addLayout(legend)
        self.traffic = Traffic()
        box.addWidget(self.traffic)
        self.rates = label("Приём 0 Б/с    Передача 0 Б/с", "muted", mono=True)
        box.addWidget(self.rates)
        settings, box = panel()
        box.addWidget(label("Параметры канала", "section"))
        grid = QGridLayout()
        grid.setHorizontalSpacing(20)
        grid.setVerticalSpacing(8)
        self.transport = QComboBox()
        self.transport.addItems(("Автоматически", "Только TCP", "Только UDP"))
        transport_label = label("Выбор транспорта", "secondary")
        transport_label.setBuddy(self.transport)
        self.transport.setAccessibleName("Выбор транспорта")
        self.transport.currentIndexChanged.connect(self.settings_changed)
        self.local_port = QSpinBox()
        self.local_port.setRange(1024, 65535)
        self.local_port.setValue(1080)
        port_label = label("Локальный порт", "secondary")
        port_label.setBuddy(self.local_port)
        self.local_port.setAccessibleName("Локальный TCP-порт")
        self.local_port.valueChanged.connect(self.settings_changed)
        grid.addWidget(transport_label, 0, 0)
        grid.addWidget(port_label, 0, 1)
        grid.addWidget(self.transport, 1, 0)
        grid.addWidget(self.local_port, 1, 1)
        self.srtl = QCheckBox("SRTL · менять размеры пакетов")
        self.srtl.setToolTip("Объединение DATA, ограниченное дополнение размеров и короткий зашифрованный хвост. Настройка сервера независима")
        self.srtl.toggled.connect(self.srtl_changed)
        box.addLayout(grid)
        box.addWidget(self.srtl)
        srtl_hint = label("Дополнительный трафик · можно переключать при подключении", "muted")
        srtl_hint.setWordWrap(True)
        box.addWidget(srtl_hint)
        self.local_hint = label("TCP-приложение подключается к 127.0.0.1:1080", "secondary")
        self.local_hint.setWordWrap(True)
        box.addWidget(self.local_hint)
        self.certificate = label("Сертификат проверяется при каждом подключении", "muted", mono=True)
        self.certificate.setWordWrap(True)
        self.certificate.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        box.addWidget(self.certificate)
        self.lower = QBoxLayout(QBoxLayout.Direction.LeftToRight)
        self.lower.setSpacing(16)
        self.lower.addWidget(traffic, 3)
        self.lower.addWidget(settings, 2)
        self.lower_widgets = (traffic, settings)
        body.addLayout(self.lower)
        self.message = label("Работает с TCP-приложениями через локальный порт", "secondary")
        self.message.setWordWrap(True)
        body.addWidget(self.message)
        body.addStretch()
        scroll.setWidget(content)
        self.pages.addWidget(scroll)

    def _logs_page(self):
        page = QWidget()
        body = QVBoxLayout(page)
        body.setContentsMargins(32, 32, 32, 24)
        body.setSpacing(16)
        body.addWidget(label("Журнал событий", "title"))
        body.addWidget(label("Аутентификация, выбор пути, переподключения и ошибки", "secondary"))
        tools = QHBoxLayout()
        self.log_level = QComboBox()
        self.log_level.addItems(("Все уровни", "Предупреждения и ошибки", "Только ошибки"))
        self.log_level.setAccessibleName("Фильтр уровня журнала")
        self.log_level.currentIndexChanged.connect(self.refresh_logs)
        tools.addWidget(self.log_level)
        self.log_search = QLineEdit()
        self.log_search.setPlaceholderText("Название, транспорт или код ошибки")
        self.log_search.setAccessibleName("Поиск по журналу")
        self.log_search.textChanged.connect(self.refresh_logs)
        tools.addWidget(button("Сохранить журнал", self.export_logs))
        body.addLayout(tools)
        search = QHBoxLayout()
        search_label = label("Поиск", "secondary")
        search_label.setBuddy(self.log_search)
        search.addWidget(search_label)
        search.addWidget(self.log_search, 1)
        body.addLayout(search)
        self.log_empty = label("События появятся после начала подключения", "secondary")
        body.addWidget(self.log_empty)
        split = QSplitter(Qt.Orientation.Vertical)
        split.setChildrenCollapsible(False)
        split.setHandleWidth(8)
        split.setAccessibleName("Размер таблицы и подробностей события")
        self.log_table = QTableWidget(0, 4)
        self.log_table.setHorizontalHeaderLabels(("Время", "Уровень", "Событие", "Данные"))
        self.log_table.setAccessibleName("События соединения")
        self.log_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.log_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.log_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.log_table.setAlternatingRowColors(True)
        self.log_table.setWordWrap(False)
        self.log_table.verticalHeader().hide()
        self.log_table.verticalHeader().setDefaultSectionSize(36)
        header = self.log_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.log_table.itemSelectionChanged.connect(self.select_log)
        self.log_table.setMinimumHeight(120)
        split.addWidget(self.log_table)
        detail = QWidget()
        detail.setMinimumHeight(120)
        detail_box = QVBoxLayout(detail)
        detail_box.setContentsMargins(0, 8, 0, 0)
        detail_box.setSpacing(8)
        detail_box.addWidget(label("Данные события", "section"))
        self.log_detail = QPlainTextEdit()
        self.log_detail.setReadOnly(True)
        self.log_detail.setPlaceholderText("Выберите строку в журнале, чтобы прочитать все поля")
        self.log_detail.setFont(mono_font())
        self.log_detail.setAccessibleName("Полные данные выбранного события")
        detail_box.addWidget(self.log_detail)
        split.addWidget(detail)
        split.setSizes([440, 160])
        body.addWidget(split, 1)
        bottom = QHBoxLayout()
        self.follow = QCheckBox("Следить за новыми событиями")
        self.follow.setChecked(True)
        bottom.addWidget(self.follow)
        bottom.addStretch()
        self.log_count = label("0 событий", "muted")
        bottom.addWidget(self.log_count)
        body.addLayout(bottom)
        body.addWidget(label("На диске: client.jsonl · ротация 5 МиБ × 4 файла", "muted"))
        self.pages.addWidget(page)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "lower"):
            # Account for font metrics as well as window width (including scaled text).
            required = sum(widget.minimumSizeHint().width() for widget in self.lower_widgets) + 328
            self.lower.setDirection(QBoxLayout.Direction.LeftToRight if self.width() >= max(1152, required) else
                                    QBoxLayout.Direction.TopToBottom)

    def _fill_profiles(self, selected=None):
        self.updating = True
        self.profile_list.clear()
        for profile in self.profiles:
            item = QListWidgetItem(profile.name)
            item.setToolTip(profile.address + "\nДвойной щелчок — переименовать")
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsEditable)
            self.profile_list.addItem(item)
        row = next((i for i, p in enumerate(self.profiles) if p.id == selected), 0)
        self.profile_list.setCurrentRow(row if self.profiles else -1)
        self.profiles_empty.setVisible(not self.profiles)
        self.updating = False
        self.select_profile()

    def select_profile(self, *_args):
        if self.updating:
            return
        self.updating = True
        profile = self.profile
        self.context.setText(profile.address if profile else "Добавьте сервер, чтобы открыть канал")
        self.srtl.setChecked(profile.srtl if profile else False)
        self.local_port.setValue(profile.local_port if profile else 1080)
        self.transport.setCurrentIndex(("auto", "tcp", "udp").index(profile.transport) if profile else 0)
        fingerprint = " ".join(profile.ca_sha256[i:i + 16] for i in range(0, 64, 16)) if profile else ""
        self.certificate.setText("CA SHA-256\n" + fingerprint if profile else "Сертификат проверяется при каждом подключении")
        self.certificate.setToolTip("CA SHA-256: " + profile.ca_sha256 if profile else "")
        self.description.setText("Готов к подключению" if profile else "Вставьте конфигурацию или импортируйте пакет")
        self.updating = False
        self.local_hint.setText(f"TCP-приложение подключается к 127.0.0.1:{self.local_port.value()}")
        self.update_controls()

    def rename_profile(self, item):
        if self.updating or self.engine.running:
            return
        row = self.profile_list.row(item)
        name = item.text().strip()[:80]
        if name and row >= 0:
            self.profiles[row] = replace(self.profiles[row], name=name)
            self.persist()
        elif row >= 0:
            self.updating = True
            item.setText(self.profiles[row].name)
            self.updating = False

    def persist(self):
        try:
            self.store.save(self.profiles)
        except (OSError, ValueError):
            self.message.setText("Не удалось сохранить настройки. Проверьте доступ к каталогу приложения")

    def settings_changed(self, *_args):
        if self.updating or not self.profile:
            return
        row = self.profile_list.currentRow()
        self.profiles[row] = replace(self.profile, local_port=self.local_port.value(),
                                     transport=("auto", "tcp", "udp")[self.transport.currentIndex()])
        self.local_hint.setText(f"TCP-приложение подключается к 127.0.0.1:{self.local_port.value()}")
        self.persist()

    def srtl_changed(self, enabled):
        if self.updating or not self.profile:
            return
        row = self.profile_list.currentRow()
        self.profiles[row] = replace(self.profile, srtl=enabled)
        self.engine.set_srtl(enabled)
        self.persist()

    def import_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Импорт клиентского пакета", "", "Пакет Myownvpn (*.tar.gz)")
        if path:
            self.begin_import(path)

    def paste_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Добавить подключение")
        dialog.resize(620, 340)
        layout = QVBoxLayout(dialog)
        label = QLabel("Вставьте конфигурацию myownvpn://, созданную на сервере")
        layout.addWidget(label)
        editor = QPlainTextEdit()
        editor.setAccessibleName("Конфигурация подключения")
        editor.setMaximumBlockCount(64)
        label.setBuddy(editor)
        layout.addWidget(editor)
        hint = QLabel("Конфигурация содержит секретный ключ. Передавайте её только доверенному человеку.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Отмена")
        buttons.addButton("Добавить", QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        editor.setFocus()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            text = editor.toPlainText()
            editor.clear()
            self.begin_import(text, pasted=True)
        editor.clear()

    def begin_import(self, path, *, pasted=False):
        if self.pending or self.engine.running:
            return
        def work():
            imported = import_text(path) if pasted else import_package(path)
            if len(self.profiles) >= 32 and all(p.id != imported.profile.id for p in self.profiles):
                raise ValueError("Можно сохранить не более 32 профилей")
            self.store.install_ca(imported)
            saved = True
            try:
                self.vault.save(imported.profile.id, imported.key)
            except VaultError:
                saved = False
            return imported, saved
        self.pending = ("import", self.pool.submit(work))
        self.message.setText("Чтение пакета и сохранение ключа в системном хранилище")
        self.update_controls()

    def toggle_connection(self):
        if self.engine.running:
            self.engine.stop()
            self.status.setText("Отключение")
            self.connect_button.setEnabled(False)
            return
        profile = self.profile
        if not profile or self.pending:
            return
        self.failed = False
        def load():
            key = self.session_keys.get(profile.id) or self.vault.load(profile.id)
            return profile, key, self.store.ca_path(profile)
        self.pending = ("connect", self.pool.submit(load))
        self.status.setText("Подключение")
        self.description.setText("Доступ к системному хранилищу ключей")
        self.message.setText("Устанавливаем защищённый канал и проверяем сервер")
        self.update_controls()

    def update_controls(self):
        busy = self.engine.running or self.pending is not None
        self.profile_list.setEnabled(not busy)
        self.import_button.setEnabled(not busy)
        self.paste_button.setEnabled(not busy)
        self.local_port.setEnabled(not busy and self.profile is not None)
        self.transport.setEnabled(not busy and self.profile is not None)
        self.srtl.setEnabled(self.profile is not None and self.pending is None)
        self.connect_button.setEnabled(self.profile is not None and self.pending is None and not self.engine.stopping)
        self.connect_button.setText("Отключить" if self.engine.running else "Подключить")

    def poll(self):
        if self.pending and self.pending[1].done():
            kind, future = self.pending
            self.pending = None
            try:
                result = future.result()
                if kind == "import":
                    imported, saved = result
                    self.session_keys[imported.profile.id] = imported.key
                    existing = next((i for i, p in enumerate(self.profiles) if p.id == imported.profile.id), None)
                    if existing is None:
                        self.profiles.append(imported.profile)
                    else:
                        self.profiles[existing] = replace(imported.profile, name=self.profiles[existing].name)
                    self.persist()
                    self._fill_profiles(imported.profile.id)
                    self.message.setText("Профиль добавлен · ключ защищён системным хранилищем" if saved else
                        "Профиль добавлен. Ключ доступен до закрытия клиента: разблокируйте системное хранилище для постоянного сохранения")
                elif not self.closing:
                    self.traffic.samples.clear()
                    self.engine.start(*result)
            except (OSError, ValueError, VaultError) as error:
                self.message.setText(str(error) if isinstance(error, (ValueError, VaultError)) else "Не удалось прочитать файл. Проверьте доступ и импортируйте пакет заново")
                self.status.setText("Отключено")
            self.update_controls()
        new_logs = False
        for _ in range(256):
            try:
                kind, data = self.engine.events.get_nowait()
            except queue.Empty:
                break
            if kind == "log":
                self.logs.append(data)
                new_logs = True
            elif kind == "state":
                self.show_snapshot(data)
            elif kind == "error":
                self.failed = True
                self.status.setText("Соединение остановлено")
                self.status.setStyleSheet("color: #e58c88; background: transparent")
                self.description.setText("Канал закрыт")
                self.message.setText(ERRORS.get(data["reason"], ERRORS["internal_error"]))
            elif kind == "stopped":
                self.engine.stopping = False
                if not self.failed:
                    self.status.setText("Отключено")
                    self.status.setStyleSheet("color: #e9eeec; background: transparent")
                    self.description.setText("Можно подключиться снова")
                for row in self.path_rows.values():
                    row.show_state({}, False)
                self.figures["rtt"].setText("—")
                self.rates.setText("Приём 0 Б/с    Передача 0 Б/с")
                self.update_controls()
        if new_logs and self.pages.currentIndex() == 1:
            self.refresh_logs()
        self.update_controls()
        if self.closing and not self.engine.running and self.pending is None:
            self.pool.shutdown(wait=False, cancel_futures=True)
            self.closing = False
            self.close()

    def show_snapshot(self, data):
        self.current_snapshot = data
        state = data["status"]
        self.status.setText({"connecting": "Подключение", "connected": "Канал подключён", "reconnecting": "Переподключение"}[state])
        self.status.setStyleSheet(f"color: {ACCENT if state == 'connected' else '#e9eeec'}; background: transparent")
        if state == "connected":
            self.description.setText(f"{data.get('path', '').upper()} · сертификат проверен · TLS 1.3")
            self.message.setText(f"127.0.0.1:{self.local_port.value()} · активных потоков: {data.get('streams', 0)}")
        else:
            self.description.setText("Сохраняем сессию и ищем рабочий путь" if state == "reconnecting" else "Устанавливаем защищённый канал и проверяем сервер")
        for kind, row in self.path_rows.items():
            stat = data.get("paths", {}).get(kind, {"disabled": True})
            row.show_state(stat, data.get("path") == kind)
        for key in ("rx", "tx"):
            self.figures[key].setText(human_bytes(data.get(key + "_bytes", 0)))
        active = data.get("paths", {}).get(data.get("path"), {})
        rtt = active.get("rtt_ms")
        self.figures["rtt"].setText(f"{rtt:.1f} мс" if rtt is not None else "—")
        if "rx_rate" in data:
            self.traffic.add(data["rx_rate"], data["tx_rate"])
            self.rates.setText(f"Приём {human_bytes(data['rx_rate'], True)}    Передача {human_bytes(data['tx_rate'], True)}")
        self.update_controls()

    def refresh_logs(self, *_args):
        search = self.log_search.text().casefold()
        allowed = (None, {"WARNING", "ERROR", "CRITICAL"}, {"ERROR", "CRITICAL"})[self.log_level.currentIndex()]
        rows = [record for record in self.logs if (allowed is None or record["level"] in allowed) and
                (not search or search in (EVENT_NAMES.get(record["event"], record["event"]) + json.dumps(record, ensure_ascii=False)).casefold())]
        current = self.log_table.item(self.log_table.currentRow(), 0)
        selected = current.data(Qt.ItemDataRole.UserRole) if current else None
        blocker = QSignalBlocker(self.log_table)
        self.log_table.setRowCount(len(rows))
        for index, record in enumerate(rows):
            try:
                stamp = datetime.datetime.fromisoformat(record["time"]).astimezone().strftime("%H:%M:%S")
            except ValueError:
                stamp = "—"
            details = {k: v for k, v in record.items() if k not in ("time", "level", "event")}
            values = (stamp, record["level"], EVENT_NAMES.get(record["event"], record["event"]), json.dumps(details, ensure_ascii=False, separators=(",", ":")))
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                item.setData(Qt.ItemDataRole.UserRole, record)
                if column in (0, 1):
                    item.setFont(mono_font())
                if record["level"] in ("ERROR", "CRITICAL"):
                    item.setForeground(QColor("#e58c88"))
                self.log_table.setItem(index, column, item)
        selected_row = next((i for i, record in enumerate(rows) if record == selected), None)
        self.log_table.clearSelection()
        if selected_row is not None:
            self.log_table.selectRow(selected_row)
        else:
            self.log_table.setCurrentCell(-1, -1)
        blocker.unblock()
        self.select_log()
        self.log_count.setText(f"Показано {len(rows)} / {len(self.logs)}")
        self.log_empty.setVisible(not rows)
        self.log_empty.setText("Нет совпадений · измените уровень или строку поиска" if self.logs else
                               "События появятся после начала подключения")
        if self.follow.isChecked():
            self.log_table.scrollToBottom()

    def select_log(self):
        row = self.log_table.currentRow()
        item = self.log_table.item(row, 0)
        self.log_detail.setPlainText(json.dumps(item.data(Qt.ItemDataRole.UserRole), ensure_ascii=False, indent=2) if item else "")

    def export_logs(self):
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить журнал", "myownvpn-client.jsonl", "Журнал JSONL (*.jsonl)")
        if path:
            try:
                data = "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in self.logs)
                write_private(path, data.encode())
            except (OSError, ValueError):
                QMessageBox.warning(self, "Журнал не сохранён", "Выберите доступный для записи каталог")

    def closeEvent(self, event):
        if self.engine.running or self.pending:
            self.closing = True
            self.engine.stop()
            self.status.setText("Завершение соединения")
            self.setEnabled(False)
            event.ignore()
        else:
            self.timer.stop()
            self.session_keys.clear()
            self.pool.shutdown(wait=False, cancel_futures=True)
            event.accept()


def configure_application(app):
    app.setApplicationName("Myownvpn")
    app.setOrganizationName("Myownvpn")
    app.setApplicationVersion(VERSION)
    app.setDesktopFileName("org.myownvpn.Client")
    app.setWindowIcon(QIcon(str(pathlib.Path(__file__).with_name("myownvpn.svg"))))
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI" if os.name == "nt" else "Noto Sans", 10))
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#151719"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#e9eeec"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#1c1f22"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#e9eeec"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#292e32"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#e9eeec"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#354742"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#e9eeec"))
    app.setPalette(palette)
    app.setStyleSheet(pathlib.Path(__file__).with_name("theme.qss").read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Myownvpn desktop client")
    parser.add_argument("--import-package", type=pathlib.Path)
    parser.add_argument("--data-dir", type=pathlib.Path, help="separate profile directory")
    parser.add_argument("--snapshot", type=pathlib.Path, help="render an offline UI screenshot and exit")
    parser.add_argument("--connect", action="store_true", help="connect the selected saved profile on launch")
    args = parser.parse_args()
    if args.connect and args.import_package:
        parser.error("import a package first, then use --connect with the saved profile")
    os.umask(0o077)
    if os.name == "posix":
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    app = QApplication(sys.argv[:1])
    configure_application(app)
    try:
        window = Window(args.data_dir)
    except (OSError, ValueError):
        QMessageBox.critical(None, "Не удалось запустить клиент", "Проверьте доступ к каталогу профилей Myownvpn")
        return 1
    window.show()
    if args.import_package:
        window.begin_import(args.import_package)
    elif args.connect:
        QTimer.singleShot(0, window.toggle_connection)
    signal.signal(signal.SIGINT, lambda *_: window.close())
    if args.snapshot:
        def snapshot():
            args.snapshot.parent.mkdir(parents=True, exist_ok=True)
            window.grab().save(str(args.snapshot))
            window.close()
        QTimer.singleShot(500, snapshot)
    return app.exec()
