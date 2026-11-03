"""Terminal progress for installer commands; raw output stays in the private log."""

import contextlib
import os
import re
import shutil
import signal
import subprocess
import sys
import time

POLL = 1
PLAIN_INTERVAL = 5


def duration(seconds):
    seconds = max(0, int(seconds))
    return f"{seconds // 60:02d}:{seconds % 60:02d}"


def activity_message(line, kind):
    """Only recognized package metadata reaches the terminal, never raw log lines."""
    if kind == "apt":
        for prefix, message in (("Get:", "Загрузка из репозитория"), ("Hit:", "Репозиторий доступен"),
                                ("Ign:", "Повторный запрос к репозиторию"), ("Err:", "Ошибка обращения к репозиторию"),
                                ("Reading package lists", "Обработка списка пакетов"),
                                ("Building dependency tree", "Проверка системных зависимостей"),
                                ("Reading state information", "Проверка установленных пакетов"),
                                ("Fetched ", "Пакеты загружены")):
            if line.startswith(prefix):
                return message
        if any(text in line for text in ("Waiting for cache lock", "Could not get lock", "Unable to acquire")):
            return "Менеджер пакетов занят другим процессом"
        match = re.match(r"^(Unpacking|Setting up) ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?)\s", line)
        if match:
            return ("Распаковка: " if match[1] == "Unpacking" else "Настройка: ") + match[2]
    elif kind == "pip":
        match = re.match(r"^(Collecting|Downloading|Using cached) ([a-zA-Z0-9][a-zA-Z0-9_.+-]*)", line.strip())
        if match:
            return ("Подготовка: " if match[1] == "Collecting" else "Загрузка: ") + match[2][:100]
        if line.startswith("Installing collected packages"):
            return "Установка загруженных пакетов"
        if line.startswith("Successfully installed"):
            return "Пакеты установлены"
        if line.startswith("No broken requirements found"):
            return "Зависимости совместимы"
    return None


class Progress:
    def __init__(self, label, reader, activity, interactive):
        self.label, self.reader, self.activity = label, reader, activity
        self.interactive = interactive
        self.started = self.last_output = time.monotonic()
        self.last_print = self.started
        self.detail, self.partial = "Процесс запущен", ""
        print(f"  → {label}", flush=True)

    def update(self, *, final=None):
        now = time.monotonic()
        changed = False
        if self.reader:
            end = os.fstat(self.reader.fileno()).st_size
            if end - self.reader.tell() > 65536:
                self.reader.seek(end - 65536)
                self.partial = ""
            data = self.reader.read(65536)
            if data:
                self.last_output = now
                lines = re.split(r"[\r\n]", self.partial + data.decode("utf-8", errors="replace"))
                self.partial = lines.pop()[-1024:]
                for line in lines:
                    detail = activity_message(line, self.activity)
                    if detail and detail != self.detail:
                        self.detail, changed = detail, True
        if final is not None:
            if self.interactive:
                print("\r\033[2K", end="")
            status = "Готово" if final == 0 else f"Ошибка · код {final}"
            print(f"  {status} · {self.label} · {duration(now - self.started)}", flush=True)
        elif self.interactive or changed or now - self.last_print >= PLAIN_INTERVAL:
            quiet = now - self.last_output
            note = self.detail if quiet < 15 else f"Ожидание завершения; новых сообщений нет {duration(quiet)}"
            line = f"    {duration(now - self.started)} · {note}"
            if self.interactive:
                width = max(20, shutil.get_terminal_size((80, 24)).columns - 1)
                print("\r\033[2K" + line[:width], end="", flush=True)
            else:
                print(line, flush=True)
            self.last_print = now


def run(command, log, log_path, *, data, capture, env, label, activity, interactive):
    reader = None
    try:
        if activity is not None and not capture:
            fd = os.open(log_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            reader = os.fdopen(fd, "rb")
            source, destination = os.fstat(log.fileno()), os.fstat(reader.fileno())
            if (source.st_dev, source.st_ino) != (destination.st_dev, destination.st_ino):
                raise ValueError("Журнал установки изменён другим процессом")
            reader.seek(0, os.SEEK_END)
        progress = Progress(label, reader, activity, interactive)
        with subprocess.Popen(command, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE if capture else log, stderr=log, env=env,
                start_new_session=os.name == "posix") as process:
            try:
                while True:
                    try:
                        output, _ = process.communicate(input=data, timeout=POLL)
                        break
                    except subprocess.TimeoutExpired:
                        data = None  # communicate retains any remaining input after a timeout.
                        progress.update()
            except BaseException:
                with contextlib.suppress(ProcessLookupError, OSError):
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGTERM)
                    else:
                        process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                    process.communicate()
                raise
            progress.update(final=process.returncode)
            return subprocess.CompletedProcess(command, process.returncode, output, None)
    finally:
        if reader:
            reader.close()
