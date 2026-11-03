"""Debian 13 terminal installer and local server management. Standard library only."""

import argparse
import datetime
import getpass
import hashlib
import io
import json
import os
import pathlib
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from server.config import APP_FILES, SERVER_FILES, BASE, COMMAND, ETC, MARKER, PROTOCOL, UNIT, address, load, unit_text, validate
from server import clients
from client_config import encode

LOG = pathlib.Path("/var/log/myownvpn-install.log")
STATE_DIR = pathlib.Path("/var/lib/myownvpn")
LOG_DIR = pathlib.Path("/var/log/myownvpn")
COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"


def paint(text, code):
    return f"\033[{code}m{text}\033[0m" if COLOR else text


def banner(title="Сервер для Debian 13"):
    print("\n" + paint("MYOWNVPN", "1;36") + "  /  " + title)
    print(paint(f"IP без SNI · TLS 1.3 / QUIC · протокол v{PROTOCOL}", "2"))
    print(paint("─" * min(64, shutil.get_terminal_size((64, 24)).columns - 1), "2"))


def row(label, value):
    width = max(20, shutil.get_terminal_size((80, 24)).columns - 24)
    lines = textwrap.wrap(str(value), width=width) or [""]
    print(f"  {label:<20} {lines[0]}")
    for line in lines[1:]:
        print(" " * 23 + line)


def step(number, text):
    print(f"\n{paint('[' + number + ']', '36')} {text}", flush=True)


def ask(label, default=None):
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"  {label}{suffix}: ").strip()
    return value or default


def yes(label, default=False):
    while True:
        value = ask(label + (" (Y/n)" if default else " (y/N)"), "y" if default else "n").lower()
        if value in ("y", "yes", "д", "да"):
            return True
        if value in ("n", "no", "н", "нет"):
            return False
        print("  Введите y или n.")


def host_check(require_manager=True):
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise ValueError("Запустите через sudo на Debian 13.")
    release = dict(line.split("=", 1) for line in pathlib.Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if release.get("ID", "").strip('"') != "debian" or release.get("VERSION_ID", "").strip('"').split(".")[0] != "13":
        raise ValueError("Поддерживается только Debian 13. Система не изменена.")
    if require_manager and pathlib.Path("/proc/1/comm").read_text().strip() != "systemd":
        raise ValueError("Для запуска нужен systemd. Для сборки образа используйте --no-start.")
    for path in (BASE, BASE / "releases", ETC, COMMAND, UNIT):
        if path.is_symlink():
            raise ValueError(f"Путь {path} не должен быть символической ссылкой.")
        if path.exists() and (path.stat().st_uid != 0 or path.stat().st_mode & 0o022):
            raise ValueError(f"Путь {path} должен принадлежать root и быть закрыт для записи другим пользователям.")


def atomic_write(path, data, mode=0o600, *, group=None):
    path = pathlib.Path(path)
    if path.is_symlink():
        raise ValueError(f"Отказ от записи через символическую ссылку: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp-" + secrets.token_hex(6))
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as output:
            if os.name == "posix":
                if group is not None:
                    os.fchown(output.fileno(), 0, group)
                os.fchmod(output.fileno(), mode)
            else:
                temp.chmod(mode)
            output.write(data.encode() if isinstance(data, str) else data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def run(command, *, data=None, capture=False, check=True):
    LOG.parent.mkdir(parents=True, exist_ok=True)
    if LOG.is_symlink():
        raise ValueError("Файл журнала установки не должен быть ссылкой.")
    fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "ab") as log:
        if os.name == "posix":
            if os.fstat(log.fileno()).st_uid != 0:
                raise ValueError("Журнал установки должен принадлежать root.")
            os.fchmod(log.fileno(), 0o600)
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", PIP_CONFIG_FILE=os.devnull)
        env.pop("MYVPN_KEY", None)
        result = subprocess.run([str(v) for v in command], input=data,
            stdout=subprocess.PIPE if capture else log, stderr=log,
            env=env)
    if check and result.returncode:
        raise RuntimeError(f"Команда {pathlib.Path(str(command[0])).name} завершилась с ошибкой. Журнал: {LOG}")
    return result


def verify_package(source):
    source = pathlib.Path(source).resolve()
    manifest = json.loads((source / "MANIFEST.json").read_text(encoding="utf-8"))
    expected = set(APP_FILES + SERVER_FILES + ("install.sh",))
    if (not isinstance(manifest, dict) or manifest.get("format") != 1 or
            manifest.get("protocol") != PROTOCOL or not isinstance(manifest.get("sha256"), dict) or
            set(manifest["sha256"]) != expected):
        raise ValueError("Неполный пакет сервера. Соберите архив через server/build.py.")
    for name, digest in manifest["sha256"].items():
        path = source / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"Контрольная сумма не совпала: {name}. Получите пакет заново.")
    return source


def plan(args):
    interactive = not args.yes
    ips = args.public_ip
    if not ips:
        if not interactive:
            raise ValueError("Укажите --public-ip с IP сервера.")
        ips = (ask("Публичный IP VPS (несколько — через запятую)") or "").split(",")
    ips = [ip.strip() for ip in ips]
    port = args.port if args.port is not None else (int(ask("Порт TCP и UDP", "443")) if interactive else 443)
    target = args.target or (ask("TCP-назначение, IP:порт", "127.0.0.1:9000") if interactive else "127.0.0.1:9000")
    host, target_port = target.rsplit(":", 1)
    cfg = validate(dict(schema=1, protocol=PROTOCOL, public_ips=ips,
        listen="::" if ":" in ips[0] else "0.0.0.0", port=port,
        target=[host.strip("[]"), int(target_port)], transport=args.transport,
        grace=30, srtl=args.srtl if args.srtl is not None else
        (yes("Включить SRTL на отправку сервера?") if interactive else False)))
    if not args.generate_identity and not all((args.ca, args.cert, args.cert_key)):
        if not interactive:
            raise ValueError("Передайте --ca/--cert/--cert-key или --generate-identity.")
        print("\n  Сертификат только с IP SAN:")
        print("  1  Импортировать готовый (CA private key остаётся вне VPS)")
        print("  2  Создать здесь; резервный ключ CA зашифровать паролем")
        if ask("Выберите вариант", "1") == "2":
            args.generate_identity = True
        else:
            args.ca = ask("Путь к ca-cert.pem")
            args.cert = ask("Путь к server-cert.pem")
            args.cert_key = ask("Путь к server-key.pem")
    return cfg


def review(cfg):
    banner("Проверка перед установкой")
    row("Адрес клиента", address(cfg["public_ips"][0], cfg["port"]))
    row("Прослушивание", address(cfg["listen"], cfg["port"]))
    row("TCP-назначение", address(*cfg["target"]))
    row("Транспорт", "TCP + UDP" if cfg["transport"] == "auto" else "TCP")
    row("SRTL сервера", "включён" if cfg["srtl"] else "выключен")
    row("Служба", "myownvpn.service · пользователь myownvpn")
    row("Конфигурация", str(ETC / "server.json"))
    print("\n  Это TCP-перенаправитель к указанному назначению.")
    print("  Firewall, SSH, NAT и системный Python не перенастраиваются.")


def port_check(cfg):
    family = socket.AF_INET6 if ":" in cfg["listen"] else socket.AF_INET
    kinds = (socket.SOCK_STREAM, socket.SOCK_DGRAM) if cfg["transport"] == "auto" else (socket.SOCK_STREAM,)
    for kind in kinds:
        with socket.socket(family, kind) as sock:
            sock.bind((cfg["listen"], cfg["port"]))


def make_release(source):
    step("1/6", "Проверка пакета и установка штатных зависимостей Debian")
    source = verify_package(source)
    run(("apt-get", "update"))
    run(("apt-get", "install", "--no-install-recommends", "-y", "python3", "python3-venv", "ca-certificates", "systemd"))
    version = json.loads(run(("/usr/bin/python3", "-c", "import sys,json;print(json.dumps(list(sys.version_info[:2])))"), capture=True).stdout)
    if version != [3, 13]:
        raise ValueError("Ожидался штатный Python 3.13 из Debian 13.")
    BASE.mkdir(mode=0o755, exist_ok=True)
    BASE.chmod(0o755)
    (BASE / "releases").mkdir(mode=0o755, exist_ok=True)
    (BASE / "releases").chmod(0o755)
    release = BASE / "releases" / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4))
    release.mkdir(mode=0o755)
    for name in APP_FILES + SERVER_FILES + ("install.sh", "MANIFEST.json"):
        dest = release / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, dest)
        dest.chmod(0o644)
    step("2/6", "Изолированное окружение и проверка SHA-256 Python-пакетов")
    run(("/usr/bin/python3", "-m", "venv", release / "venv"))
    python = release / "venv/bin/python"
    run((python, "-m", "pip", "--isolated", "install", "--disable-pip-version-check", "--no-input", "--no-cache-dir",
         "--index-url", "https://pypi.org/simple", "--require-hashes", "--only-binary=:all:", "--no-deps", "-r", release / "server/requirements.lock"))
    run((python, "-m", "pip", "check"))
    # Bootstrap uses umask 077. Only immutable program files become readable;
    # credentials and CA material are outside this tree. Never follow venv links.
    for path in [release, *release.rglob("*")]:
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
    return release


def private_file(path):
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file() or os.name == "posix" and path.stat().st_mode & 0o077:
        raise ValueError("Файл с секретом должен существовать и иметь права 600 или 400.")
    return path.read_bytes()


def credentials(release, cfg, args):
    step("3/6", "Подготовка сертификата и ключа доступа")
    python, helper = release / "venv/bin/python", release / "server/identity.py"
    with tempfile.TemporaryDirectory(prefix="myownvpn-install-", dir="/run") as tmp:
        temp = pathlib.Path(tmp)
        if args.generate_identity:
            if args.ca_password_file:
                password = private_file(args.ca_password_file).rstrip(b"\r\n")
            elif args.yes:
                raise ValueError("Для генерации укажите --ca-password-file (права 600, пароль от 12 символов).")
            else:
                first = getpass.getpass("  Пароль резервного ключа CA (от 12 символов): ")
                if first != getpass.getpass("  Повторите пароль: "):
                    raise ValueError("Пароли не совпадают. Установка службы не выполнена.")
                password = first.encode("utf-8")
            run((python, "-I", helper, "create", "--out", temp, *[v for ip in cfg["public_ips"] for v in ("--ip", ip)]), data=password)
        else:
            for name, path in (("ca-cert.pem", args.ca), ("server-cert.pem", args.cert), ("server-key.pem", args.cert_key)):
                value = pathlib.Path(path).read_bytes()
                if len(value) > 1024 * 1024:
                    raise ValueError("Файл сертификата/ключа превышает 1 МиБ.")
                atomic_write(temp / name, value)
        info = json.loads(run((python, "-I", helper, "validate", "--ca", temp / "ca-cert.pem", "--cert", temp / "server-cert.pem",
            "--key", temp / "server-key.pem", *[v for ip in cfg["public_ips"] for v in ("--ip", ip)]), capture=True).stdout)
        key = private_file(args.key_file).decode("ascii").strip() if args.key_file else secrets.token_hex(32)
        if len(key) != 64 or any(c not in "0123456789abcdefABCDEF" for c in key):
            raise ValueError("В файле ключа должны быть 64 hex-символа.")
        if ETC.exists():
            raise ValueError("Каталог /etc/myownvpn уже существует. Ключи не перезаписаны.")
        staged = ETC.with_name(".myownvpn-setup-" + secrets.token_hex(6))
        staged.mkdir(mode=0o700)
        try:
            (staged / "credentials").mkdir(mode=0o700)
            for name in ("server-cert.pem", "server-key.pem"):
                atomic_write(staged / "credentials" / name, (temp / name).read_bytes())
            atomic_write(staged / "credentials/access-key", key + "\n")
            atomic_write(staged / "credentials/health-key", secrets.token_hex(32) + "\n")
            first = clients.record("Первый клиент", key)
            atomic_write(staged / "clients.json", json.dumps(dict(clients.empty(), clients=[first])) + "\n")
            atomic_write(staged / "credentials/clients" / first["id"], key + "\n")
            atomic_write(staged / "credentials/clients-enabled", "1\n")
            atomic_write(staged / "ca-cert.pem", (temp / "ca-cert.pem").read_bytes(), 0o644)
            atomic_write(staged / "identity-info.json", json.dumps(info, indent=2) + "\n", 0o644)
            atomic_write(staged / "server.json", json.dumps(cfg, indent=2) + "\n", 0o644)
            if args.generate_identity:
                (staged / "backup").mkdir(mode=0o700)
                atomic_write(staged / "backup/ca-key.encrypted.pem", (temp / "ca-key.encrypted.pem").read_bytes())
            staged.chmod(0o755)
            os.rename(staged, ETC)  # An existing nonempty directory cannot be overwritten.
        finally:
            if staged.exists() and staged.parent == ETC.parent and not staged.is_symlink():
                shutil.rmtree(staged)


def activate(release, cfg, no_start=False):
    step("4/6", "Отдельный пользователь и systemd credentials")
    import pwd
    try:
        account = pwd.getpwnam("myownvpn")
        if account.pw_uid == 0 or account.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
            raise ValueError("Существующий пользователь myownvpn имеет login shell. Выберите чистую систему.")
    except KeyError:
        run(("useradd", "--system", "--user-group", "--home-dir", "/var/lib/myownvpn", "--shell", "/usr/sbin/nologin", "myownvpn"))
        account = pwd.getpwnam("myownvpn")
    for path in (STATE_DIR, LOG_DIR):
        if path.is_symlink():
            raise ValueError(f"Каталог {path} не должен быть ссылкой.")
        path.mkdir(mode=0o700, exist_ok=True)
        path.chmod(0o700)
        os.chown(path, account.pw_uid, account.pw_gid)
    if UNIT.exists() and MARKER not in UNIT.read_text():
        raise ValueError("Существующая systemd-служба не принадлежит этому установщику.")
    with clients.locked(ETC):
        ensure_clients()
        os.chown(ETC / "clients.json", 0, account.pw_gid)
        (ETC / "clients.json").chmod(0o640)
    old_link = os.readlink(BASE / "current") if (BASE / "current").is_symlink() else None
    old_unit = UNIT.read_bytes() if UNIT.exists() else None
    old_command = COMMAND.read_bytes() if COMMAND.exists() else None
    was_enabled = run(("systemctl", "is-enabled", "myownvpn.service"), capture=True, check=False).returncode == 0
    was_active = run(("systemctl", "is-active", "myownvpn.service"), capture=True, check=False).returncode == 0
    link = BASE / (".current-" + secrets.token_hex(4))
    try:
        atomic_write(UNIT, unit_text(cfg), 0o644)
        link.symlink_to(release, target_is_directory=True)
        os.replace(link, BASE / "current")
        atomic_write(COMMAND, '#!/bin/sh\n' + MARKER + '\nexec /usr/bin/python3 -I /opt/myownvpn/current/server/admin.py "$@"\n', 0o755)
        step("5/6", "Включение службы" if not no_start else "Подготовка службы без запуска")
        run(("systemctl", "daemon-reload"), check=not no_start)
        run(("systemctl", "enable", "myownvpn.service"))
        if not no_start:
            run(("systemctl", "restart", "myownvpn.service"))
            health_check(release)
    except BaseException:
        run(("systemctl", "stop", "myownvpn.service"), check=False)
        if not was_enabled:
            run(("systemctl", "disable", "myownvpn.service"), check=False)
        if old_link:
            restore = BASE / (".restore-" + secrets.token_hex(4))
            restore.symlink_to(old_link, target_is_directory=True)
            os.replace(restore, BASE / "current")
        else:
            (BASE / "current").unlink(missing_ok=True)
        if old_unit is not None:
            atomic_write(UNIT, old_unit, 0o644)
        else:
            UNIT.unlink(missing_ok=True)
        if old_command is not None:
            atomic_write(COMMAND, old_command, 0o755)
        else:
            COMMAND.unlink(missing_ok=True)
        run(("systemctl", "daemon-reload"), check=False)
        if old_link and was_active and not no_start:
            run(("systemctl", "restart", "myownvpn.service"), check=False)
        raise
    finally:
        link.unlink(missing_ok=True)


def health_check(release=None):
    release = release or BASE / "current"
    command = (release / "venv/bin/python", "-I", release / "server/identity.py", "health", "--config", ETC / "server.json",
               "--key", ETC / "credentials/health-key", "--ca", ETC / "ca-cert.pem")
    for _ in range(3):
        result = run(command, check=False)
        if result.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError(f"TLS/QUIC-проверка не прошла. Проверьте sudo myownvpn logs и {LOG}.")


def install(args, update=False):
    host_check(not args.no_start)
    source = verify_package(args.source or ROOT)
    exists = (ETC / "server.json").exists()
    if exists and not update:
        raise ValueError("Конфигурация уже есть. Используйте update: ключи и настройки сохранятся.")
    if update and not exists:
        raise ValueError("Сервер ещё не установлен. Выберите install.")
    if not update and ETC.exists():
        raise ValueError("Каталог /etc/myownvpn уже есть. Сохраните его данные перед новой установкой.")
    if UNIT.exists() and MARKER not in UNIT.read_text():
        raise ValueError("Существующая служба не принадлежит этому установщику.")
    if COMMAND.exists() and MARKER not in COMMAND.read_text():
        raise ValueError("Существующая команда myownvpn не принадлежит этому установщику.")
    cfg = load() if update else plan(args)
    review(cfg)
    if update:
        print("\n  Обновление перезапустит службу и завершит текущие сессии.")
    if not args.yes and not yes("Установить обновление?" if update else "Установить сервер?"):
        return
    if not update:
        port_check(cfg)
    release = make_release(source)
    if not update:
        credentials(release, cfg, args)
    else:
        step("3/6", "Сохранение существующих ключей и настроек")
    activate(release, cfg, args.no_start)
    step("6/6", "Готово" if not args.no_start else "Образ подготовлен; служба пока не запущена")
    row("Управление", "sudo myownvpn")
    row("Проверка", "sudo myownvpn doctor")
    row("Клиенты", "sudo myownvpn → 5 · создать и скопировать конфигурацию")
    row("Firewall", f"разрешите входящий {cfg['port']}/tcp" + (f" и {cfg['port']}/udp" if cfg["transport"] == "auto" else ""))
    if (ETC / "backup/ca-key.encrypted.pem").exists():
        print("\n  Зашифрованный ключ CA: /etc/myownvpn/backup/ca-key.encrypted.pem")
        print("  Сохраните его и ca-cert.pem вне VPS. Пароль не записан на сервер.")
    print("\n  Для каждого клиента создаётся отдельный ключ. Удаление клиента отзывает доступ.\n")


def status(doctor=False):
    banner("Состояние сервера")
    if not (ETC / "server.json").is_file():
        print("  Сервер не установлен. Выберите установку из архива Debian 13.\n")
        return
    cfg = load()
    result = subprocess.run(("systemctl", "is-active", "myownvpn.service"), capture_output=True, text=True)
    row("Служба", result.stdout.strip() or "не запущена")
    row("Адрес", address(cfg["public_ips"][0], cfg["port"]))
    row("Назначение", address(*cfg["target"]))
    row("SRTL сервера", "включён" if cfg["srtl"] else "выключен")
    row("Доступ клиентов", "отдельные ключи · отзыв без перезапуска")
    if (ETC / "identity-info.json").exists():
        info = json.loads((ETC / "identity-info.json").read_text())
        row("Сертификат до", info["expires"])
        row("SHA-256 CA", info["ca_sha256"])
    if doctor:
        print("\n  Проверка локальных TLS/QUIC и ключа доступа…", flush=True)
        health_check()
        print(paint("  Проверка пройдена. Внешний firewall проверяется отдельно.", "32"))
    print()


def change_srtl(value):
    cfg = load()
    old = dict(cfg)
    cfg["srtl"] = value == "on"
    atomic_write(ETC / "server.json", json.dumps(cfg, indent=2) + "\n", 0o644)
    result = run(("systemctl", "reload", "myownvpn.service"), check=False)
    if result.returncode:
        atomic_write(ETC / "server.json", json.dumps(old, indent=2) + "\n", 0o644)
        raise RuntimeError("SRTL не изменён: служба должна быть запущена. Проверьте status.")
    print("\n  SRTL сервера " + ("включён" if cfg["srtl"] else "выключен") + ". Сессии сохранены.\n")


def save_clients(data):
    clients.validate(data)
    path = ETC / "clients.json"
    group = path.stat().st_gid if path.exists() else None
    # Keep the replacement private until its group and mode are set.
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                 0o640 if group is not None and os.name == "posix" else 0o600, group=group)


def ensure_clients():
    path = ETC / "clients.json"
    marker = ETC / "credentials/clients-enabled"
    health = ETC / "credentials/health-key"
    if not health.exists():
        atomic_write(health, secrets.token_hex(32) + "\n")
    if path.exists():
        data = clients.load(path)
        if not marker.exists():
            atomic_write(marker, "1\n")
        return data
    if marker.exists():
        raise ValueError("Реестр клиентов отсутствует. Восстановите clients.json из резервной копии; прежний ключ автоматически не включается")
    # One-time upgrade: existing copied configurations remain one revocable client.
    key = (ETC / "credentials/access-key").read_text().strip()
    data = clients.empty()
    item = clients.record("Прежний общий ключ", key)
    data["clients"].append(item)
    atomic_write(ETC / "credentials/clients" / item["id"], key + "\n")
    save_clients(data)
    atomic_write(marker, "1\n")
    return data


def client_key(item):
    path = ETC / "credentials/clients" / item["id"]
    key = private_file(path).decode("ascii").strip()
    if clients.digest(key) != item["key_hash"]:
        raise ValueError("Ключ клиента не соответствует реестру. Создайте нового клиента")
    return key


def find_client(data, identity):
    item = next((c for c in data["clients"] if c["id"] == identity), None)
    if item is None:
        raise ValueError("Клиент не найден. Откройте список клиентов")
    return item


def wait_clients(revision):
    if run(("systemctl", "is-active", "myownvpn.service"), capture=True, check=False).returncode:
        return  # The next start reads the allowlist before opening a listener.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            _, _, applied, updated = clients.snapshot(STATE_DIR / "usage.sqlite")
            if applied == revision and time.time() - updated < 3:
                return
        except (OSError, clients.sqlite3.Error):
            pass
        time.sleep(.1)
    # Never report successful revocation while an old/unresponsive daemon has access.
    result = run(("systemctl", "stop", "myownvpn.service"), check=False)
    if result.returncode:
        raise RuntimeError("Реестр сохранён, но отзыв не подтверждён и остановить службу не удалось. Немедленно проверьте службу")
    raise RuntimeError("Реестр сохранён. Служба остановлена: применение доступа не подтверждено. Обновите сервер и запустите службу")


def create_client(name):
    with clients.locked(ETC):
        data = clients.load(ETC / "clients.json")
        if len(data["clients"]) >= clients.MAX_CLIENTS:
            raise ValueError("Достигнут предел: 256 клиентов")
        key = secrets.token_hex(32)
        item = clients.record(name, key)
        secret = ETC / "credentials/clients" / item["id"]
        atomic_write(secret, key + "\n")
        data["clients"].append(item)
        data["revision"] = secrets.token_hex(16)
        try:
            save_clients(data)
        except BaseException:
            secret.unlink(missing_ok=True)
            raise
        wait_clients(data["revision"])
    return item


def show_client(identity):
    data = clients.load(ETC / "clients.json")
    item = find_client(data, identity)
    cfg = load()
    print("\n  " + item["name"] + " · " + item["id"])
    print("  Скопируйте строку целиком → клиент → Вставить конфигурацию.")
    print("  Секретный ключ внутри. Передавайте только приватно.\n")
    print(encode(address(cfg["public_ips"][0], cfg["port"]), (ETC / "ca-cert.pem").read_bytes(), client_key(item), item["name"]))
    print()


def delete_client(identity):
    with clients.locked(ETC):
        data = clients.load(ETC / "clients.json")
        find_client(data, identity)
        data["clients"] = [c for c in data["clients"] if c["id"] != identity]
        data["revision"] = secrets.token_hex(16)
        save_clients(data)  # Revoke first; never roll access back on an acknowledgement error.
        (ETC / "credentials/clients" / identity).unlink(missing_ok=True)
        wait_clients(data["revision"])
    print("\n  Клиент удалён. Его соединения закрыты, конфигурация больше не работает.\n")


def list_clients():
    data = clients.load(ETC / "clients.json")
    try:
        usage, active, _, updated = clients.snapshot(STATE_DIR / "usage.sqlite")
    except clients.sqlite3.Error:
        raise ValueError("Не удалось прочитать счётчики. Проверьте журнал сервера") from None
    banner("Клиенты")
    print("  Трафик полезных данных: ↑ от клиента, ↓ к клиенту. Без повторов и SRTL.")
    if time.time() - updated >= 3:
        print("  Статус соединений недоступен: сервер остановлен или данные устарели.")
    for index, item in enumerate(data["clients"], 1):
        up, down = usage.get(item["id"], (0, 0))
        online = f"подключён · сессий {active[item['id']]}" if time.time() - updated < 3 and active.get(item["id"]) else "отключён"
        row(f"{index}. {item['name']}", f"{online} · ↑ {up:,} Б · ↓ {down:,} Б")
        row("ID", item["id"])
    if not data["clients"]:
        print("\n  Клиентов пока нет. Выберите «Создать клиента».")
    return data


def clients_menu():
    while True:
        data = list_clients()
        print("\n  1  Создать клиента\n  2  Показать конфигурацию\n  3  Удалить клиента\n  0  Назад\n")
        action = ask("Выберите действие", "0")
        if action == "0":
            return
        if action == "1":
            item = create_client(ask("Имя клиента", "Мой компьютер"))
            show_client(item["id"])
        elif action in ("2", "3"):
            number = ask("Номер клиента")
            if not number or not number.isdecimal() or not 1 <= int(number) <= len(data["clients"]):
                print("  Выберите номер клиента из списка.")
                continue
            item = data["clients"][int(number) - 1]
            if action == "2":
                show_client(item["id"])
            elif yes(f"Удалить «{item['name']}» и немедленно отключить его?"):
                delete_client(item["id"])
        input("\n  Enter — продолжить…")


def export_client(output=None, identity=None):
    cfg = load()
    output = pathlib.Path(output or ("/root/myownvpn-client-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + ".tar.gz"))
    with clients.locked(ETC):
        data = clients.load(ETC / "clients.json")
    if identity:
        item = find_client(data, identity)
    elif len(data["clients"]) == 1:
        item = data["clients"][0]
    elif data["clients"]:
        raise ValueError("Выберите клиента: myownvpn export --client ID --output ФАЙЛ")
    else:
        item = create_client("Мой компьютер")
    files = {"ca-cert.pem": (ETC / "ca-cert.pem").read_bytes(), "access-key": client_key(item).encode()}
    peer = address(cfg["public_ips"][0], cfg["port"])
    files["client.json"] = (json.dumps(dict(server=peer, protocol=PROTOCOL, ca="ca-cert.pem", srtl_client=False,
                                                 srtl_server=cfg["srtl"]), indent=2) + "\n").encode()
    files["CONNECT.txt"] = f"""Myownvpn · protocol v{PROTOCOL} · IP без SNI

Архив содержит секретный access-key. Передайте его через SSH/SCP.
Нужен клиент этой же версии; исходников клиента в этом серверном пакете нет.

PowerShell, из каталога извлечённого пакета:
$env:MYVPN_KEY = (Get-Content -LiteralPath ./access-key -Raw).Trim()
python /path/to/tunnel.py client --server {peer} --ca ./ca-cert.pem

Linux, из каталога извлечённого пакета:
export MYVPN_KEY="$(cat ./access-key)"
python /path/to/tunnel.py client --server {peer} --ca ./ca-cert.pem

SRTL клиента задаётся независимо: добавьте --srtl или --no-srtl.
CA private key и server private key в этот архив не входят.
""".encode()
    if output.is_symlink():
        raise ValueError("Выберите обычный файл для клиентского архива.")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as dest, tarfile.open(fileobj=dest, mode="w:gz") as archive:
        for name, data in files.items():
            item = tarfile.TarInfo(name)
            item.size, item.mode = len(data), 0o600
            archive.addfile(item, io.BytesIO(data))
    print(f"\n  Клиентский пакет: {output}\n  Содержит ключ доступа. Передавайте через SSH/SCP.\n")


def uninstall():
    banner("Удаление службы")
    print("  Служба будет остановлена, автозапуск и команда управления удалены.")
    print("  Ключи, конфигурация, журналы и версии программы сохранятся.")
    if not yes("Удалить службу и завершить текущие сессии?"):
        return
    if UNIT.exists() and MARKER not in UNIT.read_text():
        raise ValueError("Файл службы не принадлежит этому установщику.")
    run(("systemctl", "disable", "--now", "myownvpn.service"), check=False)
    UNIT.unlink(missing_ok=True)
    if COMMAND.exists() and MARKER in COMMAND.read_text():
        COMMAND.unlink()
    run(("systemctl", "daemon-reload"))
    print("\n  Служба удалена. Данные сохранены в /etc/myownvpn и /opt/myownvpn.\n")


def menu(args):
    while True:
        banner()
        installed = (ETC / "server.json").exists()
        row("Установка", "есть" if installed else "не выполнена")
        print("\n  1  Установить сервер\n  2  Состояние и проверка\n  3  Журнал соединений")
        print("  4  Включить / выключить SRTL\n  5  Клиенты · создать, конфигурация, трафик, удалить")
        print("  6  Запустить / остановить службу\n  7  Перезапустить службу\n  8  Удалить службу\n  0  Выйти\n")
        choice = ask("Выберите действие", "0")
        try:
            if choice == "0":
                return
            if choice == "1":
                install(args)
            elif choice == "2":
                status(doctor=True)
            elif choice == "3":
                subprocess.run(("journalctl", "-u", "myownvpn.service", "-n", "60", "--no-pager"))
            elif choice == "4":
                change_srtl("on" if yes("Включить SRTL отправки сервера?", load()["srtl"]) else "off")
            elif choice == "5":
                clients_menu()
            elif choice == "6":
                run(("systemctl", "start" if yes("Запустить службу?", True) else "stop", "myownvpn.service"))
            elif choice == "7":
                if yes("Перезапустить службу и завершить текущие сессии?"):
                    run(("systemctl", "restart", "myownvpn.service"))
            elif choice == "8":
                uninstall()
            else:
                print("  Выберите номер из меню.")
        except (OSError, ValueError, RuntimeError) as exc:
            print(paint("\n  " + str(exc), "31"))
        input("\n  Enter — вернуться в меню…")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Myownvpn server · Debian 13 · terminal only")
    parser.add_argument("command", nargs="?", default="menu",
        choices=("menu", "install", "update", "status", "doctor", "logs", "start", "stop", "restart", "srtl", "export", "uninstall", "preview", "clients", "client-add", "client-show", "client-delete"))
    parser.add_argument("--client", help="ID клиента из списка")
    parser.add_argument("--name", help="Имя нового клиента")
    parser.add_argument("value", nargs="?", choices=("on", "off"))
    parser.add_argument("--source", type=pathlib.Path)
    parser.add_argument("--public-ip", action="append")
    parser.add_argument("--port", type=int)
    parser.add_argument("--target")
    parser.add_argument("--transport", choices=("auto", "tcp"), default="auto")
    parser.add_argument("--srtl", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--generate-identity", action="store_true")
    for name in ("ca", "cert", "cert-key", "key-file", "ca-password-file", "output"):
        parser.add_argument("--" + name, type=pathlib.Path)
    parser.add_argument("--yes", action="store_true", help="подтвердить план установки/обновления")
    parser.add_argument("--no-start", action="store_true", help="подготовить образ без запущенного systemd")
    args = parser.parse_args()
    if args.command == "preview":
        review(dict(public_ips=["198.51.100.10"], listen="0.0.0.0", port=443, target=["127.0.0.1", 9000], transport="auto", srtl=False))
        print("\n  Предпросмотр. Система не изменена.\n")
        return
    host_check(require_manager=not args.no_start)
    if args.command in ("install", "update"):
        install(args, update=args.command == "update")
    elif args.command == "menu":
        menu(args)
    elif args.command in ("status", "doctor"):
        status(doctor=args.command == "doctor")
    elif args.command == "srtl":
        if args.value is None:
            parser.error("для srtl укажите on или off")
        change_srtl(args.value)
    elif args.command == "export":
        export_client(args.output, args.client)
    elif args.command == "clients":
        list_clients()
    elif args.command == "client-add":
        item = create_client(args.name or ask("Имя клиента", "Мой компьютер"))
        show_client(item["id"])
    elif args.command in ("client-show", "client-delete"):
        if not args.client:
            parser.error("укажите --client ID из списка myownvpn clients")
        if args.command == "client-show":
            show_client(args.client)
        elif args.yes or yes("Удалить клиента и немедленно отключить его?"):
            delete_client(args.client)
    elif args.command == "logs":
        subprocess.run(("journalctl", "-u", "myownvpn.service", "-n", "80", "-f"))
    elif args.command == "uninstall":
        uninstall()
    else:
        if args.command != "restart" or args.yes or yes("Перезапустить службу и завершить текущие сессии?"):
            run(("systemctl", args.command, "myownvpn.service"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Операция отменена. Для проверки используйте sudo myownvpn status.\n")
        sys.exit(130)
    except (OSError, ValueError, RuntimeError) as error:
        print(paint("\n  " + str(error) + "\n", "31"), file=sys.stderr)
        sys.exit(1)
