"""Bounded client-package import and public profile metadata; never extract a tar."""

import datetime
import gzip
import hashlib
import io
import ipaddress
import json
import os
import pathlib
import secrets
import tarfile
import zlib
from dataclasses import asdict, dataclass, field

from cryptography import x509


def data_directory():
    if os.name == "nt":
        base = pathlib.Path(os.environ.get("LOCALAPPDATA", pathlib.Path.home() / "AppData/Local"))
    else:
        base = pathlib.Path(os.environ.get("XDG_DATA_HOME", pathlib.Path.home() / ".local/share"))
    return base / "myownvpn"


def write_private(path, data):
    path = pathlib.Path(path)
    if path.is_symlink():
        raise ValueError("Отказ от записи через символическую ссылку")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            if os.name == "posix":
                os.fchmod(output.fileno(), 0o600)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def endpoint(value):
    try:
        host, port = value.rsplit(":", 1)
        host = str(ipaddress.ip_address(host.strip("[]")))
        port = int(port)
        if not 1 <= port <= 65535 or ipaddress.ip_address(host).is_unspecified or ipaddress.ip_address(host).is_multicast:
            raise ValueError
        return host, port
    except (ValueError, AttributeError):
        raise ValueError("Укажите IP сервера и порт, например 198.51.100.10:443") from None


def valid_key(key):
    if not isinstance(key, str) or len(key) != 64 or any(c not in "0123456789abcdefABCDEF" for c in key):
        raise ValueError("Ключ доступа должен содержать 64 hex-символа")
    return key


@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    server: str
    port: int
    ca_sha256: str
    srtl: bool = False
    local_port: int = 1080
    transport: str = "auto"

    @property
    def address(self):
        host = f"[{self.server}]" if ":" in self.server else self.server
        return f"{host}:{self.port}"


@dataclass(frozen=True)
class Imported:
    profile: Profile
    ca: bytes = field(repr=False)
    key: str = field(repr=False)


def import_package(path):
    with pathlib.Path(path).open("rb") as source:
        compressed = source.read(512 * 1024 + 1)
    if len(compressed) > 512 * 1024:
        raise ValueError("Клиентский пакет слишком большой")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as zipped:
            raw = zipped.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise ValueError("Распакованный клиентский пакет слишком большой")
        files = {}
        allowed = {"ca-cert.pem", "access-key", "client.json", "CONNECT.txt"}
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                if member.name not in allowed or member.name in files or not member.isfile() or member.size > 64 * 1024:
                    raise ValueError("Неподдерживаемое содержимое клиентского пакета")
                files[member.name] = archive.extractfile(member).read()
        if not {"ca-cert.pem", "access-key", "client.json"} <= files.keys():
            raise ValueError("В пакете отсутствуют сертификат, ключ или настройки")
        cfg = json.loads(files["client.json"])
        if not isinstance(cfg, dict) or type(cfg.get("protocol")) is not int or cfg["protocol"] != 5 or cfg.get("ca") != "ca-cert.pem":
            raise ValueError("Нужен клиентский пакет протокола v5")
        host, port = endpoint(cfg.get("server"))
        srtl = cfg.get("srtl_client", False)
        if type(srtl) is not bool:
            raise ValueError("Неверная настройка SRTL")
        ca = x509.load_pem_x509_certificate(files["ca-cert.pem"])
        if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("В пакете отсутствует сертификат CA")
        now = datetime.datetime.now(datetime.timezone.utc)
        if not ca.not_valid_before_utc <= now < ca.not_valid_after_utc:
            raise ValueError("Сертификат CA недействителен: проверьте срок и системное время")
        from cryptography.hazmat.primitives import hashes
        fingerprint = ca.fingerprint(hashes.SHA256()).hex()
        key = valid_key(files["access-key"].decode("ascii").strip())
        identity = hashlib.sha256((host + ":" + str(port) + ":" + fingerprint).encode()).hexdigest()[:24]
        return Imported(Profile(identity, host, host, port, fingerprint, srtl), files["ca-cert.pem"], key)
    except (tarfile.TarError, gzip.BadGzipFile, zlib.error, EOFError, UnicodeError, KeyError, x509.ExtensionNotFound):
        raise ValueError("Не удалось прочитать клиентский пакет v5") from None


class Profiles:
    def __init__(self, root=None):
        self.root = pathlib.Path(root) if root else data_directory()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink():
            raise ValueError("Каталог профилей не должен быть символической ссылкой")
        if os.name == "posix":
            self.root.chmod(0o700)

    def ca_path(self, profile):
        if len(profile.id) != 24 or any(c not in "0123456789abcdef" for c in profile.id):
            raise ValueError("Неверный идентификатор профиля")
        return self.root / (profile.id + ".pem")

    def load(self):
        path = self.root / "profiles.json"
        if not path.exists():
            return []
        with path.open(encoding="utf-8") as source:
            data = json.loads(source.read(64 * 1024 + 1))
        if not isinstance(data, list) or len(data) > 32:
            raise ValueError("Неверный список профилей")
        profiles = []
        for item in data:
            try:
                profile = Profile(**item)
                host, port = endpoint(profile.address)
                self.ca_path(profile)
                if (host != profile.server or port != profile.port or type(profile.local_port) is not int or
                        not 1024 <= profile.local_port <= 65535 or type(profile.srtl) is not bool or
                        profile.transport not in ("auto", "tcp", "udp") or not isinstance(profile.name, str) or
                        not 1 <= len(profile.name) <= 80 or not isinstance(profile.ca_sha256, str) or
                        len(profile.ca_sha256) != 64 or any(c not in "0123456789abcdef" for c in profile.ca_sha256)):
                    raise ValueError
                profiles.append(profile)
            except (TypeError, AttributeError, ValueError):
                raise ValueError("Профиль повреждён: импортируйте клиентский пакет заново") from None
        return profiles

    def save(self, profiles):
        if len(profiles) > 32:
            raise ValueError("Можно сохранить не более 32 профилей")
        write_private(self.root / "profiles.json", (json.dumps([asdict(v) for v in profiles], ensure_ascii=False, indent=2) + "\n").encode())

    def install_ca(self, imported):
        write_private(self.ca_path(imported.profile), imported.ca)
