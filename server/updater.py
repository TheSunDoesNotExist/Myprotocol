"""Bounded HTTPS release downloads. No git checkout, shell pipeline or dependencies."""

import gzip
import contextlib
import hashlib
import io
import json
import os
import pathlib
import re
import ssl
import stat
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass

from server.config import PROTOCOL

REPOSITORY = "TheSunDoesNotExist/Myprotocol"
API = f"https://api.github.com/repos/{REPOSITORY}/releases?per_page=100"
ARCHIVE = f"myownvpn-server-debian13-v{PROTOCOL}.tar.gz"
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_UNPACKED = 32 * 1024 * 1024
HOSTS = {"api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}


@contextlib.contextmanager
def installation_lock(path=pathlib.Path("/run/myownvpn-install.lock")):
    import fcntl
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):
            raise ValueError("Небезопасный файл блокировки установки")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Другая установка или обновление уже выполняется. Дождитесь завершения") from None
        yield
    finally:
        os.close(fd)


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})", value):
        raise ValueError("Неподдерживаемый номер версии сервера")
    return tuple(map(int, value.split(".")))


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Повторяющееся поле метаданных обновления")
        result[key] = value
    return result


def parse_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_object)
    except (UnicodeError, RecursionError, ValueError):
        raise ValueError("Не удалось прочитать метаданные обновления") from None


def secure_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in HOSTS or parsed.username is not None
            or parsed.password is not None or parsed.port not in (None, 443)):
        raise ValueError("Небезопасный адрес загрузки обновления")
    return url


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers, secure_url(newurl))


def download(url, limit):
    secure_url(url)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    opener = urllib.request.build_opener(Redirect(), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, headers={"User-Agent": "Myownvpn-server-updater",
        "Accept": "application/vnd.github+json" if url == API else "application/octet-stream",
        "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with opener.open(request, timeout=30) as response:
            secure_url(response.geturl())
            if response.status != 200:
                raise ValueError("GitHub вернул неполный файл обновления")
            data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Файл обновления превышает допустимый размер")
        return data
    except urllib.error.HTTPError as error:
        if error.code in (403, 429):
            raise ValueError("GitHub временно ограничил запросы. Повторите проверку позже") from None
        raise ValueError(f"Не удалось скачать обновление: GitHub HTTP {error.code}") from None
    except (urllib.error.URLError, OSError):
        raise ValueError("Не удалось связаться с GitHub по HTTPS. Проверьте сеть, время и сертификаты ОС") from None


@dataclass(frozen=True)
class Release:
    version: str
    tag: str
    size: int
    sha256: str
    prerelease: bool

    def url(self, name):
        return f"https://github.com/{REPOSITORY}/releases/download/{self.tag}/{name}"


def latest():
    data = parse_json(download(API, 2 * 1024 * 1024))
    if not isinstance(data, list) or len(data) > 100:
        raise ValueError("Неверный список выпусков GitHub")
    found = []
    for item in data:
        if not isinstance(item, dict) or item.get("draft") is not False or not isinstance(item.get("tag_name"), str):
            continue
        match = re.fullmatch(r"(?:server|clients)-v(.{1,24})", item["tag_name"])
        if not match:
            continue
        try:
            number = version(match[1])
        except ValueError:
            continue
        assets = item.get("assets")
        if not isinstance(assets, list) or len(assets) > 128:
            continue
        archive = [v for v in assets if isinstance(v, dict) and v.get("name") == ARCHIVE]
        checksum = [v for v in assets if isinstance(v, dict) and v.get("name") == ARCHIVE + ".sha256"]
        if len(archive) != 1 or len(checksum) != 1 or any(v.get("state") != "uploaded" for v in archive + checksum):
            continue
        asset = archive[0]
        sha = asset.get("digest", "")
        if (type(asset.get("size")) is not int or not 0 < asset["size"] <= MAX_ARCHIVE
                or not isinstance(sha, str) or not sha.startswith("sha256:") or not digest(sha[7:])
                or type(item.get("prerelease")) is not bool):
            continue
        found.append((number, Release(match[1], item["tag_name"], asset["size"], sha[7:], item["prerelease"])))
    if not found:
        raise ValueError("В GitHub нет полного серверного выпуска для текущего протокола")
    return max(found, key=lambda pair: pair[0])[1]


def unpack(data, destination, release):
    """Check every byte and path before writing any downloaded code to staging."""
    if len(data) != release.size or hashlib.sha256(data).hexdigest() != release.sha256:
        raise ValueError("SHA-256 серверного архива не совпал с GitHub. Обновление отменено")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            raw = compressed.read(MAX_UNPACKED + 1)
        if len(raw) > MAX_UNPACKED:
            raise ValueError("Распакованное обновление слишком большое")
        files = {}
        prefix = f"myownvpn-server-debian13-v{PROTOCOL}/"
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                if (len(files) >= 128 or not member.isfile() or not 0 <= member.size <= 2 * 1024 * 1024
                        or not member.name.startswith(prefix)):
                    raise ValueError("Неподдерживаемое содержимое обновления")
                name = member.name[len(prefix):]
                if (not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name)
                        or any(part in (".", "..") for part in name.split("/")) or name in files):
                    raise ValueError("Небезопасный путь или повторяющийся файл обновления")
                files[name] = archive.extractfile(member).read()
        manifest = parse_json(files.get("MANIFEST.json", b""))
        if (not isinstance(manifest, dict) or type(manifest.get("format")) is not int or manifest["format"] != 1
                or type(manifest.get("protocol")) is not int or manifest["protocol"] != PROTOCOL
                or manifest.get("server_version") != release.version
                or not isinstance(manifest.get("sha256"), dict)
                or set(manifest["sha256"]) != set(files) - {"MANIFEST.json"}
                or not {"server/admin.py", "server/config.py", "install.sh"} <= files.keys()):
            raise ValueError("Версия или состав серверного пакета не совпадает с выпуском")
        for name, sha in manifest["sha256"].items():
            if not digest(sha) or hashlib.sha256(files[name]).hexdigest() != sha:
                raise ValueError("Контрольная сумма файла обновления не совпала")
        destination = pathlib.Path(destination)
        if destination.exists():
            raise ValueError("Каталог загрузки обновления уже существует")
        destination.mkdir(mode=0o700)
        for name, content in files.items():
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with path.open("xb") as output:
                output.write(content)
            path.chmod(0o600)
        return destination
    except (tarfile.TarError, EOFError, gzip.BadGzipFile, OSError, zlib.error) as error:
        raise ValueError("Не удалось подготовить серверный пакет. Действующая установка не изменена") from error


def stage(release, destination):
    checksum = download(release.url(ARCHIVE + ".sha256"), 1024)
    try:
        fields = checksum.decode("ascii").split()
    except UnicodeError:
        fields = []
    if fields != [release.sha256, ARCHIVE]:
        raise ValueError("SHA-256 файла обновления не совпал с метаданными GitHub")
    data = download(release.url(ARCHIVE), MAX_ARCHIVE)
    return unpack(data, destination, release)
