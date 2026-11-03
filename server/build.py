"""Build a server runtime Debian archive; never includes local state, tests or keys."""

import argparse
import gzip
import hashlib
import io
import json
import pathlib
import sys
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from server.config import APP_FILES, SERVER_FILES, PROTOCOL


def refresh_lock():
    entries = []
    for line in (ROOT / "requirements.lock").read_text().splitlines():
        name, version = line.split("==")
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as response:
            files = json.load(response)["urls"]
        wheels = [file for file in files if file["filename"].endswith(".whl") and
                  (file["filename"].endswith("none-any.whl") or "manylinux" in file["filename"] and
                   any(arch in file["filename"] for arch in ("x86_64", "aarch64")))]
        if not wheels:
            raise ValueError(f"Нет Linux wheels для {line}")
        hashes = sorted({file["digests"]["sha256"] for file in wheels})
        entries.append(line + " \\\n" + " \\\n".join("    --hash=sha256:" + digest for digest in hashes))
    (ROOT / "server/requirements.lock").write_text(
        "# Debian 13 amd64/arm64; PyPI wheel hashes; binary-only installation.\n" + "\n".join(entries) + "\n", encoding="utf-8")


def build(output):
    output = pathlib.Path(output)
    output.mkdir(parents=True, exist_ok=True)
    files = {}
    for name in APP_FILES + SERVER_FILES + ("install.sh",):
        source = ROOT / ("server/install.sh" if name == "install.sh" else name)
        if source.is_symlink():
            raise ValueError(f"Source file cannot be a symlink: {source}")
        files[name] = source.read_text(encoding="utf-8").replace("\r\n", "\n").encode()
    manifest = {"format": 1, "protocol": PROTOCOL,
                "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}}
    files["MANIFEST.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    prefix = f"myownvpn-server-debian13-v{PROTOCOL}"
    archive = output / (prefix + ".tar.gz")
    with archive.open("wb") as dest, gzip.GzipFile(fileobj=dest, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as bundle:
            for name, data in sorted(files.items()):
                item = tarfile.TarInfo(prefix + "/" + name)
                item.size = len(data)
                item.mode = 0o755 if name == "install.sh" else 0o644
                bundle.addfile(item, io.BytesIO(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + ".sha256").write_text(digest + "  " + archive.name + "\n", encoding="ascii")
    return archive, digest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh-lock", action="store_true")
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / ".local/dist")
    args = parser.parse_args()
    if args.refresh_lock:
        refresh_lock()
    archive, digest = build(args.output)
    print(f"{archive.resolve()}\nSHA-256: {digest}")
