"""Build a native Windows portable app or Fedora RPM on its target OS."""

import argparse
import hashlib
import importlib.metadata
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from desktop import VERSION


def build(rpm=False):
    if platform.machine().lower() not in ("amd64", "x86_64"):
        raise SystemExit("This build currently targets x86_64")
    out = ROOT / ".local/dist"
    work = ROOT / ".local/client-build"
    out.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    assert work.resolve().is_relative_to(ROOT / ".local")
    icon = None
    if os.name == "nt":
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QGuiApplication, QPainter, QPixmap
        from PySide6.QtSvg import QSvgRenderer
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        app = QGuiApplication.instance() or QGuiApplication([])
        pixmap = QPixmap(256, 256)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        QSvgRenderer(str(ROOT / "desktop/myownvpn.svg")).render(painter)
        painter.end()
        icon = work / "myownvpn.ico"
        if not pixmap.save(str(icon)):
            raise RuntimeError("Could not render application icon")
    command = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--windowed",
               "--name", "Myownvpn", "--distpath", str(work / "dist"), "--workpath", str(work / "work"),
               "--specpath", str(work), "--paths", str(ROOT),
               "--add-data", str(ROOT / "desktop/theme.qss") + os.pathsep + "desktop",
               "--add-data", str(ROOT / "desktop/myownvpn.svg") + os.pathsep + "desktop",
               "--exclude-module", "tkinter", "--exclude-module", "PySide6.QtQml",
               "--exclude-module", "PySide6.QtQuick", "--exclude-module", "PySide6.QtWebEngineWidgets"]
    if icon:
        command += ["--icon", str(icon)]
    for name in ("aioquic", "cryptography", "certifi", "PySide6-Essentials", "shiboken6"):
        command += ["--copy-metadata", name]
    build_env = dict(os.environ)
    if os.name == "nt":
        # Qt uses the Windows ICU API. A developer's PATH can contain a different
        # ICU (e.g. Poppler), with the same DLL name and incompatible exports.
        system = pathlib.Path(os.environ["SystemRoot"])
        build_env["PATH"] = os.pathsep.join(map(str, (pathlib.Path(sys.executable).parent,
            pathlib.Path(sys.base_prefix), system / "System32", system)))
    subprocess.run([*command, "--noupx", str(ROOT / "client.py")], cwd=ROOT, env=build_env, check=True)
    bundle = work / "dist/Myownvpn"
    if os.name == "nt":
        import pefile
        for library in bundle.rglob("icuuc.dll"):
            image = pefile.PE(str(library))
            names = {v.name for v in image.DIRECTORY_ENTRY_EXPORT.symbols}
            if b"ucnv_open" not in names:
                raise RuntimeError("Incompatible ICU DLL in Windows bundle; refusing to package")
    shutil.copyfile(ROOT / "desktop/README.md", bundle / "README.md")
    shutil.copyfile(ROOT / "desktop/THIRD_PARTY.md", bundle / "THIRD_PARTY.md")
    shutil.copyfile(ROOT / "desktop/DESIGN.md", bundle / "DESIGN.md")
    licenses = bundle / "licenses"
    licenses.mkdir(exist_ok=True)
    for name in ("aioquic", "cryptography", "certifi", "PySide6-Essentials", "shiboken6", "PyInstaller"):
        distribution = importlib.metadata.distribution(name)
        for file in distribution.files or ():
            if any(part.lower() in ("licenses", "license", "copying") for part in file.parts) or file.name.lower().startswith(("license", "copying")):
                source = pathlib.Path(distribution.locate_file(file))
                if source.is_file():
                    destination = licenses / name / file.name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
    if os.name == "nt":
        artifact = out / f"Myownvpn-Windows-x86_64-v{VERSION}.zip"
        with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for path in sorted(bundle.rglob("*")):
                if path.is_file():
                    archive.write(path, pathlib.Path("Myownvpn") / path.relative_to(bundle))
    elif rpm:
        artifact = build_rpm(bundle, out)
    else:
        artifact = out / f"Myownvpn-Linux-x86_64-v{VERSION}.tar.gz"
        with tarfile.open(artifact, "w:gz") as archive:
            archive.add(bundle, arcname="Myownvpn")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    artifact.with_name(artifact.name + ".sha256").write_text(digest + "  " + artifact.name + "\n", encoding="ascii")
    print(str(artifact), "SHA-256", digest)
    return artifact


def build_rpm(bundle, out):
    with tempfile.TemporaryDirectory(prefix="myownvpn-rpm-") as directory:
        tree = pathlib.Path(directory)
        payload = tree / "payload"
        target = payload / "usr/libexec/myownvpn"
        target.parent.mkdir(parents=True)
        shutil.copytree(bundle, target)
        applications = payload / "usr/share/applications"
        applications.mkdir(parents=True)
        (applications / "org.myownvpn.Client.desktop").write_text("""[Desktop Entry]
Type=Application
Name=Myownvpn
Comment=Secure TCP application tunnel
Exec=/usr/libexec/myownvpn/Myownvpn
Icon=myownvpn
Terminal=false
Categories=Network;
StartupWMClass=Myownvpn
""")
        icons = payload / "usr/share/icons/hicolor/scalable/apps"
        icons.mkdir(parents=True)
        shutil.copyfile(ROOT / "desktop/myownvpn.svg", icons / "myownvpn.svg")
        spec = tree / "myownvpn.spec"
        spec.write_text(f"""Name: myownvpn-client
Version: {VERSION}
Release: 1%{{?dist}}
Summary: Desktop client for Myownvpn protocol v5
License: LicenseRef-NotSpecified
URL: https://github.com/TheSunDoesNotExist/Myprotocol
BuildArch: x86_64
AutoReqProv: no
Requires: glibc >= 2.43
Requires: libsecret, glib2, libX11, libxcb, libXext, libXrender, libxkbcommon, libxkbcommon-x11
Requires: libXcursor, libXfixes, libXrandr, libXi, libSM, libICE, mesa-libEGL, mesa-libGL, fontconfig
Requires: xcb-util-cursor, xcb-util-image, xcb-util-keysyms, xcb-util-renderutil, xcb-util-wm

%description
Native Qt client with authenticated TLS/QUIC, independent SRTL and metadata logs.

%install
mkdir -p %{{buildroot}}
cp -a {payload}/. %{{buildroot}}/

%files
/usr/libexec/myownvpn
/usr/share/applications/org.myownvpn.Client.desktop
/usr/share/icons/hicolor/scalable/apps/myownvpn.svg
""", encoding="utf-8")
        subprocess.run(["rpmbuild", "-bb", "--define", f"_topdir {tree}", "--define", "_build_id_links none",
                        "--define", "__os_install_post %{nil}", "--define", "debug_package %{nil}", str(spec)], check=True)
        result = next((tree / "RPMS/x86_64").glob("*.rpm"))
        dest = out / result.name
        shutil.copyfile(result, dest)
        return dest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", action="store_true")
    build(parser.parse_args().rpm)
