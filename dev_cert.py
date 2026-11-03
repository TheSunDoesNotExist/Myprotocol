"""Generate a local-only TLS certificate using OpenSSL (also bundled with Git)."""

import pathlib
import shutil
import subprocess


def generate(directory):
    openssl = shutil.which("openssl")
    if not openssl:
        candidate = pathlib.Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe")
        if candidate.exists():
            openssl = str(candidate)
    if not openssl:
        raise RuntimeError("OpenSSL is required to generate the development certificate")
    directory = pathlib.Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    cert, key = directory / "cert.pem", directory / "key.pem"
    if cert.exists() or key.exists():
        raise FileExistsError("refusing to overwrite an existing certificate or key")
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "7",
                    "-subj", "/CN=localhost", "-addext",
                    "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                   check=True, capture_output=True)
    return cert, key


if __name__ == "__main__":
    cert, key = generate(pathlib.Path(__file__).parent / ".local")
    print(f"Development certificate: {cert}\nPrivate key: {key}")
