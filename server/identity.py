"""Private identity creation/validation and local authenticated health checks."""

import argparse
import asyncio
import datetime
import ipaddress
import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from ip_cert import generate
from server.config import load


def validate(ca_path, cert_path, key_path, ips):
    ca = x509.load_pem_x509_certificate(pathlib.Path(ca_path).read_bytes())
    cert = x509.load_pem_x509_certificate(pathlib.Path(cert_path).read_bytes())
    key = serialization.load_pem_private_key(pathlib.Path(key_path).read_bytes(), password=None)
    if cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
        raise ValueError("Сертификат и закрытый ключ не совпадают.")
    cert.verify_directly_issued_by(ca)
    if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("ca-cert.pem должен быть сертификатом CA.")
    if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Используйте отдельный серверный сертификат, а не ключ CA.")
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if san.get_values_for_type(x509.DNSName):
        raise ValueError("Основной профиль требует сертификат только с IP SAN.")
    if not set(map(ipaddress.ip_address, ips)) <= set(san.get_values_for_type(x509.IPAddress)):
        raise ValueError("Сертификат не содержит все указанные IP-адреса.")
    now = datetime.datetime.now(datetime.timezone.utc)
    if any(not c.not_valid_before_utc <= now < c.not_valid_after_utc for c in (ca, cert)):
        raise ValueError("Проверьте срок сертификатов и время сервера.")
    return {"expires": cert.not_valid_after_utc.isoformat(), "ca_sha256": ca.fingerprint(hashes.SHA256()).hex()}


def create(out, ips):
    password = sys.stdin.buffer.read(4097).rstrip(b"\r\n")
    if not 12 <= len(password) <= 4096:
        raise ValueError("Для резервного ключа CA нужен пароль от 12 символов.")
    out = pathlib.Path(out)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    # /run is tmpfs on Debian/systemd. The unencrypted CA key never enters /opt or /etc.
    with tempfile.TemporaryDirectory(prefix="myownvpn-identity-", dir="/run") as directory:
        files = generate(directory, ips)
        ca_key = serialization.load_pem_private_key(files["ca-key.pem"].read_bytes(), password=None)
        encrypted = ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.BestAvailableEncryption(password))
        for name in ("ca-cert.pem", "server-cert.pem", "server-key.pem"):
            with (out / name).open("xb") as dest:
                os.chmod(out / name, 0o600)
                dest.write(files[name].read_bytes())
        with (out / "ca-key.encrypted.pem").open("xb") as dest:
            os.chmod(out / "ca-key.encrypted.pem", 0o600)
            dest.write(encrypted)


async def health(config, key_path, ca):
    from transports import quic_config, shutdown_channels, tls_client
    from tunnel import probe
    cfg = load(config)
    key = pathlib.Path(key_path).read_text(encoding="ascii").strip()
    bind = cfg["listen"]
    host = ("127.0.0.1" if ":" not in bind else "::1") if ipaddress.ip_address(bind).is_unspecified else bind
    context = tls_client(ca)
    try:
        for kind in (("tcp", "udp") if cfg["transport"] == "auto" else ("tcp",)):
            await probe(kind, (host, cfg["port"]), key, context, cfg["public_ips"][0],
                        quic_config(ca=ca, hostname=cfg["public_ips"][0]))
    finally:
        await shutdown_channels()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    gen = sub.add_parser("create")
    gen.add_argument("--out", required=True)
    gen.add_argument("--ip", action="append", required=True)
    check = sub.add_parser("validate")
    for name in ("ca", "cert", "key"):
        check.add_argument("--" + name, required=True)
    check.add_argument("--ip", action="append", required=True)
    probe_cmd = sub.add_parser("health")
    for name in ("config", "key", "ca"):
        probe_cmd.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if args.mode == "create":
        create(args.out, args.ip)
    elif args.mode == "validate":
        print(json.dumps(validate(args.ca, args.cert, args.key, args.ip)))
    else:
        asyncio.run(health(args.config, args.key, args.ca))
