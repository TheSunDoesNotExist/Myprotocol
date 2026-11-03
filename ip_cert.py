"""Private CA and an IP-only server certificate; no DNS names or public CA."""

import argparse
import datetime
import ipaddress
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def generate(directory, addresses, days=90):
    ips = list(dict.fromkeys(ipaddress.ip_address(value) for value in addresses))
    if not ips or not 1 <= days <= 365:
        raise ValueError("provide IP addresses and a validity of 1..365 days")
    directory = pathlib.Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    files = {name: directory / name for name in ("ca-cert.pem", "ca-key.pem", "server-cert.pem", "server-key.pem")}
    if any(path.exists() for path in files.values()):
        raise FileExistsError("refusing to overwrite existing identity material")
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, server_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(2))
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Private CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=366))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(ca_name)
            .public_key(server_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip) for ip in ips]), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    for name, value in (("ca-cert.pem", ca), ("ca-key.pem", ca_key),
                        ("server-cert.pem", cert), ("server-key.pem", server_key)):
        data = (value.public_bytes(serialization.Encoding.PEM) if name.endswith("cert.pem") else
                value.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
        # Exclusive creation protects existing keys, including concurrent invocations.
        with files[name].open("xb") as output:
            files[name].chmod(0o600 if name.endswith("key.pem") else 0o644)
            output.write(data)
    return files


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", action="append", required=True, help="repeat for each server IPv4/IPv6")
    parser.add_argument("--out", default=".local/ip-identity")
    parser.add_argument("--days", type=int, default=90)
    args = parser.parse_args()
    for name, path in generate(args.out, args.ip, args.days).items():
        print(f"{name}: {path.resolve()}")
