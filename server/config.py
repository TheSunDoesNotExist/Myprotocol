"""Small, shared server configuration. No shell values or secrets in JSON."""

import ipaddress
import json
import pathlib

BASE = pathlib.Path("/opt/myownvpn")
ETC = pathlib.Path("/etc/myownvpn")
UNIT = pathlib.Path("/etc/systemd/system/myownvpn.service")
COMMAND = pathlib.Path("/usr/local/sbin/myownvpn")
MARKER = "# Managed by Myownvpn Debian installer"
PROTOCOL = 5
APP_FILES = ("tunnel.py", "transports.py", "http_carrier.py", "selection.py", "diagnostics.py",
             "srtl.py", "ech_gateway.py", "ip_cert.py")
SERVER_FILES = ("server/admin.py", "server/config.py", "server/runtime.py", "server/identity.py",
                "server/requirements.lock", "server/README.md")


def validate(data):
    expected = {"schema", "protocol", "public_ips", "listen", "port", "target", "transport", "grace", "srtl"}
    if (not isinstance(data, dict) or set(data) != expected or type(data["schema"]) is not int or
            data["schema"] != 1 or type(data["protocol"]) is not int or data["protocol"] != PROTOCOL):
        raise ValueError("Неподдерживаемый формат server.json. Используйте установщик этой версии.")
    if not isinstance(data["public_ips"], list) or not 1 <= len(data["public_ips"]) <= 16:
        raise ValueError("Укажите от 1 до 16 IP-адресов сервера.")
    if any(not isinstance(ip, str) for ip in data["public_ips"]) or not isinstance(data["listen"], str):
        raise ValueError("IP-адрес должен быть строкой.")
    ips = [ipaddress.ip_address(ip) for ip in data["public_ips"]]
    if any(ip.is_unspecified or ip.is_multicast for ip in ips):
        raise ValueError("Укажите адрес сервера, а не wildcard или multicast.")
    bind = ipaddress.ip_address(data["listen"])
    if bind.is_multicast or bind.version != ips[0].version:
        raise ValueError("Адрес прослушивания должен соответствовать семейству первого IP.")
    if type(data["port"]) is not int or not 1 <= data["port"] <= 65535:
        raise ValueError("Порт должен быть от 1 до 65535.")
    if not isinstance(data["target"], list) or len(data["target"]) != 2:
        raise ValueError("Назначение должно содержать IP и порт.")
    if not isinstance(data["target"][0], str):
        raise ValueError("IP назначения должен быть строкой.")
    ipaddress.ip_address(data["target"][0])
    if type(data["target"][1]) is not int or not 1 <= data["target"][1] <= 65535:
        raise ValueError("Порт назначения должен быть от 1 до 65535.")
    if data["transport"] not in ("auto", "tcp") or type(data["srtl"]) is not bool:
        raise ValueError("Проверьте транспорт и флаг SRTL.")
    if type(data["grace"]) not in (int, float) or not 1 <= data["grace"] <= 300:
        raise ValueError("Grace должен быть от 1 до 300 секунд.")
    return dict(data, public_ips=[str(ip) for ip in ips], listen=str(bind),
                target=[str(ipaddress.ip_address(data["target"][0])), data["target"][1]])


def load(path=ETC / "server.json"):
    with pathlib.Path(path).open(encoding="utf-8") as source:
        return validate(json.loads(source.read(16385)))


def address(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def unit_text(config):
    capability = "CAP_NET_BIND_SERVICE" if config["port"] < 1024 else ""
    return f"""{MARKER}
[Unit]
Description=Myownvpn secure server (protocol v{PROTOCOL})
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=myownvpn
Group=myownvpn
WorkingDirectory=/var/lib/myownvpn
ExecStart=/opt/myownvpn/current/venv/bin/python -I /opt/myownvpn/current/server/runtime.py
ExecReload=/usr/bin/python3 -I -c "import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGHUP)" $MAINPID
Restart=on-failure
RestartSec=3
TimeoutStopSec=15
KillSignal=SIGTERM
LoadCredential=access-key:/etc/myownvpn/credentials/access-key
LoadCredential=server-cert.pem:/etc/myownvpn/credentials/server-cert.pem
LoadCredential=server-key.pem:/etc/myownvpn/credentials/server-key.pem
StateDirectory=myownvpn
StateDirectoryMode=0700
LogsDirectory=myownvpn
LogsDirectoryMode=0700
UMask=0077
LimitCORE=0
LimitNOFILE=4096
TasksMax=256
MemoryMax=512M
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet={capability}
AmbientCapabilities={capability}
StandardOutput=journal
StandardError=journal
SyslogIdentifier=myownvpn

[Install]
WantedBy=multi-user.target
"""
