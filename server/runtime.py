"""Server-only systemd entry point; secrets arrive through LoadCredential."""

import asyncio
import os
import pathlib
import signal
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # -I; installed code is root-owned, never service-writable.

from diagnostics import configure, event
from server.config import ETC, PROTOCOL, load
from server import clients
from transports import quic_config, serve_tcp, serve_udp, shutdown_channels, tls_server
from tunnel import VERSION, Server


async def watch_clients(manager, registry, usage):
    revision = None
    invalid = False
    try:
        while True:
            try:
                data = clients.load(registry)
                allowed = {c["key_hash"]: c["id"] for c in data["clients"]}
                if invalid or revision != data["revision"] or manager.clients != allowed:
                    manager.set_clients(allowed)
                    revision, invalid = data["revision"], False
            except (OSError, ValueError):
                if not invalid:
                    manager.set_clients({})
                    event("client_registry_rejected", reason="invalid_or_missing", action="all_clients_disconnected")
                revision, invalid = None, True
            usage.flush(manager, revision)
            await asyncio.sleep(.5)
    finally:
        usage.flush(manager, revision)


async def serve(config_path=ETC / "server.json"):
    cfg = load(config_path)
    if VERSION != PROTOCOL:
        raise RuntimeError("Installed protocol and configuration versions differ")
    credentials = pathlib.Path(os.environ["CREDENTIALS_DIRECTORY"])
    key = (credentials / "access-key").read_text(encoding="ascii").strip()
    if len(key) != 64 or any(c not in "0123456789abcdefABCDEF" for c in key):
        raise ValueError("Invalid access-key credential")
    cert, private = credentials / "server-cert.pem", credentials / "server-key.pem"
    manager = Server(key, tuple(cfg["target"]), cfg["grace"], srtl=cfg["srtl"])
    registry = pathlib.Path(config_path).parent / "clients.json"
    data = clients.load(registry)  # No legacy fallback if the allowlist disappears.
    manager.set_clients({c["key_hash"]: c["id"] for c in data["clients"]})
    usage = clients.Usage("/var/lib/myownvpn/usage.sqlite")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    def reload_srtl():
        try:
            updated = load(config_path)
            if any(updated[k] != cfg[k] for k in cfg if k != "srtl"):
                event("configuration_reload_rejected", reason="restart_required")
                return
            manager.set_srtl(updated["srtl"])
            cfg["srtl"] = updated["srtl"]
            event("srtl_reloaded", srtl=cfg["srtl"])
        except (OSError, ValueError):
            event("configuration_reload_rejected", reason="invalid_configuration")

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    loop.add_signal_handler(signal.SIGHUP, reload_srtl)
    tcp = udp = None
    udp_tasks = set()
    acceptor = waiter = monitor = None
    try:
        tcp = await serve_tcp(manager, (cfg["listen"], cfg["port"]), tls_server(cert, private))
        if cfg["transport"] != "tcp":
            udp, udp_tasks = await serve_udp(manager, (cfg["listen"], cfg["port"]), quic_config(cert=cert, key=private))
        event("server_started", mode=cfg["transport"], srtl=cfg["srtl"], tls="TLSv1.3")
        acceptor = asyncio.create_task(tcp.serve_forever())
        waiter = asyncio.create_task(stop.wait())
        monitor = asyncio.create_task(watch_clients(manager, registry, usage))
        done, _ = await asyncio.wait((acceptor, waiter, monitor), return_when=asyncio.FIRST_COMPLETED)
        if monitor in done:
            await monitor  # Accounting/registry-monitor failure closes the server.
        if acceptor in done:
            await acceptor
    finally:
        manager.close()
        if tcp:
            tcp.close()
            await tcp.wait_closed()
        if udp:
            await udp.aclose()
        for task in [*udp_tasks, *[t for t in (acceptor, waiter, monitor) if t]]:
            task.cancel()
        await asyncio.gather(*udp_tasks, *[t for t in (acceptor, waiter, monitor) if t], return_exceptions=True)
        await manager.wait_closed()
        await shutdown_channels()
        usage.flush(manager, None)
        usage.close()


if __name__ == "__main__":
    configure(filename="/var/log/myownvpn/server.jsonl", role="server")
    asyncio.run(serve())
