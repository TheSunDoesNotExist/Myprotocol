"""Required-ECH transport wrapper; existing inner TLS remains end-to-end."""

import argparse
import asyncio
import json
import logging
import os
import pathlib

from diagnostics import event

ROOT = pathlib.Path(__file__).resolve().parent
DEFAULT_BINARY = ROOT / ".local" / ("ech-gateway.exe" if os.name == "nt" else "ech-gateway")


def endpoint(value):
    host, port = value.rsplit(":", 1)
    if host.strip("[]") not in {"127.0.0.1", "::1"} or not 1 <= int(port) <= 65535:
        raise ValueError("invalid ECH loopback endpoint")
    return host.strip("[]"), int(port)


def address(value):
    host, port = value
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


class EchGateway:
    def __init__(self, process):
        self.process = process
        self.endpoints = {}
        self.logger = asyncio.create_task(self.logs())
        self.exited = asyncio.create_task(process.wait())

    @classmethod
    async def start(cls, config, *, binary=DEFAULT_BINARY, key=None):
        binary = pathlib.Path(binary).resolve()
        if not binary.is_file():
            raise RuntimeError("ECH backend is missing: build native/ first")
        env = os.environ.copy()
        if key is not None:
            env["MYVPN_KEY"] = key
        process = await asyncio.create_subprocess_exec(
            str(binary), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env=env, limit=16384,
            creationflags=0x08000000 if os.name == "nt" else 0)
        gateway = cls(process)
        try:
            process.stdin.write(json.dumps(config, separators=(",", ":")).encode() + b"\n")
            await process.stdin.drain()
            ready = json.loads(await asyncio.wait_for(process.stdout.readline(), 10))
            if not ready or set(ready) - {"tcp", "udp"}:
                raise ValueError("invalid ECH readiness")
            # Server addresses may be public; clients must only route through loopback.
            gateway.endpoints = {k: endpoint(v) for k, v in ready.items()} if config["mode"] == "client" else ready
            event("ech_backend_started", reason="ech_required")
            return gateway
        except BaseException as exc:
            await gateway.close()
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise RuntimeError("ECH backend failed to start; direct fallback is prohibited") from None

    async def logs(self):
        while line := await self.process.stderr.readline():
            try:
                record = json.loads(line)
                name = record.get("event")
                path, reason = record.get("path"), record.get("reason")
                if (name in {"ech_accepted", "ech_connection_failed", "ech_backend_failed"}
                        and path in {"", "tcp", "udp"}
                        and reason in {"verified", "ech_rejected", "certificate_verification_failed",
                                       "authentication_or_protocol_failed", "network_error",
                                       "configuration_or_runtime_error"}):
                    event(name, logging.INFO if name == "ech_accepted" else logging.WARNING,
                          path=path, reason=reason)
            except (ValueError, TypeError, AttributeError):
                # Never forward arbitrary native-library stderr to a log file.
                continue

    async def guard(self, operation):
        task = asyncio.ensure_future(operation)
        try:
            done, _ = await asyncio.wait((task, self.exited), return_when=asyncio.FIRST_COMPLETED)
            if self.exited in done:
                raise RuntimeError("ECH backend stopped; direct fallback is prohibited")
            return await task
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def close(self):
        if self.process.stdin:
            self.process.stdin.close()
        try:
            await asyncio.wait_for(asyncio.shield(self.exited), 3)
        except TimeoutError:
            self.process.kill()
            await self.exited
        finally:
            self.logger.cancel()
            await asyncio.gather(self.logger, return_exceptions=True)


async def keygen(args):
    directory = pathlib.Path(args.out).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    server, public = directory / "ech-keys.json", directory / "ech-config.bin"
    if server.exists() or public.exists():
        raise FileExistsError("refusing to overwrite ECH material")
    process = await asyncio.create_subprocess_exec(
        str(pathlib.Path(args.binary).resolve()), stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        creationflags=0x08000000 if os.name == "nt" else 0)
    config = dict(mode="keygen", public_name=args.public_name.encode("idna").decode("ascii"),
                  keys_file=str(server), config_file=str(public))
    try:
        await asyncio.wait_for(process.communicate(json.dumps(config).encode()), 10)
        if process.returncode:
            raise RuntimeError("ECH key generation failed")
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    print(f"Server private keys: {server}\nClient public config: {public}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create ECH material; send only ech-config.bin to clients")
    parser.add_argument("--public-name", required=True)
    parser.add_argument("--out", default=str(ROOT / ".local" / "ech"))
    parser.add_argument("--binary", default=str(DEFAULT_BINARY))
    asyncio.run(keygen(parser.parse_args()))
