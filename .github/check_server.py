"""Exercise only a disposable CI installation; never run against a real VPS."""
import asyncio
import contextlib
import io
import json
import os
import pathlib
import pwd
import shutil
import signal
import subprocess
import sys
from unittest.mock import patch

ROOT = pathlib.Path('/opt/myownvpn/current').resolve()
sys.path.insert(0, str(ROOT))
from server import admin, clients
from server.identity import health
from transports import quic_config, tls_client, shutdown_channels, SecurityError
from tunnel import Session, connect

ETC = pathlib.Path('/etc/myownvpn')
account = pwd.getpwnam('myownvpn')

def demote():
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)

async def until(condition):
    async with asyncio.timeout(8):
        while not condition():
            await asyncio.sleep(.03)

async def main():
    os.umask(0o077)
    registry = ETC / 'clients.json'
    assert registry.stat().st_uid == 0 and registry.stat().st_gid == account.pw_gid
    assert registry.stat().st_mode & 0o777 == 0o640
    first = clients.load(registry)['clients'][0]
    first_key = admin.client_key(first)
    with patch.object(admin, 'wait_clients'):
        second = admin.create_client('Debian second')
    second_key = admin.client_key(second)
    assert first_key != second_key
    health_key = (ETC / 'credentials/health-key').read_text().strip()
    assert health_key not in (first_key, second_key)
    for path in (ETC / 'credentials/health-key', ETC / 'credentials/clients' / first['id']):
        result = subprocess.run(['/usr/bin/python3', '-I', '-c', 'from pathlib import Path;Path(' + repr(str(path)) + ').read_bytes()'], preexec_fn=demote, capture_output=True)
        assert result.returncode != 0
    copied = pathlib.Path('/run/myownvpn-test-credentials')
    copied.mkdir(mode=0o700)
    for name, source in [('access-key', 'health-key'), ('server-cert.pem', 'server-cert.pem'), ('server-key.pem', 'server-key.pem')]:
        dest = copied / name
        shutil.copyfile(ETC / 'credentials' / source, dest)
        dest.chmod(0o600)
        os.chown(dest, account.pw_uid, account.pw_gid)
    os.chown(copied, account.pw_uid, account.pw_gid)
    echo_tasks = set()
    async def echo(reader, writer):
        task = asyncio.current_task()
        echo_tasks.add(task)
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except ConnectionError:
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            echo_tasks.discard(task)
    target = await asyncio.start_server(echo, '127.0.0.1', 9000)
    logs = pathlib.Path('/root/runtime-stderr.log').open('w')
    process = subprocess.Popen([str(ROOT / 'venv/bin/python'), '-I', str(ROOT / 'server/runtime.py')],
        env=dict(os.environ, CREDENTIALS_DIRECTORY=str(copied)), preexec_fn=demote, stdout=logs, stderr=logs)
    sessions, readers, local_servers, app_writers = [], [], [], []
    context = tls_client(ETC / 'ca-cert.pem')
    quic = quic_config(ca=ETC / 'ca-cert.pem', hostname='127.0.0.1')
    async def attach(key, kind):
        session = Session()
        sessions.append(session)
        reader, writer = await connect(session, ('127.0.0.1', 8443), key, context, '127.0.0.1', kind=kind, quic=quic)
        readers.append(asyncio.create_task(session.run_transport(reader, writer)))
        local = await asyncio.start_server(session.accept_local, '127.0.0.1', 0)
        local_servers.append(local)
        app_reader, app_writer = await asyncio.open_connection(*local.sockets[0].getsockname()[:2])
        app_writers.append(app_writer)
        return session, app_reader, app_writer
    try:
        await until(lambda: any(json.loads(line).get('event') == 'server_started' for line in pathlib.Path('/var/log/myownvpn/server.jsonl').read_text().splitlines()) if pathlib.Path('/var/log/myownvpn/server.jsonl').exists() else False)
        await health(ETC / 'server.json', ETC / 'credentials/health-key', ETC / 'ca-cert.pem')
        a, ar, aw = await attach(first_key, 'tcp')
        b, br, bw = await attach(second_key, 'udp')
        for reader, writer in ((ar, aw), (br, bw)):
            writer.write(b'X' * 65536)
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(65536), 5) == b'X' * 65536
        db = pathlib.Path('/var/lib/myownvpn/usage.sqlite')
        await until(lambda: clients.snapshot(db)[0].get(first['id']) == (65536, 65536))
        with patch.object(admin, 'wait_clients'), contextlib.redirect_stdout(io.StringIO()):
            admin.delete_client(first['id'])
        revision = clients.load(registry)['revision']
        await until(lambda: clients.snapshot(db)[2] == revision)
        for kind in ('tcp', 'udp'):
            trial = Session()
            sessions.append(trial)
            try:
                await connect(trial, ('127.0.0.1', 8443), first_key, context, '127.0.0.1', kind=kind, quic=quic)
            except SecurityError:
                pass
            else:
                raise AssertionError('deleted client accepted')
        bw.write(b'Y' * 65536)
        await bw.drain()
        assert await asyncio.wait_for(br.readexactly(65536), 5) == b'Y' * 65536
        await until(lambda: clients.snapshot(db)[0].get(second['id']) == (131072, 131072))
        entries = pathlib.Path('/var/log/myownvpn/server.jsonl').read_text()
        assert all(key not in entries for key in (first_key, second_key, health_key))
        assert 'client_revoked' in entries
        print('DEBIAN_UNPRIVILEGED_CLIENT_ACCESS_OK: 196608 bytes each direction; revoked TCP/UDP; other client intact; no keys in logs')
    finally:
        for writer in app_writers:
            writer.close()
        for session in sessions:
            session.close()
        for local in local_servers:
            local.close()
            await local.wait_closed()
        await asyncio.gather(*(s.wait_closed() for s in sessions), return_exceptions=True)
        for task in readers:
            task.cancel()
        await asyncio.gather(*readers, return_exceptions=True)
        process.send_signal(signal.SIGTERM)
        await asyncio.to_thread(process.wait, 10)
        assert process.returncode == 0, pathlib.Path('/root/runtime-stderr.log').read_text()
        logs.close()
        target.close()
        await target.wait_closed()
        for task in list(echo_tasks):
            task.cancel()
        await asyncio.gather(*echo_tasks, return_exceptions=True)
        await shutdown_channels()

asyncio.run(main())
