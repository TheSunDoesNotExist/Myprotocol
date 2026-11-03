"""Root-managed hash allowlist and service-owned cumulative payload accounting."""

import contextlib
import hashlib
import json
import os
import pathlib
import secrets
import sqlite3
import time

MAX_CLIENTS = 256


def digest(key):
    if not isinstance(key, str) or len(key) != 64 or any(c not in "0123456789abcdefABCDEF" for c in key):
        raise ValueError("Неверный ключ клиента")
    return hashlib.sha256(key.encode("ascii")).hexdigest()


def validate(data):
    if (not isinstance(data, dict) or set(data) != {"schema", "revision", "clients"}
            or type(data["schema"]) is not int or data["schema"] != 1
            or not isinstance(data["revision"], str) or len(data["revision"]) != 32
            or any(c not in "0123456789abcdef" for c in data["revision"])
            or not isinstance(data["clients"], list) or len(data["clients"]) > MAX_CLIENTS):
        raise ValueError("Неверный реестр клиентов")
    ids, hashes = set(), set()
    for client in data["clients"]:
        if (not isinstance(client, dict) or set(client) != {"id", "name", "key_hash", "created"}
                or not isinstance(client["id"], str) or len(client["id"]) != 24
                or any(c not in "0123456789abcdef" for c in client["id"])
                or not isinstance(client["name"], str) or not 1 <= len(client["name"]) <= 80
                or not all(c.isprintable() for c in client["name"])
                or not isinstance(client["key_hash"], str) or len(client["key_hash"]) != 64
                or any(c not in "0123456789abcdef" for c in client["key_hash"])
                or type(client["created"]) is not int or client["created"] < 0
                or client["id"] in ids or client["key_hash"] in hashes):
            raise ValueError("Повреждённая или повторяющаяся запись клиента")
        ids.add(client["id"])
        hashes.add(client["key_hash"])
    return data


def load(path):
    path = pathlib.Path(path)
    if path.is_symlink():
        raise ValueError("Реестр клиентов не должен быть ссылкой")
    with path.open(encoding="utf-8") as source:
        raw = source.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        raise ValueError("Реестр клиентов слишком большой")
    try:
        return validate(json.loads(raw))
    except (RecursionError, TypeError):
        raise ValueError("Неверный реестр клиентов") from None


def empty():
    return dict(schema=1, revision=secrets.token_hex(16), clients=[])


def record(name, key):
    client = dict(id=secrets.token_hex(12), name=name, key_hash=digest(key), created=int(time.time()))
    validate(dict(empty(), clients=[client]))
    return client


@contextlib.contextmanager
def locked(etc):
    # Administrative mutations are serialized; the daemon only reads atomic replacements.
    import fcntl
    fd = os.open(pathlib.Path(etc) / ".clients.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


class Usage:
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=2)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS usage (id TEXT PRIMARY KEY, uploaded INTEGER NOT NULL, downloaded INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS live (id TEXT PRIMARY KEY, sessions INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision TEXT, updated REAL)")
        self.db.commit()

    def flush(self, manager, revision):
        manager.collect_usage()
        active = {}
        for session in manager.sessions.values():
            if not session.closed and session.writer is not None:
                identity = session.client_id
                active[identity] = active.get(identity, 0) + 1
        with self.db:
            for identity, (up, down) in manager.usage.items():
                self.db.execute("INSERT INTO usage VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET uploaded=uploaded+excluded.uploaded, downloaded=downloaded+excluded.downloaded", (identity, up, down))
            self.db.execute("DELETE FROM live")
            self.db.executemany("INSERT INTO live VALUES (?, ?)", active.items())
            self.db.execute("INSERT OR REPLACE INTO state VALUES (1, ?, ?)", (revision, time.time()))
        manager.usage.clear()

    def close(self):
        self.db.close()


def snapshot(path):
    if not pathlib.Path(path).is_file():
        return {}, {}, None, 0
    # Read-only connection: displaying clients never creates a database.
    db = sqlite3.connect(pathlib.Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
    try:
        with db:
            usage = {identity: (up, down) for identity, up, down in db.execute("SELECT * FROM usage")}
            active = dict(db.execute("SELECT * FROM live"))
            state = db.execute("SELECT revision, updated FROM state WHERE singleton=1").fetchone()
        return usage, active, *(state or (None, 0))
    finally:
        db.close()
