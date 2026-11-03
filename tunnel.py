"""Resumable port forwarder over authenticated TLS/TCP or QUIC/UDP."""

import argparse
import asyncio
import base64
import contextlib
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import socket
import struct
import time

from diagnostics import configure, event, tag
from selection import Selector
from transports import (ALPN, AUTH_TIMEOUT, SecurityError, open_channel, quic_config, serve_tcp, serve_udp,
                        shutdown_channels, tls_client, tls_server)
from http_carrier import accept_http
from ech_gateway import DEFAULT_BINARY, EchGateway, address as format_address
from srtl import (SRTL, COVER_SIZES, MAX_PADDING, TAIL_COOLDOWN, TAIL_MAX_BYTES,
                  TAIL_QUIET, collect)

CHUNK = 16 * 1024
MAX_FRAME = 32 * 1024
QUEUE = 64
FRAME_WINDOW = 16
STREAM_WINDOW = 64 * 1024
MAX_STREAMS = 128  # Includes closed streams: bounded deduplication tombstones.
MAX_SESSIONS = 16
HEARTBEAT = 1.0
DEAD_TRANSPORT = 4.0
VERSION = 5


class ProtocolError(Exception):
    pass


class SupersededError(ConnectionError):
    pass


def integer(value, minimum=0):
    if type(value) is not int or not minimum <= value < 2**63:
        raise ProtocolError("invalid integer")
    return value


async def read_frame(reader):
    size = struct.unpack("!I", await reader.readexactly(4))[0]
    if not 0 < size <= MAX_FRAME:
        raise ProtocolError("frame too large or empty")
    try:
        data = await reader.readexactly(size)
        if len(data) - len(data.rstrip(b" \t\r\n")) > MAX_PADDING:
            raise ProtocolError("padding limit exceeded")
        frame = json.loads(data)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("invalid JSON") from exc
    if not isinstance(frame, dict) or not isinstance(frame.get("type"), str):
        raise ProtocolError("invalid frame")
    if frame["type"] == "cover":
        if set(frame) != {"type"} or size + 4 not in COVER_SIZES:
            raise ProtocolError("invalid SRTL cover")
        frame["_wire_size"] = size + 4  # Locally measured, never trusted from JSON.
    return frame


async def write_frame(writer, frame, *, srtl=None):
    data = json.dumps(frame, separators=(",", ":")).encode()
    if srtl is not None:
        data = srtl.pad(frame, data)
    if len(data) > MAX_FRAME:
        raise ProtocolError("frame too large")
    # One synchronous write prevents interleaving heartbeat and data records.
    writer.write(struct.pack("!I", len(data)) + data)
    await asyncio.wait_for(writer.drain(), 5)
    return len(data) + 4


def abort(writer):
    if writer is not None:
        writer.transport.abort()


def reset_application(writer):
    """Abort failed application TCP streams with RST, never an ordinary FIN."""
    if writer is None:
        return
    raw = None
    if not getattr(writer, "is_closing", lambda: False)():
        sock = getattr(writer, "get_extra_info", lambda name: None)("socket")
        if sock:
            try:
                # Windows uses two unsigned shorts; POSIX uses two ints.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack("HH" if os.name == "nt" else "ii", 1, 0))
                # asyncio's normal close path calls shutdown() before close(),
                # which can emit FIN. Close the owned socket abortively after
                # cancelling transport I/O and before that scheduled callback.
                raw = getattr(sock, "_sock", sock)
            except OSError:
                event("application_reset_failed", logging.ERROR, reason="socket_option_failed")
    abort(writer)
    if raw:
        raw.close()


class Stream:
    def __init__(self, session, sid, reader=None, writer=None):
        self.session, self.sid = session, sid
        self.reader, self.writer = reader, writer
        self.tx = self.rx = 0
        self.local_fin = self.remote_fin = self.reset = False
        self.fin_delivered = False
        self.tx_limit = STREAM_WINDOW
        self.rx_delivered = 0
        self.rx_buffer = bytearray()
        self.readable = asyncio.Event()
        self.writable = asyncio.Event()
        self.ready = asyncio.Event()
        if writer is not None:
            self.ready.set()
        self.task = None
        self.reporter = None
        self.delivery = self.connector = None

    def start(self):
        self.task = asyncio.create_task(self.pump())

    async def open_target(self):
        try:
            async with asyncio.timeout(5):
                reader, writer = await asyncio.open_connection(*self.session.target, limit=CHUNK)
            if self.reset or self.session.closed:
                reset_application(writer)
                return
            self.reader, self.writer = reader, writer
            self.ready.set()
            self.start()
        except (OSError, TimeoutError):
            self.fail()

    def wake_delivery(self):
        if self.delivery is None:
            self.delivery = asyncio.create_task(self.deliver_to_socket())
        self.readable.set()

    async def deliver_to_socket(self):
        try:
            await self.ready.wait()
            while not self.reset:
                await self.readable.wait()
                self.readable.clear()
                while self.rx_buffer and not self.reset:
                    chunk = bytes(self.rx_buffer[:CHUNK])
                    self.writer.write(chunk)
                    await self.writer.drain()
                    del self.rx_buffer[:len(chunk)]
                    self.rx_delivered += len(chunk)
                    self.session.advertise_window(self)
                if self.remote_fin and not self.reset:
                    self.writer.write_eof()
                    await self.writer.drain()
                    self.fin_delivered = True
                    self.finish()
                    return
        except (OSError, ConnectionError):
            self.fail()

    async def pump(self):
        try:
            while not self.session.closed and not self.reset:
                while self.tx >= self.tx_limit:
                    self.writable.clear()
                    await self.writable.wait()
                data = await self.reader.read(min(CHUNK, self.tx_limit - self.tx))
                if data and self.session.srtl.enabled and len(data) < min(CHUNK, self.tx_limit - self.tx):
                    data = await collect(self.reader, data, min(CHUNK, self.tx_limit - self.tx), self.session.srtl)
                if self.reset:
                    return
                if not data:
                    await self.session.enqueue("fin", self.sid, offset=self.tx)
                    self.local_fin = True
                    self.finish()
                    return
                await self.session.enqueue("data", self.sid, offset=self.tx,
                                           data=base64.b64encode(data).decode())
                self.tx += len(data)
        except (ConnectionError, OSError):
            self.fail()

    def fail(self):
        if self.reset:
            return
        self.stop()
        event("stream_failed", logging.WARNING, session=tag(self.session.sid), stream=self.sid,
              reason="socket_error")

        async def report():
            with contextlib.suppress(ConnectionError):
                await self.session.enqueue("reset", self.sid)

        # Delivery must never wait for a full outbound queue to report a failure:
        # both peers could otherwise wait for each other's ACK indefinitely.
        self.reporter = asyncio.create_task(report())

    def finish(self):
        if self.local_fin and self.fin_delivered:
            self.writer.close()
            self.reader = self.writer = None

    def stop(self):
        self.reset = True
        reset_application(self.writer)
        self.reader = self.writer = None
        self.rx_buffer.clear()
        for task in (self.task, self.delivery, self.connector):
            if task and task is not asyncio.current_task():
                task.cancel()

    async def wait_closed(self):
        tasks = [t for t in (self.task, self.delivery, self.connector, self.reporter)
                 if t and t is not asyncio.current_task()]
        await asyncio.gather(*tasks, return_exceptions=True)


class Session:
    def __init__(self, *, target=None, grace=30, srtl=False):
        self.target, self.grace = target, grace
        self.sid, self.secret = secrets.token_hex(16), secrets.token_hex(32)
        self.transport_id = None
        self.writer = None
        self.closed = False
        self.reason = None
        self.generation = 0
        self.next_generation = 0
        self.path = None
        self.tx_bytes = self.rx_bytes = self.replayed = 0
        self.pings = {}
        self.rtt_ms = None
        self.last_metrics = time.monotonic()
        self.detached_at = time.monotonic()
        self.last_seen = time.monotonic()
        self.streams = {}
        self.next_stream = 1
        self.tx_seq = self.rx_seq = 0
        self.tx_acked = self.rx_enqueued = 0
        self.last_ack = None
        self.pending = asyncio.Queue(QUEUE)
        self.space = asyncio.Event()
        self.inflight = {}
        self.ever_sent = set()
        self.sent_on = {}
        self.windows = {}
        self.rx_queue = asyncio.Queue(FRAME_WINDOW)
        self.incoming = None
        self.ack_sender = None
        self.srtl = SRTL(srtl)
        self.srtl_changed = asyncio.Event()
        self.data_sends = 0
        self.changed = asyncio.Event()
        self.sender = asyncio.create_task(self.send_loop())
        self.timer = asyncio.create_task(self.watchdog())
        self.shaping = asyncio.create_task(self.srtl_loop())
        event("srtl_configured", session=tag(self.sid), srtl=srtl)

    def set_srtl(self, enabled):
        if type(enabled) is not bool:
            raise ValueError("SRTL requires a boolean")
        self.srtl.enabled = enabled
        self.srtl.credit = 0
        self.srtl.last_seq = max(self.srtl.last_seq, self.tx_seq)
        self.srtl.last_data = 0
        self.srtl_changed.set()
        event("srtl_configured", session=tag(self.sid), srtl=enabled)

    async def wait_srtl_change(self, delay):
        try:
            async with asyncio.timeout(max(0, delay)):
                await self.srtl_changed.wait()
        except TimeoutError:
            return False
        self.srtl_changed.clear()
        return True

    def can_cover(self, writer):
        return (self.writer is writer and writer is not None and self.srtl.enabled
                and not self.closed and not self.data_sends and self.pending.empty() and not self.windows
                and all(self.sent_on.get(seq) == self.transport_id for seq in self.inflight)
                and getattr(writer.transport, "get_write_buffer_size", lambda: 0)() < 16 * 1024)

    async def srtl_loop(self):
        while not self.closed:
            await self.srtl_changed.wait()
            self.srtl_changed.clear()
            while self.srtl.enabled and self.writer is not None and self.srtl.last_data:
                last_data = self.srtl.last_data
                if await self.wait_srtl_change(last_data + TAIL_QUIET - time.monotonic()):
                    continue
                writer = self.writer
                if (last_data != self.srtl.last_data or time.monotonic() < self.srtl.next_tail
                        or not self.can_cover(writer)):
                    break
                remaining = TAIL_MAX_BYTES
                for _ in range(4 + secrets.randbelow(5)):
                    if await self.wait_srtl_change(0.075 + secrets.randbelow(101) / 1000):
                        # Preserve the newest DATA notification when this tail
                        # is interrupted. A cancelled, unsent tail costs no quota.
                        self.srtl_changed.set()
                        break
                    if not self.can_cover(writer) or remaining < max(COVER_SIZES):
                        break
                    size = await self.send(dict(type="cover"))
                    if not size:
                        break
                    if remaining == TAIL_MAX_BYTES:
                        self.srtl.next_tail = time.monotonic() + TAIL_COOLDOWN
                    remaining -= size
                    self.srtl.cover_tx += 1
                    self.srtl.cover_bytes_tx += size
                break

    @property
    def current(self):
        return next(iter(self.inflight.values()), None)

    def advertise_window(self, stream):
        if not self.closed and not stream.reset:
            self.windows[stream.sid] = stream.rx_delivered + STREAM_WINDOW
            self.changed.set()

    def receive_window(self, frame):
        sid = integer(frame.get("stream"), 1)
        limit = integer(frame.get("limit"))
        stream = self.streams.get(sid)
        if stream is None or limit < STREAM_WINDOW or limit > stream.tx + STREAM_WINDOW:
            raise ProtocolError("invalid stream credit")
        if limit > stream.tx_limit:
            stream.tx_limit = limit
            stream.writable.set()
            event("stream_credit", logging.DEBUG, session=tag(self.sid), stream=sid, limit=limit)

    async def enqueue(self, kind, sid, **fields):
        if self.closed:
            raise ConnectionError("session closed")
        # Wait without blocking ACK processing or transport recovery.
        while self.pending.full():
            self.space.clear()
            await self.space.wait()
            if self.closed:
                raise ConnectionError("session closed")
        self.pending.put_nowait(dict(type=kind, stream=sid, **fields))
        self.changed.set()

    def attach(self, writer, transport_id):
        if self.closed:
            raise ProtocolError("session expired")
        downtime = (time.monotonic() - self.detached_at) * 1000 if self.detached_at else 0
        previous = self.path
        abort(self.writer)
        self.writer, self.transport_id = writer, transport_id
        self.path = getattr(writer, "kind", "tcp")
        self.detached_at = None
        self.last_seen = time.monotonic()
        self.sent_on.clear()
        for stream in self.streams.values():
            if stream.rx_delivered:
                self.advertise_window(stream)
        self.pings.clear()
        self.srtl.last_data = 0
        self.srtl_changed.set()
        self.changed.set()
        event("transport_attached", session=tag(self.sid), transport=transport_id,
              path=self.path, previous=previous, downtime_ms=round(downtime, 2),
              generation=self.generation, resumed=self.tx_seq > 0 or self.rx_seq > 0,
              srtl=self.srtl.enabled)

    def detach(self, writer, reason="connection_lost"):
        if writer is not None and self.writer is writer:
            abort(writer)
            self.writer = None
            self.detached_at = time.monotonic()
            self.srtl.last_data = 0
            self.srtl_changed.set()
            self.changed.set()
            event("transport_lost", logging.WARNING, session=tag(self.sid),
                  transport=self.transport_id, path=self.path, reason=reason,
                  queued=self.pending.qsize())

    async def send(self, frame):
        writer = self.writer
        if writer is None:
            return 0
        if frame["type"] == "cover" and not self.srtl.enabled:
            return 0
        data = frame["type"] == "data"
        if data:
            self.data_sends += 1
        try:
            size = await write_frame(writer, frame, srtl=self.srtl) if self.srtl.enabled else await write_frame(writer, frame)
            if data and self.writer is writer and self.srtl.enabled:
                self.srtl.last_data = time.monotonic()
                self.srtl_changed.set()
            return size
        except (ConnectionError, OSError, TimeoutError):
            self.detach(writer, "write_failed")
            return 0
        finally:
            if data:
                self.data_sends -= 1

    async def send_loop(self):
        while not self.closed:
            await self.changed.wait()
            self.changed.clear()
            for sid, limit in list(self.windows.items()):
                writer = self.writer
                if writer is None:
                    break
                await self.send(dict(type="window", stream=sid, limit=limit))
                if self.writer is writer and self.windows.get(sid) == limit:
                    del self.windows[sid]
            while len(self.inflight) < FRAME_WINDOW and not self.pending.empty():
                self.tx_seq += 1
                self.inflight[self.tx_seq] = dict(self.pending.get_nowait(), seq=self.tx_seq)
                self.space.set()
            for seq, frame in list(self.inflight.items()):
                if self.writer is None:
                    break
                if seq not in self.inflight or self.sent_on.get(seq) == self.transport_id:
                    continue
                self.sent_on[seq] = self.transport_id
                if seq in self.ever_sent:
                    self.replayed += 1
                    event("frame_replayed", session=tag(self.sid), path=self.path,
                          seq=seq, stream=frame["stream"])
                self.ever_sent.add(seq)
                event("frame_sent", logging.DEBUG, session=tag(self.sid), path=self.path,
                      seq=seq, stream=frame["stream"], offset=frame.get("offset", 0))
                await self.send(frame)

    async def watchdog(self):
        while not self.closed:
            await asyncio.sleep(min(HEARTBEAT, self.grace / 4))
            now = time.monotonic()
            if self.writer:
                if now - self.last_seen > DEAD_TRANSPORT:
                    self.detach(self.writer, "heartbeat_timeout")
                else:
                    nonce = secrets.token_hex(8)
                    self.pings[nonce] = now
                    self.pings = {n: sent for n, sent in self.pings.items()
                                  if now - sent <= DEAD_TRANSPORT}
                    await self.send(dict(type="ping", nonce=nonce))
            if now - self.last_metrics >= 5:
                self.last_metrics = now
                event("session_metrics", session=tag(self.sid), path=self.path,
                      tx_seq=self.tx_seq, rx_seq=self.rx_seq, queued=self.pending.qsize(),
                      inflight=len(self.inflight), rx_queued=self.rx_queue.qsize(),
                      buffered_bytes=sum(len(s.rx_buffer) for s in self.streams.values()),
                      delivered_bytes=sum(s.rx_delivered for s in self.streams.values()),
                      credit_blocked_streams=sum(not s.reset and not s.local_fin and s.tx >= s.tx_limit
                                                 for s in self.streams.values()),
                      tx_bytes=self.tx_bytes, rx_bytes=self.rx_bytes, replayed=self.replayed,
                      srtl=self.srtl.enabled, srtl_padding_bytes=self.srtl.padding_bytes,
                      srtl_merged_reads=self.srtl.merged_reads,
                      srtl_cover_tx=self.srtl.cover_tx, srtl_cover_rx=self.srtl.cover_rx,
                      srtl_cover_bytes_tx=self.srtl.cover_bytes_tx, srtl_cover_bytes_rx=self.srtl.cover_bytes_rx,
                      rtt_ms=self.rtt_ms,
                      active_streams=sum(not s.reset and not (s.local_fin and s.remote_fin)
                                         for s in self.streams.values()))
            if self.detached_at is not None and now - self.detached_at >= self.grace:
                self.close("resume deadline expired")

    async def run_transport(self, reader, writer):
        try:
            while not self.closed and self.writer is writer:
                frame = await asyncio.wait_for(read_frame(reader), DEAD_TRANSPORT)
                if self.writer is not writer:  # Fence superseded transport readers.
                    break
                kind = frame["type"]
                if kind == "cover":
                    if not self.srtl.accept_cover(frame["_wire_size"]):
                        raise ProtocolError("SRTL cover budget exceeded")
                    # Cover is neither heartbeat nor a reliable event. No ACK/echo.
                    continue
                self.last_seen = time.monotonic()
                if kind == "ping":
                    nonce = frame.get("nonce")
                    if not isinstance(nonce, str) or len(nonce) != 16:
                        raise ProtocolError("invalid ping")
                    await self.send(dict(type="pong", nonce=nonce))
                elif kind == "pong":
                    nonce = frame.get("nonce")
                    if not isinstance(nonce, str):
                        raise ProtocolError("invalid pong")
                    sent = self.pings.pop(nonce, None)
                    if sent is not None:
                        self.rtt_ms = round((time.monotonic() - sent) * 1000, 2)
                    continue
                elif kind == "ack":
                    self.acknowledge(frame)
                elif kind == "window":
                    self.receive_window(frame)
                else:
                    self.receive(frame)
        except TimeoutError:
            self.detach(writer, "read_timeout")
        except asyncio.IncompleteReadError:
            self.detach(writer, "peer_eof")
        except (ConnectionError, OSError):
            self.detach(writer, "read_error")
        except ProtocolError as exc:
            self.close(str(exc))
        finally:
            self.detach(writer)
            abort(writer)

    def acknowledge(self, frame):
        seq = integer(frame.get("seq"), 1)
        if seq > self.tx_seq:
            raise ProtocolError("ACK beyond sent sequence")
        if seq > self.tx_acked:
            acknowledged = self.inflight.get(seq)
            if acknowledged is None or seq not in self.ever_sent:
                raise ProtocolError("ACK for unsent record")
            integer(frame.get("stream"), 1)
            integer(frame.get("offset"))
            expected = acknowledged.get("offset", 0)
            if acknowledged["type"] == "data":
                expected += len(base64.b64decode(acknowledged["data"]))
            if frame.get("stream") != acknowledged["stream"] or frame.get("offset") != expected:
                raise ProtocolError("ACK stream/offset mismatch")
            for pending_seq in list(self.inflight):
                if pending_seq <= seq:
                    record = self.inflight.pop(pending_seq)
                    if record["type"] == "data":
                        self.tx_bytes += len(base64.b64decode(record["data"]))
                    self.sent_on.pop(pending_seq, None)
                    self.ever_sent.discard(pending_seq)
            self.tx_acked = seq
            event("frame_acked", logging.DEBUG, session=tag(self.sid), path=self.path,
                  seq=seq, stream=frame["stream"], offset=expected)
            self.changed.set()

    def receive(self, frame):
        if frame["type"] not in {"open", "data", "fin", "reset"}:
            raise ProtocolError("unknown message")
        seq = integer(frame.get("seq"), 1)
        integer(frame.get("stream"), 1)
        if seq <= self.rx_seq:
            event("duplicate_discarded", logging.DEBUG, session=tag(self.sid),
                  seq=seq, stream=frame["stream"])
            # Old records cannot reach the socket again, including OPEN and FIN.
            if self.ack_sender is None or self.ack_sender.done():
                self.ack_sender = asyncio.create_task(self.send(self.last_ack))
        elif seq <= self.rx_enqueued:
            return  # Already queued or being applied by the session worker.
        elif seq != self.rx_enqueued + 1:
            raise ProtocolError("sequence gap")
        else:
            if self.rx_queue.full():
                raise ProtocolError("reliable receive window exceeded")
            self.rx_enqueued = seq
            self.rx_queue.put_nowait(frame)
            if self.incoming is None:
                # This bounded worker survives transport replacement.
                self.incoming = asyncio.create_task(self.deliver())

    async def deliver(self):
        try:
            while not self.closed:
                frame = await self.rx_queue.get()
                offset = await self.apply(frame)
                self.rx_seq = frame["seq"]
                self.last_ack = dict(type="ack", seq=self.rx_seq,
                                     stream=frame["stream"], offset=offset)
                await self.send(self.last_ack)
        except (ProtocolError, ValueError) as exc:
            self.close(str(exc))

    async def apply(self, frame):
        kind, sid = frame["type"], frame["stream"]
        stream = self.streams.get(sid)
        if kind == "open":
            if self.target is None or stream or len(self.streams) >= MAX_STREAMS:
                raise ProtocolError("invalid OPEN or stream limit exceeded")
            stream = self.streams[sid] = Stream(self, sid)
            event("stream_opened", session=tag(self.sid), stream=sid)
            stream.connector = asyncio.create_task(stream.open_target())
            return 0
        if stream is None:
            raise ProtocolError("unknown stream")
        if kind == "reset":
            event("stream_reset", logging.WARNING, session=tag(self.sid), stream=sid,
                  reason="peer_socket_error")
            stream.stop()
            return 0
        offset = integer(frame.get("offset"))
        if offset != stream.rx or stream.remote_fin:
            raise ProtocolError("stream offset mismatch or data after FIN")
        if kind == "data":
            encoded = frame.get("data")
            if not isinstance(encoded, str):
                raise ProtocolError("invalid data")
            data = base64.b64decode(encoded, validate=True)
            if not 0 < len(data) <= CHUNK:
                raise ProtocolError("invalid data size")
            if not stream.reset:
                if stream.rx + len(data) > stream.rx_delivered + STREAM_WINDOW:
                    raise ProtocolError("stream receive credit exceeded")
                stream.rx_buffer.extend(data)
                stream.wake_delivery()
            stream.rx += len(data)
            self.rx_bytes += len(data)
        elif kind == "fin":
            event("stream_half_closed", logging.DEBUG, session=tag(self.sid), stream=sid,
                  offset=offset)
            stream.remote_fin = True
            if not stream.reset:
                stream.wake_delivery()
        return stream.rx

    async def accept_local(self, reader, writer):
        if self.closed or len(self.streams) >= MAX_STREAMS:
            event("stream_rejected", logging.WARNING, session=tag(self.sid),
                  reason="session_closed_or_stream_limit")
            reset_application(writer)
            return
        sid = self.next_stream
        self.next_stream += 1
        stream = self.streams[sid] = Stream(self, sid, reader, writer)
        event("stream_opened", session=tag(self.sid), stream=sid)
        try:
            await self.enqueue("open", sid)
            if not self.closed:
                stream.start()
        except ConnectionError:
            stream.stop()

    def close(self, reason="shutdown"):
        if self.closed:
            return
        self.closed = True
        self.reason = reason
        event("session_closed", logging.WARNING, session=tag(self.sid), reason=reason,
              tx_bytes=self.tx_bytes, rx_bytes=self.rx_bytes, replayed=self.replayed)
        abort(self.writer)
        self.writer = None
        for stream in self.streams.values():
            stream.stop()
            if stream.reporter:
                stream.reporter.cancel()
        for task in (self.sender, self.timer, self.incoming, self.ack_sender, self.shaping):
            if task and task is not asyncio.current_task():
                task.cancel()
        self.inflight.clear()
        self.ever_sent.clear()
        self.sent_on.clear()
        self.windows.clear()
        for queue in (self.pending, self.rx_queue):
            while not queue.empty():
                queue.get_nowait()
        self.changed.set()
        self.space.set()

    async def wait_closed(self):
        tasks = [t for t in (self.sender, self.timer, self.incoming, self.ack_sender, self.shaping)
                 if t and t is not asyncio.current_task()]
        await asyncio.gather(*tasks, *(stream.wait_closed() for stream in self.streams.values()),
                             return_exceptions=True)


class Server:
    def __init__(self, key, target, grace=30, *, srtl=False):
        self.key, self.target, self.grace = key, target, grace
        self.srtl = srtl
        self.sessions = {}
        self.connections = {}
        self.closed = False
        self.clients = None  # None retains the standalone CLI's single-key mode.
        self.usage = {}

    def authenticate(self, key, *, probe=True):
        if not isinstance(key, str) or len(key) != 64 or not key.isascii():
            return None
        if self.clients is None:
            return "legacy" if hmac.compare_digest(key, self.key) else None
        identity = self.clients.get(hashlib.sha256(key.encode("ascii")).hexdigest())
        if identity is not None:
            return identity
        # The installation credential may check health, but can never open a session.
        if probe and hmac.compare_digest(key, self.key):
            return "__health__"
        return None

    def collect_usage(self):
        for session in self.sessions.values():
            identity = getattr(session, "client_id", None)
            if identity is None:
                continue
            previous = getattr(session, "accounted", (0, 0))
            current = session.rx_bytes, session.tx_bytes
            totals = self.usage.setdefault(identity, [0, 0])
            totals[0] += current[0] - previous[0]
            totals[1] += current[1] - previous[1]
            session.accounted = current

    def set_clients(self, clients):
        """Replace the hash->identity allowlist atomically in the event loop."""
        self.collect_usage()
        old = self.clients or {}
        self.clients = dict(clients)
        for session in self.sessions.values():
            digest = getattr(session, "client_digest", None)
            if digest is not None and clients.get(digest) != session.client_id:
                session.close("client_revoked")
        event("client_access_updated", clients=len(clients), revoked=len(set(old) - set(clients)))

    def set_srtl(self, enabled):
        if type(enabled) is not bool:
            raise ValueError("SRTL requires a boolean")
        self.srtl = enabled
        for session in self.sessions.values():
            if not session.closed:
                session.set_srtl(enabled)

    async def accept(self, reader, writer):
        probing = False
        new_session = None
        committed = False
        task = asyncio.current_task()
        self.connections[task] = writer
        try:
            if self.closed:
                return
            protocol = getattr(writer, "protocol", None)
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None and not (
                    protocol and protocol.handshake_complete and not protocol.security_failure):
                raise SecurityError("unencrypted channel rejected")
            if ssl_object and (ssl_object.version() != "TLSv1.3"
                               or ssl_object.selected_alpn_protocol() != ALPN):
                raise SecurityError("TLS security policy")
            kind = getattr(writer, "kind", "tcp")
            if ssl_object is not None:
                deadline = getattr(writer, "auth_deadline", asyncio.get_running_loop().time() + AUTH_TIMEOUT)
                async with asyncio.timeout_at(deadline):
                    if not getattr(writer, "carrier_ready", False):
                        if not await accept_http(reader, writer, self.authenticate):
                            return
                writer.authenticated = True
            event("secure_connection", path=kind, tls="TLSv1.3",
                  carrier=("ech-" if getattr(writer, "ech", False) else "") +
                          ("https-connect" if kind == "tcp" else "http3-connect"),
                  cipher=ssl_object.cipher()[0] if ssl_object else protocol.cipher)
            for _ in range(4):
                hello = await asyncio.wait_for(read_frame(reader), 5)
                key = hello.get("key")
                client_id = self.authenticate(key, probe=hello.get("type") == "probe")
                if (hello["type"] not in {"hello", "probe"} or hello.get("version") != VERSION
                        or client_id is None):
                    await write_frame(writer, dict(type="rejected"))
                    raise SecurityError("authentication_failed")
                if protocol:
                    protocol.mark_authenticated()
                if hello["type"] == "hello":
                    break
                probing = True
                nonce = hello.get("nonce")
                if not isinstance(nonce, str) or len(nonce) != 32:
                    raise ProtocolError("invalid probe")
                await write_frame(writer, dict(type="probe_ok", nonce=nonce, version=VERSION))
            else:
                return
            generation = integer(hello.get("generation"), 1)
            self.collect_usage()
            self.sessions = {sid: s for sid, s in self.sessions.items() if not s.closed}
            sid = hello.get("session")
            if sid is None:
                if len(self.sessions) >= MAX_SESSIONS:
                    raise ProtocolError("session limit reached")
                session = Session(target=self.target, grace=self.grace, srtl=self.srtl)
                session.client_id = client_id
                session.client_digest = hashlib.sha256(key.encode("ascii")).hexdigest()
                self.sessions[session.sid] = session
                new_session = session
            else:
                if not isinstance(sid, str):
                    raise ProtocolError("invalid session ID")
                session = self.sessions.get(sid)
                secret = hello.get("secret")
                if (session is None or getattr(session, "client_id", None) != client_id
                        or (session.detached_at is not None
                        and time.monotonic() - session.detached_at >= session.grace)
                        or not isinstance(secret, str) or not secret.isascii()
                        or not hmac.compare_digest(secret, session.secret)):
                    await write_frame(writer, dict(type="expired"))
                    event("resume_rejected", logging.WARNING, path=kind,
                          reason="unknown_session_or_secret")
                    return
            if generation <= session.generation:
                await write_frame(writer, dict(type="rejected", reason="stale_generation"))
                event("resume_rejected", logging.WARNING, session=tag(session.sid),
                      reason="stale_generation", generation=generation)
                return
            # Reserve before await: a delayed old handshake cannot reclaim ownership.
            session.generation = generation
            transport_id = secrets.token_hex(16)
            # Respond before attach, so the session cannot send DATA before WELCOME.
            await write_frame(writer, dict(type="welcome", version=VERSION, session=session.sid,
                                          secret=session.secret, transport=transport_id,
                                          generation=generation))
            ready = await asyncio.wait_for(read_frame(reader), 3)
            if ready != dict(type="ready", generation=generation, transport=transport_id):
                raise SecurityError("invalid channel confirmation")
            if generation != session.generation:
                return
            await write_frame(writer, dict(type="ready_ok", generation=generation))
            # drain() yields: a later handshake may have committed while waiting.
            # The final check and ownership change must be one synchronous step.
            if generation != session.generation or session.closed:
                event("resume_rejected", session=tag(session.sid),
                      reason="superseded_commit", generation=generation)
                return
            session.attach(writer, transport_id)
            event("client_connected", client=client_id, session=tag(session.sid), path=kind)
            committed = True
            await session.run_transport(reader, writer)
        except (ProtocolError, SecurityError, OSError, TimeoutError,
                asyncio.IncompleteReadError) as exc:
            normal_probe_end = probing and isinstance(exc, asyncio.IncompleteReadError)
            event("probe_complete" if normal_probe_end else "connection_rejected",
                  logging.DEBUG if normal_probe_end else logging.WARNING,
                  path=getattr(writer, "kind", "tcp"),
                  reason=str(exc) if isinstance(exc, (SecurityError, ProtocolError)) else type(exc).__name__)
        finally:
            try:
                # A never-committed new session has no application sockets to
                # preserve. Do not hold a full grace period after failed READY.
                if (new_session is not None and not committed and new_session.writer is None
                        and new_session.generation == generation):
                    new_session.close("unconfirmed_session")
                    if self.sessions.get(new_session.sid) is new_session:
                        del self.sessions[new_session.sid]
                # Flush terminal replies (e.g. EXPIRED) before closing TLS.
                writer.close()
                with contextlib.suppress(OSError, TimeoutError):
                    await asyncio.wait_for(writer.wait_closed(), 1)
                if new_session is not None and new_session.closed:
                    await new_session.wait_closed()
            finally:
                self.connections.pop(task, None)

    def close(self):
        self.closed = True
        for session in self.sessions.values():
            session.close()
        for task, writer in list(self.connections.items()):
            writer.close()
            if task is not asyncio.current_task():
                task.cancel()

    async def wait_closed(self):
        tasks = [t for t in self.connections if t is not asyncio.current_task()]
        await asyncio.gather(*tasks, *(s.wait_closed() for s in list(self.sessions.values())),
                             return_exceptions=True)


async def connect(session, endpoint, key, context, hostname, *, kind="tcp", quic=None):
    started = time.monotonic()
    event("connect_attempt", path=kind, session=tag(session.sid),
          resumed=getattr(session, "established", False))
    reader, writer = await open_channel(kind, endpoint, context, hostname, quic, key=key)
    try:
        session.next_generation += 1
        generation = session.next_generation
        hello = dict(type="hello", version=VERSION, key=key, generation=generation)
        if getattr(session, "established", False):
            hello.update(session=session.sid, secret=session.secret)
        await write_frame(writer, hello)
        reply = await asyncio.wait_for(read_frame(reader), 5)
        if reply["type"] == "rejected":
            if reply.get("reason") == "stale_generation":
                raise SupersededError("connection attempt superseded")
            raise SecurityError("authentication or generation rejected")
        if reply["type"] == "expired":
            session.close("server no longer holds this session")
            raise ProtocolError("session expired")
        if (reply["type"] != "welcome" or reply.get("version") != VERSION
                or reply.get("generation") != generation
                or any(not isinstance(reply.get(k), str) or len(reply[k]) != n
                       for k, n in (("session", 32), ("secret", 64), ("transport", 32)))):
            raise ProtocolError("invalid welcome")
        if getattr(session, "established", False) and (
                reply["session"] != session.sid or reply["secret"] != session.secret):
            raise ProtocolError("server changed session identity")
        await write_frame(writer, dict(type="ready", generation=generation,
                                      transport=reply["transport"]))
        ready = await asyncio.wait_for(read_frame(reader), 3)
        if ready != dict(type="ready_ok", generation=generation):
            raise SecurityError("channel confirmation rejected")
        if generation != session.next_generation:
            raise SupersededError("connection attempt superseded")
        session.sid, session.secret = reply["session"], reply["secret"]
        session.established = True
        session.generation = generation
        session.attach(writer, reply["transport"])
        ssl_object = writer.get_extra_info("ssl_object")
        event("connect_success", session=tag(session.sid), path=kind,
              carrier=("ech-" if getattr(writer, "ech", False) else "") +
                      ("https-connect" if kind == "tcp" else "http3-connect"),
              duration_ms=round((time.monotonic() - started) * 1000, 2),
              tls="TLSv1.3", cipher=ssl_object.cipher()[0] if ssl_object else writer.protocol.cipher,
              generation=generation)
        return reader, writer
    except BaseException:
        abort(writer)
        raise


async def reconnect(session, endpoint, key, context, hostname):
    while not session.closed:
        try:
            reader, writer = await connect(session, endpoint, key, context, hostname)
            await session.run_transport(reader, writer)
        except (ProtocolError, SecurityError) as exc:
            session.close(str(exc))
        except (OSError, TimeoutError, asyncio.IncompleteReadError):
            event("connect_failed", logging.WARNING, path="tcp", reason="network_error")
        if not session.closed:
            await asyncio.sleep(0.5)


async def probe(kind, endpoint, key, context, hostname, quic):
    writer = None
    try:
        reader, writer = await open_channel(kind, endpoint, context, hostname, quic, key=key)
        samples = []
        for _ in range(3):
            nonce = secrets.token_hex(16)
            start = time.monotonic()
            await write_frame(writer, dict(type="probe", version=VERSION, key=key, nonce=nonce))
            reply = await asyncio.wait_for(read_frame(reader), 2)
            if reply.get("type") == "rejected":
                raise SecurityError("probe authentication rejected")
            if reply != dict(type="probe_ok", version=VERSION, nonce=nonce):
                raise SecurityError("invalid authenticated probe response")
            samples.append((time.monotonic() - start) * 1000)
        return samples
    finally:
        if writer:
            abort(writer)


class AdaptiveClient:
    def __init__(self, session, endpoints, key, context, hostname, quic, *, interval=5):
        self.session, self.endpoints, self.key = session, endpoints, key
        self.context, self.hostname, self.quic = context, hostname, quic
        self.interval = interval
        self.selector = Selector(tuple(endpoints))
        self.active = None
        self.runner = None
        self.probing = None
        self.retry_at = 0
        self.quarantined = set()
        self.measure_changed = asyncio.Event()
        self.switch_lock = asyncio.Lock()

    def quarantine(self, kind):
        self.quarantined.add(kind)
        self.selector.stats[kind].update()
        event("candidate_quarantined", logging.ERROR, path=kind,
              reason="certificate_or_authentication_failed")

    async def measure(self):
        kinds = tuple(kind for kind in self.endpoints if kind not in self.quarantined)

        async def measure_path(kind):
            try:
                samples = await probe(kind, self.endpoints[kind], self.key,
                                      self.context, self.hostname, self.quic)
            except SecurityError:
                self.quarantine(kind)
                self.measure_changed.set()
                return
            except (OSError, TimeoutError, asyncio.IncompleteReadError):
                samples = None
            if kind not in self.quarantined:
                stat = self.selector.stats[kind]
                stat.update(samples)
                event("path_probe", path=kind, reason="ok" if stat.available else "network_error",
                      rtt_ms=round(stat.rtt_ms, 2) if stat.available else None,
                      jitter_ms=round(stat.jitter_ms, 2), failure_rate=round(stat.failure_rate, 3),
                      failures=stat.failures, attempts=stat.attempts,
                      score_ms=round(stat.score(kind, time.monotonic()), 2) if stat.available else None)
                self.measure_changed.set()

        await asyncio.gather(*(measure_path(kind) for kind in kinds))

    async def switch(self, kind, reason, *, expected_generation=None):
        async with self.switch_lock:
            if (expected_generation is not None
                    and expected_generation != self.session.next_generation):
                return False  # The selection was made before a different handover.
            if (kind == self.active and self.session.writer is not None
                    and self.runner and not self.runner.done()):
                return True
            return await self.switch_locked(kind, reason)

    async def switch_locked(self, kind, reason):
        if kind in self.quarantined:
            return False
        previous = self.active
        event("path_selected", path=kind, previous=previous, reason=reason,
              session=tag(self.session.sid))
        try:
            reader, writer = await connect(self.session, self.endpoints[kind], self.key,
                                           self.context, self.hostname, kind=kind, quic=self.quic)
        except SecurityError:
            self.quarantine(kind)
            return False
        except SupersededError:
            self.retry_at = time.monotonic() + 0.25
            event("connect_superseded", path=kind, reason="newer_attempt")
            return False
        except (OSError, ConnectionError, TimeoutError, asyncio.IncompleteReadError):
            self.selector.stats[kind].update()
            event("connect_failed", logging.WARNING, path=kind, reason="network_error")
            self.retry_at = time.monotonic() + 0.25
            return False
        # Only after the new authenticated channel is accepted do we stop the old
        # reader. Session-owned delivery and application sockets keep running.
        previous_runner = self.runner
        # Publish ownership before yielding to clean up the old reader. DATA on
        # the committed channel must never race stale controller state.
        self.active = kind
        self.runner = asyncio.create_task(self.session.run_transport(reader, writer))
        self.selector.committed()
        if previous_runner:
            previous_runner.cancel()
            await asyncio.gather(previous_runner, return_exceptions=True)
        return True

    async def run(self):
        next_probe = 0
        try:
            while not self.session.closed:
                now = time.monotonic()
                if self.probing is None and now >= next_probe:
                    self.probing = asyncio.create_task(self.measure())
                    next_probe = now + self.interval
                measured = self.measure_changed.is_set()
                self.measure_changed.clear()
                if self.probing and self.probing.done():
                    await self.probing
                    self.probing = None
                    measured = True
                alive = self.session.writer is not None and self.runner and not self.runner.done()
                if not alive and len(self.quarantined) == len(self.endpoints):
                    self.session.close("no_authenticated_path")
                    break
                if not alive and self.active:
                    self.selector.stats[self.active].update()
                    self.active = None
                if (measured or not alive) and now >= self.retry_at:
                    desired, reason = self.selector.choose(self.active if alive else None)
                    if desired and desired != self.active:
                        await self.switch(desired, reason,
                                          expected_generation=self.session.next_generation)
                await asyncio.sleep(0.05)
        except SecurityError:
            self.session.close("security_verification_failed")
        except ProtocolError as exc:
            self.session.close(str(exc))
        finally:
            tasks = [t for t in (self.probing, self.runner) if t]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.session.close("client_stopped")


def address(value):
    try:
        host, port = value.rsplit(":", 1)
        port = int(port)
        if not host or not 1 <= port <= 65535:
            raise ValueError
        return host.strip("[]"), port
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected host:port") from exc


async def main(args):
    key = os.environ.get("MYVPN_KEY", "")
    if len(key) != 64 or any(c not in "0123456789abcdefABCDEF" for c in key):
        raise SystemExit("Set MYVPN_KEY to 64 hex characters generated with secrets.token_hex(32)")
    if args.mode == "server":
        context = tls_server(args.cert, args.cert_key)
        manager = Server(key, args.target, args.grace, srtl=args.srtl)
        ech_enabled = bool(args.ech_keys)
        server = await serve_tcp(manager, ("127.0.0.1", 0) if ech_enabled else args.listen,
                                 context, ech=ech_enabled)
        udp_server = None
        udp_tasks = set()
        gateway = None
        try:
            if ech_enabled:
                backend_udp = None
                if args.transport != "tcp":
                    udp_server = await serve_tcp(manager, ("127.0.0.1", 0), context, kind="udp", ech=True)
                    backend_udp = format_address(udp_server.sockets[0].getsockname()[:2])
                gateway = await EchGateway.start(dict(mode="server", tcp=format_address(args.listen),
                    udp=format_address(args.udp_listen or args.listen) if backend_udp else "",
                    backend_tcp=format_address(server.sockets[0].getsockname()[:2]),
                    backend_udp=backend_udp or "", cert=os.path.abspath(args.cert),
                    cert_key=os.path.abspath(args.cert_key), keys_file=os.path.abspath(args.ech_keys)),
                    binary=args.ech_binary, key=key)
            elif args.transport != "tcp":
                udp_server, udp_tasks = await serve_udp(
                    manager, args.udp_listen or args.listen,
                    quic_config(cert=args.cert, key=args.cert_key))
            event("server_started", mode=args.transport, endpoint=str(args.listen), tls="TLSv1.3")
            async with server:
                if gateway:
                    await gateway.guard(server.serve_forever())
                else:
                    await server.serve_forever()
        finally:
            server.close()
            manager.close()
            if gateway:
                await gateway.close()
            if udp_server:
                if ech_enabled:
                    udp_server.close()
                    await udp_server.wait_closed()
                else:
                    await udp_server.aclose()
            for task in list(udp_tasks):
                task.cancel()
            await asyncio.gather(*udp_tasks, return_exceptions=True)
            await server.wait_closed()
            await manager.wait_closed()
            await shutdown_channels()
    else:
        context = tls_client(args.ca)
        hostname = args.server_name or args.server[0]
        client_quic = quic_config(ca=args.ca, hostname=hostname)
        endpoints = {}
        if args.transport != "udp":
            endpoints["tcp"] = args.server
        if args.transport != "tcp":
            endpoints["udp"] = args.udp_server or args.server
        gateway = None
        if args.ech_config:
            gateway = await EchGateway.start(dict(mode="client",
                tcp="127.0.0.1:0" if "tcp" in endpoints else "",
                udp="127.0.0.1:0" if "udp" in endpoints else "",
                remote_tcp=format_address(args.server), remote_udp=format_address(args.udp_server or args.server),
                server_name=hostname, ca=os.path.abspath(args.ca), config_file=os.path.abspath(args.ech_config)),
                binary=args.ech_binary, key=key)
            context.ech_gateway = gateway
        session = Session(grace=args.grace, srtl=args.srtl)
        controller = AdaptiveClient(session, endpoints, key, context, hostname,
                                    client_quic,
                                    interval=args.probe_interval)
        task = asyncio.create_task(controller.run())
        server = None
        try:
            server = await asyncio.start_server(session.accept_local, *args.listen, limit=CHUNK)
            event("client_started", endpoint=str(args.listen), mode=args.transport,
                  probe_interval=args.probe_interval)
            async with server:
                if gateway:
                    await gateway.guard(task)
                else:
                    await task
            raise SystemExit("Tunnel stopped: " + session.reason)
        finally:
            if server:
                server.close()
                await server.wait_closed()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            session.close()
            await session.wait_closed()
            if gateway:
                await gateway.close()
            await shutdown_channels()


def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    server = commands.add_parser("server")
    server.add_argument("--listen", type=address, default=("0.0.0.0", 8443))
    server.add_argument("--target", type=address, required=True)
    server.add_argument("--cert", required=True)
    server.add_argument("--cert-key", required=True)
    server.add_argument("--udp-listen", type=address)
    server.add_argument("--transport", choices=("auto", "tcp"), default="auto")
    server.add_argument("--ech-keys", help="server-only ECH private keys JSON; enables required-ECH gateway")
    client = commands.add_parser("client")
    client.add_argument("--listen", type=address, default=("127.0.0.1", 1080))
    client.add_argument("--server", type=address, required=True)
    client.add_argument("--ca", required=True)
    client.add_argument("--server-name")
    client.add_argument("--udp-server", type=address)
    client.add_argument("--transport", choices=("auto", "tcp", "udp"), default="auto")
    client.add_argument("--probe-interval", type=float, default=5)
    client.add_argument("--ech-config", help="pinned public ECHConfigList; prohibits direct-SNI fallback")
    for command in (server, client):
        command.add_argument("--srtl", action=argparse.BooleanOptionalAction, default=False,
                             help="SRTL: coalesce DATA, bounded padding and cover tail (outgoing only; default off)")
        command.add_argument("--grace", type=float, default=30)
        command.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
        command.add_argument("--log-file", help="rotating JSONL metadata log (no payloads or secrets)")
        command.add_argument("--ech-binary", default=str(DEFAULT_BINARY), help="path to the built native ECH gateway")
    args = parser.parse_args()
    if args.mode == "client" and not args.ech_config:
        try:
            identity = ipaddress.ip_address(args.server[0])
            if args.udp_server:
                ipaddress.ip_address(args.udp_server[0])
            if args.server_name and ipaddress.ip_address(args.server_name) != identity:
                raise ValueError
        except ValueError:
            parser.error("direct mode requires IP endpoints and the server IP as identity; DNS/SNI is disabled")
    if not 1 <= args.grace <= 300:
        parser.error("--grace must be between 1 and 300 seconds")
    if args.mode == "client" and not 0.5 <= args.probe_interval <= 10:
        parser.error("--probe-interval must be between 0.5 and 10 seconds")
    configure(args.log_level, args.log_file, args.mode)
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    cli()
