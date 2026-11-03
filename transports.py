"""TLS/TCP and QUIC/UDP adapters. No plaintext transport or 0-RTT."""

import asyncio
import contextlib
import socket
import ssl

from diagnostics import event
from http_carrier import (AUTHORITY, CONTROL_LIMIT, H3_ALPN, HTTP_ALPN, PAGE,
                          BoundedH3, CarrierRejected, connect_http, header_map,
                          valid_authorization)

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.protocol import QuicStreamAdapter
from aioquic.asyncio.server import QuicServer
from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import (MAX_STREAM_DATA_FRAME_CAPACITY, QuicConnection,
                                    QuicConnectionError)
from aioquic.quic.events import (ConnectionTerminated, HandshakeCompleted, StopSendingReceived,
                                StreamDataReceived, StreamReset)
from aioquic.quic.packet import QuicErrorCode, QuicFrameType, pull_quic_header
from aioquic.h3.events import DataReceived, HeadersReceived

ALPN = HTTP_ALPN
CONNECT_TIMEOUT = 3.0
BUFFER_LIMIT = 96 * 1024
SEND_LIMIT = 256 * 1024
AUTH_TIMEOUT = 5.0
MAX_CONNECTIONS = 64
MAX_PENDING = 32
MAX_PENDING_PER_IP = 8
CLEANUPS = set()


async def shutdown_channels():
    loop = asyncio.get_running_loop()
    while True:
        batch = [task for task in list(CLEANUPS) if task.get_loop() is loop]
        if not batch:
            return
        await asyncio.gather(*batch, return_exceptions=True)
        # Python 3.14 gather can return immediately for completed tasks, before
        # their discard callbacks run. Remove them here to avoid a busy loop.
        CLEANUPS.difference_update(task for task in batch if task.done())


def observe_future(future):
    if not future.cancelled():
        future.exception()


class SecurityError(Exception):
    """A certificate, authenticated peer, or negotiated protocol was rejected."""


def tls_client(ca):
    # SSLContext avoids create_default_context's SSLKEYLOGFILE environment hook.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=str(ca))
    context.set_alpn_protocols([ALPN])
    return context


def tls_server(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols([ALPN])
    return context


def quic_config(*, ca=None, hostname=None, cert=None, key=None):
    config = QuicConfiguration(is_client=cert is None, alpn_protocols=[H3_ALPN],
                               idle_timeout=8, max_data=BUFFER_LIMIT + 3 * CONTROL_LIMIT,
                               max_stream_data=BUFFER_LIMIT, server_name=hostname)
    config.secrets_log_file = None
    config.session_ticket = None
    if cert:
        config.load_cert_chain(str(cert), str(key))
    else:
        config.verify_mode = ssl.CERT_REQUIRED
        config.load_verify_locations(cafile=str(ca))
    return config


class SecureWriter:
    def __init__(self, writer, *, protocol=None):
        self.writer, self.protocol = writer, protocol
        self.transport = self
        self.kind = "udp" if protocol else "tcp"
        self.closing = False
        self.cleanup = None
        self.authenticated = False

    def write(self, data):
        if self.closing or (self.protocol and (self.protocol._closed.is_set()
                                               or self.protocol._quic._close_event is not None)):
            raise ConnectionError("transport closed")
        if self.protocol and self.protocol.send_buffered() + len(data) + 16 > SEND_LIMIT:
            event("send_buffer_limited", path="udp", reason="send_buffer_budget",
                  buffered_bytes=self.protocol.send_buffered(), limit=SEND_LIMIT)
            raise ConnectionError("QUIC send buffer limit")
        self.writer.write(data)

    async def drain(self):
        if self.closing:
            raise ConnectionError("transport closed")
        await self.writer.drain()
        if self.protocol:
            self.protocol.transmit()
            await self.protocol.drain_send_buffer()

    def get_extra_info(self, name, default=None):
        return self.writer.get_extra_info(name, default)

    def get_write_buffer_size(self):
        if self.protocol:
            return self.protocol.send_buffered()
        return self.writer.transport.get_write_buffer_size()

    def is_closing(self):
        return self.closing or self.writer.is_closing()

    def abort(self):
        self.close()

    def close(self):
        if self.closing:
            return
        self.closing = True
        self.writer.close()
        if self.protocol:
            self.protocol.send_changed.set()
            self.protocol.transmit()
            self.cleanup = asyncio.create_task(self.finish_quic())
        else:
            # GUI clients can retire their event loop immediately after stop.
            # Keep SSL shutdown alive until the underlying TCP socket is closed.
            self.cleanup = asyncio.create_task(self.finish_tcp())
        CLEANUPS.add(self.cleanup)
        self.cleanup.add_done_callback(CLEANUPS.discard)

    async def finish_tcp(self):
        try:
            await asyncio.wait_for(self.writer.wait_closed(), 1.5)
        except (OSError, TimeoutError):
            self.writer.transport.abort()
            await asyncio.sleep(0)
        except asyncio.CancelledError:
            self.writer.transport.abort()
            raise

    async def finish_quic(self):
        try:
            # QUIC StreamWriter.drain does not wait for delivery. Give the final
            # response/FIN a transport ACK before emitting CONNECTION_CLOSE.
            with contextlib.suppress(ConnectionError, TimeoutError):
                await asyncio.wait_for(self.protocol.ping(), 0.5)
        finally:
            for future in self.protocol._ping_waiters.values():
                future.cancel()
            self.protocol._ping_waiters.clear()
            self.protocol.close()
            if self.protocol.owns_socket:
                await self.protocol.cleanup_socket()

    async def wait_closed(self):
        if self.cleanup:
            await asyncio.shield(self.cleanup)
        elif self.protocol:
            await self.protocol.wait_closed()
        else:
            await self.writer.wait_closed()


class ReceiveWindow:
    """Pinned aioquic 1.7.1 adapter: receive credits follow application reads.

    CONNECT stream 0 has a sliding byte window. Three remote HTTP/3 control/QPACK
    streams each have a fixed lifetime allowance, never auto-growing credits.
    """
    def __init__(self, connection):
        self.connection = connection
        self.consumed = 0
        self.get_original = connection._get_or_create_stream
        connection._get_or_create_stream = self.get_stream
        connection._write_stream_limits = self.write_limits
        connection._local_max_stream_data_uni = CONTROL_LIMIT
        connection._local_max_streams_bidi.value = 0 if connection._is_client else 1
        connection._local_max_streams_bidi.sent = connection._local_max_streams_bidi.value
        connection._local_max_streams_uni.value = connection._local_max_streams_uni.sent = 3
        self.remote_controls = {3, 7, 11} if connection._is_client else {2, 6, 10}

    def get_stream(self, frame_type, stream_id):
        if stream_id != 0 and stream_id not in self.remote_controls:
            raise QuicConnectionError(QuicErrorCode.STREAM_LIMIT_ERROR, frame_type,
                                      "stream limit")
        return self.get_original(frame_type, stream_id)

    def write_limits(self, builder, space, stream):
        # Do not invoke aioquic's automatic highest_offset-based window growth.
        if not stream.max_stream_data_local:
            return
        allowed = self.consumed + BUFFER_LIMIT if stream.stream_id == 0 else CONTROL_LIMIT
        if allowed - stream.max_stream_data_local >= BUFFER_LIMIT // 2:
            stream.max_stream_data_local = allowed
        if stream.max_stream_data_local_sent != stream.max_stream_data_local:
            buf = builder.start_frame(QuicFrameType.MAX_STREAM_DATA,
                                      capacity=MAX_STREAM_DATA_FRAME_CAPACITY,
                                      handler=self.connection._on_max_stream_data_delivery,
                                      handler_args=(stream,))
            buf.push_uint_var(stream.stream_id)
            buf.push_uint_var(stream.max_stream_data_local)
            stream.max_stream_data_local_sent = stream.max_stream_data_local


class WindowReader(asyncio.StreamReader):
    def __init__(self, protocol):
        super().__init__(limit=BUFFER_LIMIT)
        self.protocol = protocol
        self.fed = 0

    def feed_data(self, data):
        self.fed += len(data)
        super().feed_data(data)

    def _maybe_resume_transport(self):
        super()._maybe_resume_transport()
        self.protocol.update_receive_credit()
        if not self.protocol._closed.is_set():
            self.protocol._transmit_soon()


class Http3StreamAdapter(QuicStreamAdapter):
    def write(self, data):
        stream = self.protocol.http._stream.get(self.stream_id)
        if stream is None or stream.sending_ended:
            raise ConnectionError("HTTP stream closed")
        self.protocol.http.send_data(self.stream_id, data, end_stream=False)
        self.protocol._transmit_soon()

    def write_eof(self):
        if not self._closing:
            self._closing = True
            stream = self.protocol.http._stream.get(self.stream_id)
            if stream is None or stream.sending_ended or self.protocol._quic._close_event is not None:
                return
            self.protocol.http.send_data(self.stream_id, b"", end_stream=True)
            self.protocol._transmit_soon()


class TunnelQuicProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        self.access_key = kwargs.pop("access_key", None)
        super().__init__(*args, **kwargs)
        self.receive_window = ReceiveWindow(self._quic)
        self.owns_socket = False
        self.disposed = False
        self.security_failure = False
        self.handshake_complete = False
        self.negotiated_alpn = None
        self.cipher = None
        self.socket_closed = asyncio.Event()
        self.authenticated = False
        self.send_changed = asyncio.Event()
        self.peer_ip = None
        self.auth_timer = (self._loop.call_later(AUTH_TIMEOUT, self.authentication_expired)
                           if not self._quic._is_client else None)
        close_original = self._quic.close

        def local_close(error_code=QuicErrorCode.NO_ERROR, frame_type=None, reason_phrase=""):
            # Only locally detected TLS errors establish verification failure.
            # A remote Initial CONNECTION_CLOSE has an attacker-chosen error code.
            if not self.handshake_complete and 0x100 <= error_code <= 0x1ff:
                self.security_failure = True
            self.cancel_auth_deadline()
            self.send_changed.set()
            close_original(error_code=error_code, frame_type=frame_type, reason_phrase=reason_phrase)

        self._quic.close = local_close
        self.http = BoundedH3(self._quic)
        self.http_reader = self.http_writer = None
        self.response_waiter = None
        self.wire_fed = 0
        self.carrier_ready = False
        self.headers_seen = False

    def cancel_auth_deadline(self):
        if self.auth_timer:
            self.auth_timer.cancel()
            self.auth_timer = None

    def send_buffered(self):
        # Pinned aioquic: ACKed bytes are removed from sender._buffer. Include
        # unsent / flow-control-blocked bytes, not only bytes in flight.
        return sum(len(stream.sender._buffer) for stream in self._quic._streams.values())

    async def drain_send_buffer(self):
        while True:
            self.send_changed.clear()
            if self._quic._close_event is not None or self._closed.is_set():
                raise ConnectionError("QUIC connection closed")
            if self.send_buffered() <= SEND_LIMIT // 2:
                return
            await self.send_changed.wait()

    def datagram_received(self, data, addr):
        if self.disposed:
            return
        super().datagram_received(data, addr)
        self.send_changed.set()

    def transmit(self):
        if not self.disposed:
            super().transmit()

    def _transmit_soon(self):
        if not self.disposed:
            super()._transmit_soon()

    def stop_callbacks(self):
        self.disposed = True
        self.cancel_auth_deadline()
        for handle in (self._timer, self._transmit_task):
            if handle:
                handle.cancel()
        self._timer = self._transmit_task = self._timer_at = None
        self._closed.set()
        self.send_changed.set()
        for future in (self._connected_waiter, self.response_waiter, *self._ping_waiters.values()):
            if future and not future.done():
                future.add_done_callback(observe_future)
                future.set_exception(ConnectionError("transport closed"))
        self._connected_waiter = None
        self._ping_waiters.clear()
        for reader in self._stream_readers.values():
            reader.feed_eof()

    def mark_authenticated(self):
        self.authenticated = True
        self.cancel_auth_deadline()

    def authentication_expired(self):
        self.auth_timer = None
        if not self.authenticated:
            event("authentication_timeout", path="udp", reason="access_key_deadline")
            self.close(error_code=QuicErrorCode.CONNECTION_REFUSED,
                       reason_phrase="authentication timeout")

    def _create_stream(self, stream_id):
        reader = WindowReader(self)
        adapter = Http3StreamAdapter(self, stream_id)
        stream_protocol = asyncio.StreamReaderProtocol(reader)
        writer = asyncio.StreamWriter(adapter, stream_protocol, reader, self._loop)
        self._stream_readers[stream_id] = reader
        return reader, writer

    def update_receive_credit(self):
        stream = self.http._stream.get(0)
        parser_buffer = len(stream.buffer) if stream else 0
        app_buffer = len(self.http_reader._buffer) if self.http_reader else 0
        self.receive_window.consumed = max(0, self.wire_fed - parser_buffer - app_buffer)

    async def open_http(self, key):
        self.response_waiter = self._loop.create_future()
        self.response_waiter.add_done_callback(observe_future)
        self.http_reader, self.http_writer = self._create_stream(0)
        self.http.send_headers(0, [(b":method", b"CONNECT"), (b":authority", AUTHORITY),
                                  (b"proxy-authorization", b"Bearer " + key.encode("ascii"))])
        self.transmit()
        try:
            await asyncio.wait_for(asyncio.shield(self.response_waiter), CONNECT_TIMEOUT)
        finally:
            if not self.response_waiter.done():
                self.response_waiter.cancel()
        return self.http_reader, self.http_writer

    async def ping(self):
        if self._closed.is_set():
            raise ConnectionError("connection closed")
        waiter = self._loop.create_future()
        waiter.add_done_callback(observe_future)
        uid = id(waiter)
        self._ping_waiters[uid] = waiter
        self._quic.send_ping(uid)
        self.transmit()
        try:
            await asyncio.shield(waiter)
        finally:
            self._ping_waiters.pop(uid, None)
            if not waiter.done():
                waiter.cancel()

    def http_event(self, ev):
        if isinstance(ev, HeadersReceived):
            if ev.stream_id != 0 or self.headers_seen:
                raise CarrierRejected("unexpected headers")
            self.headers_seen = True
            headers = header_map(ev.headers)
            if self._quic._is_client:
                if (headers.get(b":status") != b"200" or ev.stream_ended
                        or b"content-length" in headers):
                    raise CarrierRejected("CONNECT rejected")
                self.carrier_ready = True
                if self.response_waiter and not self.response_waiter.done():
                    self.response_waiter.set_result(None)
            else:
                if (headers.get(b":method") == b"CONNECT" and headers.get(b":authority") == AUTHORITY
                        and b":scheme" not in headers and b":path" not in headers
                        and b":protocol" not in headers
                        and b"content-length" not in headers and not ev.stream_ended
                        and valid_authorization(headers.get(b"proxy-authorization"), self.access_key)):
                    self.mark_authenticated()
                    self.carrier_ready = True
                    self.http.send_headers(0, [(b":status", b"200")])
                    self.http_reader, self.http_writer = self._create_stream(0)
                    self._stream_handler(self.http_reader, self.http_writer)
                else:
                    found = headers.get(b":method") in (b"GET", b"HEAD") and headers.get(b":path") == b"/"
                    body = PAGE if found else b"Not found.\n"
                    self.http.send_headers(0, [(b":status", b"200" if found else b"404"),
                                              (b"content-type", b"text/html; charset=utf-8"),
                                              (b"content-length", str(len(body)).encode())])
                    self.http.send_data(0, b"" if headers.get(b":method") == b"HEAD" else body, end_stream=True)
        elif isinstance(ev, DataReceived):
            if not self.carrier_ready or self.http_reader is None:
                if ev.data:
                    raise CarrierRejected("data before CONNECT")
                return
            self.http_reader.feed_data(ev.data)
            if ev.stream_ended:
                self.http_reader.feed_eof()

    def connection_lost(self, exc):
        self.stop_callbacks()
        self.socket_closed.set()

    def quic_event_received(self, ev):
        if isinstance(ev, HandshakeCompleted):
            self.handshake_complete = True
            self.negotiated_alpn = ev.alpn_protocol
            self.cipher = self._quic.tls.key_schedule.cipher_suite.name
            if ev.alpn_protocol != H3_ALPN or ev.early_data_accepted:
                self.security_failure = True
                self.close(error_code=0x100, reason_phrase="security policy")
        elif isinstance(ev, ConnectionTerminated):
            self.cancel_auth_deadline()
            self.send_changed.set()
            if self.response_waiter and not self.response_waiter.done():
                self.response_waiter.set_exception(ConnectionError("HTTP/3 channel closed"))
        elif isinstance(ev, (StreamReset, StopSendingReceived)):
            # All permitted HTTP/3 streams are required by our single CONNECT.
            # An HTTP reset is a path failure, never a certificate failure.
            self.close(reason_phrase="HTTP stream reset")
            for reader in self._stream_readers.values():
                reader.set_exception(ConnectionError("HTTP stream reset"))
            if self.response_waiter and not self.response_waiter.done():
                self.response_waiter.set_exception(ConnectionError("HTTP stream reset"))
            return
        elif isinstance(ev, StreamDataReceived):
            if not self.handshake_complete:
                self.close(error_code=0x01, reason_phrase="stream limit")
                return
            if ev.stream_id == 0:
                self.wire_fed += len(ev.data)
            try:
                for http_event in self.http.handle_event(ev):
                    self.http_event(http_event)
                self.update_receive_credit()
            except CarrierRejected:
                if self.response_waiter and not self.response_waiter.done():
                    self.response_waiter.set_exception(SecurityError("HTTP CONNECT rejected"))
                self.close(error_code=0x100, reason_phrase="HTTP policy")
            return
        super().quic_event_received(ev)

    async def cleanup_socket(self):
        try:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.wait_closed(), 2)
        finally:
            # Pinned aioquic adapter: stop callbacks before closing an owned UDP
            # endpoint, including when the peer blackholes the closing packets.
            self.stop_callbacks()
            self._transport.abort()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.socket_closed.wait(), 1)


class BoundedQuicServer(QuicServer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.socket_closed = asyncio.Event()

    def connection_lost(self, exc):
        self.socket_closed.set()

    def datagram_received(self, data, addr):
        try:
            header = pull_quic_header(Buffer(data=data),
                                      host_cid_length=self._configuration.connection_id_length)
        except ValueError:
            return
        if header.destination_cid not in self._protocols:
            protocols = set(self._protocols.values())
            pending = [p for p in protocols if not p.authenticated]
            # Source ports cannot evade the per-IP pre-authentication quota.
            if (len(protocols) >= MAX_CONNECTIONS or len(pending) >= MAX_PENDING
                    or sum(p.peer_ip == addr[0] for p in pending) >= MAX_PENDING_PER_IP):
                return
        super().datagram_received(data, addr)
        protocol = self._protocols.get(header.destination_cid)
        if protocol and protocol.peer_ip is None:
            protocol.peer_ip = addr[0]

    async def aclose(self):
        protocols = set(self._protocols.values())
        self.close()
        for protocol in protocols:
            protocol.stop_callbacks()
        self._transport.abort()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self.socket_closed.wait(), 1)


class BoundedTCPServer:
    """Accept and reserve a slot before allocating TLS state (public asyncio API)."""
    def __init__(self, manager, listener, context, kind="tcp", ech=False):
        self.manager, self.listener, self.context = manager, listener, context
        self.kind, self.ech = kind, ech
        self.clients = {}
        self.tasks = set()
        self.acceptor = asyncio.create_task(self.accept_loop())

    @property
    def sockets(self):
        return (self.listener,)

    async def accept_loop(self):
        loop = asyncio.get_running_loop()
        while True:
            client, peer = await loop.sock_accept(self.listener)
            pending = [ip for ip, writer in self.clients.values()
                       if writer is None or not writer.authenticated]
            if (len(self.clients) >= MAX_CONNECTIONS or len(pending) >= MAX_PENDING
                    or pending.count(peer[0]) >= MAX_PENDING_PER_IP):
                client.close()
                event("connection_limited", path="tcp", reason="connection_budget",
                      connections=len(self.clients), pending_connections=len(pending))
                continue
            self.clients[client] = (peer[0], None)
            task = asyncio.create_task(self.handle(client, loop.time() + AUTH_TIMEOUT))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

    async def handle(self, client, deadline):
        writer = None
        try:
            loop = asyncio.get_running_loop()
            if loop.time() >= deadline:
                raise TimeoutError
            reader = asyncio.StreamReader(limit=BUFFER_LIMIT)
            protocol = asyncio.StreamReaderProtocol(reader)
            transport, _ = await loop.connect_accepted_socket(
                lambda: protocol, client, ssl=self.context,
                ssl_handshake_timeout=deadline - loop.time(), ssl_shutdown_timeout=1)
            writer = SecureWriter(asyncio.StreamWriter(transport, protocol, reader, loop))
            writer.kind, writer.ech = self.kind, self.ech
            writer.auth_deadline = deadline
            self.clients[client] = (self.clients[client][0], writer)
            await self.manager.accept(reader, writer)
        except (OSError, TimeoutError):
            event("connection_rejected", path="tcp", reason="tls_handshake_failed")
        finally:
            try:
                if writer:
                    writer.close()
                    with contextlib.suppress(OSError, TimeoutError):
                        await asyncio.wait_for(writer.wait_closed(), 1)
                else:
                    client.close()
            finally:
                self.clients.pop(client, None)

    async def serve_forever(self):
        await self.acceptor

    def close(self):
        self.acceptor.cancel()
        self.listener.close()
        for task in self.tasks:
            task.cancel()

    async def wait_closed(self):
        await asyncio.gather(self.acceptor, *list(self.tasks), return_exceptions=True)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.close()
        await self.wait_closed()


async def serve_tcp(manager, address, context, *, kind="tcp", ech=False):
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(*address, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
    family, kind, proto, _, local = infos[0]
    listener = socket.socket(family, kind, proto)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(local)
        listener.listen(64)
        listener.setblocking(False)
        return BoundedTCPServer(manager, listener, context, kind, ech)
    except BaseException:
        listener.close()
        raise


async def open_channel(kind, endpoint, context, hostname, quic=None, key=None):
    requested_kind = kind
    gateway = getattr(context, "ech_gateway", None)
    if gateway is not None:
        if gateway.process.returncode is not None or kind not in gateway.endpoints:
            raise SecurityError("ECH backend unavailable; direct fallback prohibited")
        endpoint = gateway.endpoints[kind]
        kind = "tcp"  # Inner TLS over the ECH-protected TCP or HTTP/3 byte stream.
    if kind == "tcp":
        connect_timeout = CONNECT_TIMEOUT * 3 if gateway is not None else CONNECT_TIMEOUT
        if (context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname
                or context.minimum_version < ssl.TLSVersion.TLSv1_3
                or context.keylog_filename is not None):
            raise SecurityError("unsafe TLS client configuration")
        try:
            reader, raw = await asyncio.wait_for(asyncio.open_connection(
                *endpoint, ssl=context, server_hostname=hostname,
                limit=BUFFER_LIMIT, ssl_handshake_timeout=connect_timeout,
                ssl_shutdown_timeout=1, happy_eyeballs_delay=0.25, interleave=1), connect_timeout)
        except ssl.SSLCertVerificationError as exc:
            raise SecurityError("certificate verification failed") from exc
        if raw.get_extra_info("ssl_object").selected_alpn_protocol() != ALPN:
            raw.close()
            raise SecurityError("ALPN mismatch")
        writer = SecureWriter(raw)
        writer.kind, writer.ech = requested_kind, gateway is not None
        try:
            if key is not None:
                await connect_http(reader, writer, key)
            return reader, writer
        except CarrierRejected as exc:
            writer.close()
            raise SecurityError("HTTP CONNECT rejected") from exc
        except BaseException:
            writer.close()
            raise
    if (kind != "udp" or quic is None or quic.verify_mode != ssl.CERT_REQUIRED
            or quic.server_name != hostname or quic.secrets_log_file is not None
            or quic.session_ticket is not None or quic.quic_logger is not None):
        raise SecurityError("invalid secure UDP configuration")
    infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
        *endpoint, type=socket.SOCK_DGRAM), CONNECT_TIMEOUT)
    candidates = []
    for family, _, _, _, remote in infos:
        if family in (socket.AF_INET, socket.AF_INET6) and (family, remote) not in candidates:
            candidates.append((family, remote))
    if not candidates:
        raise OSError("no UDP address")
    # Alternate families, preserving resolver order within each family.
    first = [c for c in candidates if c[0] == candidates[0][0]]
    second = [c for c in candidates if c[0] != candidates[0][0]]
    ordered = []
    while first or second:
        if first:
            ordered.append(first.pop(0))
        if second:
            ordered.append(second.pop(0))
    return await race_udp_addresses(ordered[:8], quic, key)


async def race_udp_addresses(candidates, quic, key):
    async def attempt(index, candidate):
        if index:
            await asyncio.sleep(0.25 * index)
        family, remote = candidate
        label = "IPv6" if family == socket.AF_INET6 else "IPv4"
        started = asyncio.get_running_loop().time()
        event("address_attempt", path="udp", family=label, attempts=index + 1)
        try:
            reader, writer = await open_udp_address(family, remote, quic, key)
        except asyncio.CancelledError:
            event("address_cancelled", path="udp", family=label, attempts=index + 1)
            raise
        except (SecurityError, OSError, TimeoutError, asyncio.IncompleteReadError) as exc:
            reason = ("security_verification_failed" if isinstance(exc, SecurityError) else
                      "connect_timeout" if isinstance(exc, TimeoutError) else "network_error")
            event("address_failed", path="udp", family=label, attempts=index + 1, reason=reason,
                  duration_ms=round((asyncio.get_running_loop().time() - started) * 1000, 2))
            raise
        event("address_connected", path="udp", family=label, attempts=index + 1,
              duration_ms=round((asyncio.get_running_loop().time() - started) * 1000, 2))
        return reader, writer

    tasks = [asyncio.create_task(attempt(i, c)) for i, c in enumerate(candidates)]
    winner = None
    errors = []
    try:
        for result in asyncio.as_completed(tasks):
            try:
                winner = await result
                return winner
            except (SecurityError, OSError, TimeoutError, asyncio.IncompleteReadError) as exc:
                errors.append(exc)
        for error in errors:
            if isinstance(error, SecurityError):
                raise error
        raise errors[-1] if errors else OSError("no UDP path")
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()

        async def reap():
            for result in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(result, tuple) and (winner is None or result[1] is not winner[1]):
                    result[1].close()

        cleanup = asyncio.create_task(reap())
        CLEANUPS.add(cleanup)
        cleanup.add_done_callback(CLEANUPS.discard)


async def open_udp_address(family, remote, quic, key):
    loop = asyncio.get_running_loop()
    connection = QuicConnection(configuration=quic)
    _, protocol = await loop.create_datagram_endpoint(
        lambda: TunnelQuicProtocol(connection), family=family,
        local_addr=("::" if family == socket.AF_INET6 else "0.0.0.0", 0))
    protocol.owns_socket = True
    try:
        protocol.connect(remote)
        await asyncio.wait_for(protocol.wait_connected(), CONNECT_TIMEOUT)
        if protocol.security_failure or protocol.negotiated_alpn != H3_ALPN:
            raise SecurityError("QUIC security policy")
        if key is not None:
            reader, raw = await protocol.open_http(key)
        else:
            # Low-level QUIC access for ordinary HTTP clients / adversarial tests.
            reader, raw = super(TunnelQuicProtocol, protocol)._create_stream(0)
        writer = SecureWriter(raw, protocol=protocol)
        writer.carrier_ready = protocol.carrier_ready
        return reader, writer
    except BaseException as exc:
        if protocol.http_writer:
            protocol.http_writer.close()
        if protocol._connected_waiter is not None:
            protocol._connected_waiter.cancel()
            protocol._connected_waiter = None
        protocol.close()
        await protocol.cleanup_socket()
        if protocol.security_failure:
            raise SecurityError("QUIC certificate or handshake verification failed") from exc
        raise


async def serve_udp(manager, address, config):
    tasks = set()

    def factory(*args, **kwargs):
        protocol = TunnelQuicProtocol(*args, access_key=getattr(manager, "authenticate", manager.key), **kwargs)

        def accept(reader, writer):
            secured = SecureWriter(writer, protocol=protocol)
            secured.carrier_ready = True
            task = asyncio.create_task(manager.accept(reader, secured))
            tasks.add(task)
            task.add_done_callback(tasks.discard)

        protocol._stream_handler = accept
        return protocol

    _, server = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: BoundedQuicServer(configuration=config, create_protocol=factory, retry=True),
        local_addr=address)
    return server, tasks
