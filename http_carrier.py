"""Authenticated HTTP CONNECT and bounded HTTP/3 metadata handling."""

import asyncio
import hmac

import pylsqpack
from aioquic.h3.connection import (FrameError, FrameType, H3Connection, Setting,
                                   encode_settings, parse_settings)

HTTP_ALPN = "http/1.1"
H3_ALPN = "h3"
AUTHORITY = b"relay.internal:443"
HEADER_LIMIT = 8192
CONTROL_LIMIT = 4096
PAGE = b"<!doctype html><title>Service</title><p>Service online.</p>\n"


class CarrierRejected(Exception):
    pass


def valid_authorization(value, key):
    if not isinstance(value, bytes):
        return False
    parts = value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != b"bearer":
        return False
    if callable(key):
        try:
            return key(parts[1].decode("ascii")) is not None
        except UnicodeError:
            return False
    return isinstance(key, str) and hmac.compare_digest(parts[1], key.encode("ascii"))


def header_map(headers):
    if sum(len(k) + len(v) + 32 for k, v in headers) > HEADER_LIMIT:
        raise CarrierRejected("header limit")
    result = {}
    for name, value in headers:
        if name in result:
            raise CarrierRejected("duplicate header")
        result[name] = value
    return result


async def read_head(reader):
    # Strict CRLF and a hard parser bound, independent of StreamReader's limit.
    head = bytearray()
    while len(head) < HEADER_LIMIT:
        head.extend(await reader.readexactly(1))
        if head.endswith(b"\r\n\r\n"):
            break
    else:
        raise CarrierRejected("header limit")
    lines = bytes(head[:-4]).split(b"\r\n")
    headers = []
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator or not name or any(c not in b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in name):
            raise CarrierRejected("invalid header")
        value = value.strip(b" \t")
        if any(c < 32 and c != 9 or c == 127 for c in value):
            raise CarrierRejected("invalid header value")
        headers.append((name.lower(), value))
    return lines[0], header_map(headers)


async def accept_http(reader, writer, key):
    try:
        request, headers = await asyncio.wait_for(read_head(reader), 3)
        parts = request.split(b" ")
        if len(parts) != 3 or parts[2] != b"HTTP/1.1":
            raise CarrierRejected("invalid request")
        method, target, _ = parts
        if not headers.get(b"host"):
            raise CarrierRejected("missing host")
        no_body = b"transfer-encoding" not in headers and headers.get(b"content-length", b"0") == b"0"
        if (method == b"CONNECT" and target == AUTHORITY and no_body
                and headers.get(b"host") == AUTHORITY
                and valid_authorization(headers.get(b"proxy-authorization"), key)):
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            writer.carrier_ready = True
            return True
        if method in (b"GET", b"HEAD") and target == b"/" and no_body:
            status, body = b"200 OK", PAGE
        else:
            status, body = b"404 Not Found", b"Not found.\n"
        writer.write(b"HTTP/1.1 " + status + b"\r\nContent-Type: text/html; charset=utf-8\r\n"
                     b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n"
                     + (b"" if method == b"HEAD" else body))
        await writer.drain()
        return False
    except CarrierRejected:
        writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        return False


async def connect_http(reader, writer, key):
    writer.write(b"CONNECT " + AUTHORITY + b" HTTP/1.1\r\nHost: " + AUTHORITY
                 + b"\r\nProxy-Authorization: Bearer " + key.encode("ascii") + b"\r\n\r\n")
    await writer.drain()
    status, headers = await asyncio.wait_for(read_head(reader), 3)
    if (status.split(b" ", 2)[:2] != [b"HTTP/1.1", b"200"]
            or b"transfer-encoding" in headers or b"content-length" in headers):
        raise CarrierRejected("CONNECT rejected")
    writer.carrier_ready = True


class BoundedH3(H3Connection):
    """A single CONNECT with no dynamic QPACK and bounded non-DATA frames."""
    def __init__(self, quic):
        super().__init__(quic)
        self._decoder = pylsqpack.Decoder(0, 0)

    def _get_local_settings(self):
        settings = super()._get_local_settings()
        settings[Setting.QPACK_MAX_TABLE_CAPACITY] = 0
        settings[Setting.QPACK_BLOCKED_STREAMS] = 0
        settings[Setting.MAX_FIELD_SECTION_SIZE] = HEADER_LIMIT
        return settings

    def _check_request_or_push_frame_type(self, frame_type, stream):
        super()._check_request_or_push_frame_type(frame_type, stream)
        if frame_type != FrameType.DATA and stream.frame_size > HEADER_LIMIT:
            raise FrameError("metadata limit")

    def _decode_headers(self, stream_id, frame_data):
        if frame_data is None or len(frame_data) > HEADER_LIMIT:
            raise FrameError("header limit")
        headers = super()._decode_headers(stream_id, frame_data)
        try:
            header_map(headers)
        except CarrierRejected as exc:
            raise FrameError("header limit or duplicate") from exc
        return headers

    def _handle_control_frame(self, frame_type, frame_data):
        if len(frame_data) > CONTROL_LIMIT:
            raise FrameError("control limit")
        if frame_type == FrameType.SETTINGS:
            settings = parse_settings(frame_data)
            # Our encoder chooses a zero-sized table, even if the peer permits a
            # huge one. This does not allocate a peer-selected table before auth.
            settings[Setting.QPACK_MAX_TABLE_CAPACITY] = 0
            settings[Setting.QPACK_BLOCKED_STREAMS] = 0
            frame_data = encode_settings(settings)
        super()._handle_control_frame(frame_type, frame_data)
