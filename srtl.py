"""SRTL: bounded application-record padding; encryption stays in TLS/QUIC."""

import asyncio
import base64
import secrets
import time

BATCH_MIN = 0.001
BATCH_MAX = 0.004
MAX_PADDING = 512
COVER_SIZES = (256, 384, 512)  # Whole framed record, including uint32 length.
TAIL_QUIET = 0.1
TAIL_COOLDOWN = 5.0
TAIL_MAX_BYTES = 4096
RX_COVER_BURST = 8192
RX_COVER_RATE = 2048  # Bytes/s; receiver support is independent of local TX setting.


class SRTL:
    def __init__(self, enabled=False):
        self.enabled = enabled
        self.credit = 0.0
        self.last_seq = 0
        self.last_data = 0.0
        self.next_tail = 0.0
        self.padding_bytes = self.merged_reads = 0
        self.cover_tx = self.cover_rx = 0
        self.cover_bytes_tx = self.cover_bytes_rx = 0
        self.rx_tokens = float(RX_COVER_BURST)
        self.rx_updated = time.monotonic()

    def pad(self, frame, data):
        if not self.enabled:
            return data
        if frame["type"] == "cover":
            target = secrets.choice(COVER_SIZES)
            return data + b" " * (target - 4 - len(data))
        if frame["type"] != "data":
            return data
        seq = frame["seq"]
        if seq > self.last_seq:
            # Replays never mint new padding credits. No initial free allowance.
            self.credit = min(2048, self.credit + len(base64.b64decode(frame["data"])) / 10)
            self.last_seq = seq
        length = len(data) + 4
        target = ((length + 127) // 128 + secrets.randbelow(2)) * 128
        padding = target - length
        if padding > min(MAX_PADDING, self.credit):
            return data
        self.credit -= padding
        self.padding_bytes += padding
        return data + b" " * padding

    def accept_cover(self, size, now=None):
        now = time.monotonic() if now is None else now
        self.rx_tokens = min(RX_COVER_BURST, self.rx_tokens + max(0, now - self.rx_updated) * RX_COVER_RATE)
        self.rx_updated = now
        if size > self.rx_tokens:
            return False
        self.rx_tokens -= size
        self.cover_rx += 1
        self.cover_bytes_rx += size
        return True


async def collect(reader, first, limit, policy):
    """Coalesce one stream only; never consume beyond its flow-control credit."""
    data = bytearray(first)
    delay = BATCH_MIN + secrets.randbelow(round((BATCH_MAX - BATCH_MIN) * 1_000_000) + 1) / 1_000_000
    try:
        async with asyncio.timeout(delay):
            while policy.enabled and len(data) < limit:
                extra = await reader.read(limit - len(data))
                if not extra:
                    break
                data.extend(extra)
                policy.merged_reads += 1
    except TimeoutError:
        pass
    return bytes(data)
