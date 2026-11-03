"""Structured diagnostics: only explicitly selected metadata is logged."""

import datetime
import hashlib
import json
import logging
import logging.handlers
import os
import secrets

LOG = logging.getLogger("tunnel")
RUN = secrets.token_hex(6)
ROLE = None
FIELDS = set("session transport path previous reason stream seq offset bytes queued "
             "rtt_ms jitter_ms failure_rate score_ms failures attempts downtime_ms "
             "duration_ms cipher tls resumed generation tx_seq rx_seq active_streams "
             "tx_bytes rx_bytes replayed endpoint mode probe_interval inflight rx_queued "
             "buffered_bytes delivered_bytes credit_blocked_streams limit family carrier "
             "connections pending_connections srtl srtl_padding_bytes srtl_merged_reads "
             "srtl_cover_tx srtl_cover_rx srtl_cover_bytes_tx srtl_cover_bytes_rx "
             "client clients revoked action".split())


def tag(sid):
    return hashlib.sha256(sid.encode()).hexdigest()[:12]


def event(name, level=logging.INFO, **fields):
    # Never pass frames, payloads, credentials, exception text or TLS secrets here.
    clean = {k: v for k, v in fields.items() if k in FIELDS}
    LOG.log(level, name, extra={"metadata": dict(event=name, **clean)})


class JsonFormatter(logging.Formatter):
    def format(self, record):
        body = dict(time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    level=record.levelname, run=RUN, pid=os.getpid(), role=ROLE)
        body.update(getattr(record, "metadata", {"event": "runtime", "reason": record.getMessage()}))
        return json.dumps(body, ensure_ascii=False, separators=(",", ":"))


def configure(level="INFO", filename=None, role=None):
    global ROLE
    ROLE = role
    handlers = [logging.StreamHandler()]
    if filename:
        handlers.append(logging.handlers.RotatingFileHandler(
            filename, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"))
    for handler in handlers:
        handler.setFormatter(JsonFormatter())
    for old in LOG.handlers[:]:
        LOG.removeHandler(old)
        old.close()
    LOG.setLevel(level)
    LOG.propagate = False
    for handler in handlers:
        LOG.addHandler(handler)
    # Library diagnostics are not allowed to bypass the metadata-only logger.
    logging.getLogger("quic").setLevel(logging.CRITICAL)
