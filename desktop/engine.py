"""Threaded asyncio adapter. Qt sees bounded metadata, never keys or payloads."""

import asyncio
import datetime
import logging
import logging.handlers
import queue
import threading
import time

from diagnostics import FIELDS, JsonFormatter, LOG, configure, event
from desktop.profiles import valid_key
from transports import quic_config, shutdown_channels, tls_client
from tunnel import AdaptiveClient, CHUNK, Session


class Events(logging.Handler):
    def __init__(self, publish):
        super().__init__()
        self.publish = publish

    def emit(self, record):
        metadata = getattr(record, "metadata", None)
        if not isinstance(metadata, dict) or not isinstance(metadata.get("event"), str):
            return
        safe = {k: v for k, v in metadata.items() if k == "event" or k in FIELDS}
        safe.update(time=datetime.datetime.now(datetime.timezone.utc).isoformat(), level=record.levelname)
        self.publish("log", safe)


def setup_logging(directory, publish):
    configure(filename=str(directory / "client.jsonl"), role="client")
    # Frozen Windows GUI apps do not have stderr. The rotating file remains.
    for handler in LOG.handlers[:]:
        if type(handler) is logging.StreamHandler:
            LOG.removeHandler(handler)
            handler.close()
    LOG.addHandler(Events(publish))


class Engine:
    def __init__(self):
        self.events = queue.Queue(512)
        self.thread = None
        self.loop = None
        self.stop_event = None
        self.session = None
        self.srtl = False
        self.stopping = False

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def publish(self, kind, data):
        item = (kind, data)
        try:
            self.events.put_nowait(item)
        except queue.Full:
            try:
                self.events.get_nowait()
            except queue.Empty:
                pass
            try:
                self.events.put_nowait(item)
            except queue.Full:
                pass  # Another producer won the slot; the queue stays bounded.

    def start(self, profile, key, ca):
        if self.running:
            raise RuntimeError("Сначала отключите текущий канал")
        valid_key(key)
        self.stopping, self.srtl = False, profile.srtl
        self.publish("state", {"status": "connecting"})
        self.thread = threading.Thread(target=self._run, args=(profile, key, ca), name="myownvpn-network", daemon=False)
        self.thread.start()

    def stop(self):
        self.stopping = True
        if self.loop and self.stop_event:
            try:
                self.loop.call_soon_threadsafe(self.stop_event.set)
            except RuntimeError:
                pass

    def set_srtl(self, enabled):
        self.srtl = bool(enabled)
        if self.loop:
            try:
                self.loop.call_soon_threadsafe(self._apply_srtl)
            except RuntimeError:
                pass

    def _apply_srtl(self):
        if self.session and not self.session.closed:
            self.session.set_srtl(self.srtl)

    def _run(self, profile, key, ca):
        try:
            asyncio.run(self.serve(profile, key, ca))
        except (OSError, ValueError, RuntimeError) as error:
            reason = "port_unavailable" if isinstance(error, OSError) and getattr(error, "errno", None) in (13, 48, 98, 10013, 10048) else "connection_setup_failed"
            event("client_error", logging.ERROR, reason=reason)
            self.publish("error", {"reason": reason})
        except Exception:
            event("client_error", logging.ERROR, reason="internal_error")
            self.publish("error", {"reason": "internal_error"})
        finally:
            self.loop = self.stop_event = self.session = None
            self.publish("stopped", {})

    async def serve(self, profile, key, ca):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        import hmac
        import pathlib
        trusted = x509.load_pem_x509_certificate(pathlib.Path(ca).read_bytes())
        if not hmac.compare_digest(trusted.fingerprint(hashes.SHA256()).hex(), profile.ca_sha256):
            self.publish("error", {"reason": "security_verification_failed"})
            return
        self.loop = asyncio.get_running_loop()
        self.stop_event = asyncio.Event()
        if self.stopping:
            self.stop_event.set()
        context = tls_client(str(ca))
        quic = quic_config(ca=str(ca), hostname=profile.server)
        endpoints = {kind: (profile.server, profile.port) for kind in ("tcp", "udp") if profile.transport in ("auto", kind)}
        session = self.session = Session(srtl=self.srtl)
        controller = AdaptiveClient(session, endpoints, key, context, profile.server, quic, interval=5)
        local = None
        runner = waiter = None
        started = time.monotonic()
        connected_once = False
        previous_time, previous_rx, previous_tx = started, 0, 0
        try:
            local = await asyncio.start_server(session.accept_local, "127.0.0.1", profile.local_port, limit=CHUNK)
            runner = asyncio.create_task(controller.run())
            waiter = asyncio.create_task(self.stop_event.wait())
            event("client_started", endpoint=f"127.0.0.1:{profile.local_port}", mode=profile.transport)
            while not self.stop_event.is_set() and not session.closed and not runner.done():
                now = time.monotonic()
                alive = session.writer is not None and controller.runner is not None and not controller.runner.done()
                connected_once = connected_once or alive
                elapsed = max(.001, now - previous_time)
                paths = {}
                for kind, stat in controller.selector.stats.items():
                    fresh = now - stat.measured <= 15
                    paths[kind] = dict(available=stat.available and fresh, measured=stat.attempts > 0,
                                       quarantined=kind in controller.quarantined,
                                       rtt_ms=round(stat.rtt_ms, 1) if stat.available and fresh else None,
                                       jitter_ms=round(stat.jitter_ms, 1), failure_rate=round(stat.failure_rate, 3))
                self.publish("state", dict(status="connected" if alive else "reconnecting" if connected_once else "connecting",
                    path=controller.active if alive else None, tx_bytes=session.tx_bytes, rx_bytes=session.rx_bytes,
                    tx_rate=max(0, session.tx_bytes - previous_tx) / elapsed,
                    rx_rate=max(0, session.rx_bytes - previous_rx) / elapsed,
                    uptime=int(now - started), paths=paths, srtl=session.srtl.enabled,
                    streams=sum(not stream.reset and not (stream.local_fin and stream.remote_fin) for stream in session.streams.values())))
                previous_time, previous_rx, previous_tx = now, session.rx_bytes, session.tx_bytes
                done, _ = await asyncio.wait((runner, waiter), timeout=1, return_when=asyncio.FIRST_COMPLETED)
                if done:
                    break
            if runner.done():
                await runner
            if not self.stop_event.is_set():
                reason = "security_verification_failed" if session.reason in ("no_authenticated_path", "security_verification_failed") else "session_expired"
                self.publish("error", {"reason": reason})
        finally:
            if local:
                local.close()
                await local.wait_closed()
            for task in (runner, waiter):
                if task:
                    task.cancel()
            session.close("client_stopped")
            await asyncio.gather(*[task for task in (runner, waiter) if task], return_exceptions=True)
            await session.wait_closed()
            await shutdown_channels()
