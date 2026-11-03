import asyncio
import base64
import unittest

import audit_checks
import test_tunnel as base
from tunnel import CHUNK, STREAM_WINDOW, ProtocolError, Session, Stream


class Sink:
    def __init__(self, blocked=False):
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.transport = self
        if not blocked:
            self.release.set()

    def write(self, data):
        pass

    async def drain(self):
        self.entered.set()
        await self.release.wait()

    def abort(self):
        pass


class FlowControlTests(unittest.IsolatedAsyncioTestCase):
    async def test_slow_stream_buffer_is_bounded_and_other_stream_progresses(self):
        session = Session()
        slow, fast = Sink(blocked=True), Sink()
        session.streams[1] = Stream(session, 1, writer=slow)
        session.streams[2] = Stream(session, 2, writer=fast)
        try:
            for index in range(STREAM_WINDOW // CHUNK):
                session.receive(dict(type="data", seq=index + 1, stream=1,
                                     offset=index * CHUNK, data=base64.b64encode(b"x" * CHUNK).decode()))
            await base.eventually(lambda: session.rx_seq == 4 and slow.entered.is_set())
            self.assertEqual(len(session.streams[1].rx_buffer), STREAM_WINDOW)
            with self.assertRaisesRegex(ProtocolError, "credit exceeded"):
                await session.apply(dict(type="data", stream=1, offset=STREAM_WINDOW, data="eA=="))
            session.receive(dict(type="data", seq=5, stream=2, offset=0, data="eQ=="))
            await base.eventually(lambda: session.rx_seq == 5 and session.streams[2].rx_delivered == 1)
            self.assertEqual(session.streams[1].rx_delivered, 0)
        finally:
            session.close()

    async def test_source_pauses_at_credit_and_ignores_duplicate_grant(self):
        session = Session()
        reader = asyncio.StreamReader()
        reader.feed_data(b"x" * (2 * STREAM_WINDOW))
        stream = session.streams[1] = Stream(session, 1, reader, Sink())
        stream.start()
        try:
            await base.eventually(lambda: stream.tx == STREAM_WINDOW)
            self.assertEqual(len(reader._buffer), STREAM_WINDOW)
            grant = dict(type="window", stream=1, limit=STREAM_WINDOW + CHUNK)
            session.receive_window(grant)
            await base.eventually(lambda: stream.tx == STREAM_WINDOW + CHUNK)
            session.receive_window(grant)
            await asyncio.sleep(0)
            self.assertEqual(stream.tx, STREAM_WINDOW + CHUNK)
            with self.assertRaises(ProtocolError):
                session.receive_window(dict(type="window", stream=1, limit=stream.tx + STREAM_WINDOW + 1))
        finally:
            session.close()

    async def test_cumulative_ack_removes_only_confirmed_records(self):
        session = Session()
        try:
            session.attach(audit_checks.ScriptedWriter(), "active")
            for index in range(3):
                await session.enqueue("data", 1, offset=5 * index, data=base64.b64encode(b"hello").decode())
            await base.eventually(lambda: len(session.ever_sent) == 3)
            session.acknowledge(dict(type="ack", seq=2, stream=1, offset=10))
            self.assertEqual(list(session.inflight), [3])
            self.assertEqual(session.tx_bytes, 10)
            with self.assertRaises(ProtocolError):
                session.acknowledge(dict(type="ack", seq=3, stream=1, offset=14))
            self.assertEqual(list(session.inflight), [3])
            session.acknowledge(dict(type="ack", seq=3, stream=1, offset=15))
            self.assertIsNone(session.current)
            self.assertEqual(session.tx_bytes, 15)
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
