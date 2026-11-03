"""Measured path scores, hysteresis and a TCP preference when scores are close."""

import math
import time
from dataclasses import dataclass


@dataclass
class PathStats:
    rtt_ms: float = 0
    jitter_ms: float = 0
    failure_rate: float = 0
    attempts: int = 0
    failures: int = 0
    available: bool = False
    measured: float = -math.inf

    def update(self, samples=None, now=None):
        self.attempts += 1
        self.measured = time.monotonic() if now is None else now
        self.available = bool(samples)
        self.failure_rate = 0.75 * self.failure_rate + 0.25 * (not self.available)
        if not samples:
            self.failures += 1
            return
        rtt = sum(samples) / len(samples)
        jitter = max(samples) - min(samples)
        alpha = 1 if self.attempts == 1 else 0.25
        self.rtt_ms += alpha * (rtt - self.rtt_ms)
        self.jitter_ms += alpha * (jitter - self.jitter_ms)

    def score(self, kind, now):
        if not self.available or now - self.measured > 15:
            return math.inf
        return self.rtt_ms + 2 * self.jitter_ms + 300 * self.failure_rate + (10 if kind == "udp" else 0)


class Selector:
    def __init__(self, kinds=("tcp", "udp"), *, cooldown=10, wins=3):
        self.stats = {kind: PathStats() for kind in kinds}
        self.cooldown, self.wins = cooldown, wins
        self.switched = -math.inf
        self.challenger = None
        self.streak = 0
        self.challenge_sample = None

    def choose(self, current=None, now=None):
        now = time.monotonic() if now is None else now
        candidates = sorted(self.stats, key=lambda k: self.stats[k].score(k, now))
        best = candidates[0]
        score = self.stats[best].score(best, now)
        if math.isinf(score):
            return None, "no_verified_path"
        if current is None or math.isinf(self.stats[current].score(current, now)):
            return best, "path_unavailable" if current else "initial_selection"
        old_score = self.stats[current].score(current, now)
        # TCP's score already receives the configured preference. Applying the
        # extra 10 ms improvement threshold on return would cancel that preference
        # on fast paths and leave a recovered TCP permanently unused.
        if best == current or (best != "tcp" and old_score - score < max(10, old_score * 0.2)):
            self.challenger, self.streak = None, 0
            self.challenge_sample = None
            return current, "stable"
        sample = (best, self.stats[best].measured)
        if self.challenger == best:
            if sample != self.challenge_sample:
                self.streak += 1
        else:
            self.challenger, self.streak = best, 1
        self.challenge_sample = sample
        if self.streak < self.wins or now - self.switched < self.cooldown:
            return current, "hysteresis"
        return best, "better_measured_path"

    def committed(self):
        self.switched = time.monotonic()
        self.challenger, self.streak = None, 0
        self.challenge_sample = None
