"""
AgentAudit Rate Limiter
========================
Per-session sliding window rate limiter. In-memory, no external dependencies.
 
Stays stateless to clients — internal state is purely a defensive bookkeeping layer
and is purged when sessions go idle.
 
Configuration (env vars):
  AGENTAUDIT_RATE_LIMIT            — max requests per window (default 60)
  AGENTAUDIT_RATE_WINDOW_SECONDS   — sliding window length in seconds (default 60)
"""
 
import os
import time
import threading
from collections import deque, defaultdict
 
 
_RATE_LIMIT = int(os.environ.get("AGENTAUDIT_RATE_LIMIT", "60"))
_WINDOW_SEC = int(os.environ.get("AGENTAUDIT_RATE_WINDOW_SECONDS", "60"))
# Idle sessions are purged after 5x the window length
_IDLE_PURGE_SEC = _WINDOW_SEC * 5
 
 
class _SlidingWindowLimiter:
    """
    Per-key sliding window rate limiter.
 
    check(key) returns (allowed: bool, retry_after_sec: int).
    Idle sessions are auto-purged on every check call to bound memory.
    """
 
    def __init__(self, limit: int, window_sec: int):
        self.limit = limit
        self.window_sec = window_sec
        self._buckets: dict = defaultdict(deque)
        self._last_seen: dict = {}
        self._lock = threading.Lock()
        self._last_purge = time.monotonic()
 
    def check(self, key: str) -> tuple:
        now = time.monotonic()
        cutoff = now - self.window_sec
 
        with self._lock:
            # Opportunistic idle-session purge — runs at most once per window
            if now - self._last_purge > self.window_sec:
                self._purge_idle_locked(now)
                self._last_purge = now
 
            bucket = self._buckets[key]
 
            # Drop timestamps that have aged out of the window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
 
            self._last_seen[key] = now
 
            if len(bucket) >= self.limit:
                oldest = bucket[0]
                retry_after = max(1, int((oldest + self.window_sec) - now) + 1)
                return False, retry_after
 
            bucket.append(now)
            return True, 0
 
    def _purge_idle_locked(self, now: float) -> int:
        idle_cutoff = now - _IDLE_PURGE_SEC
        stale = [k for k, t in self._last_seen.items() if t < idle_cutoff]
        for k in stale:
            self._buckets.pop(k, None)
            self._last_seen.pop(k, None)
        return len(stale)
 
    def stats(self) -> dict:
        with self._lock:
            return {
                "rate_limit": self.limit,
                "window_sec": self.window_sec,
                "active_sessions": len(self._buckets),
            }
 
 
# Module-level singleton
_limiter = _SlidingWindowLimiter(limit=_RATE_LIMIT, window_sec=_WINDOW_SEC)
 
 
async def check_rate_limit(session_id: str) -> None:
    """
    Enforce the rate limit for a session_id. Raises HTTPException(429)
    with a Retry-After header on exceed. Returns None on allowed.
    """
    from fastapi import HTTPException  # lazy import — keeps core class framework-free
    allowed, retry_after = _limiter.check(session_id)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"RATE_LIMIT_EXCEEDED: session '{session_id}' exceeded {_RATE_LIMIT} requests per {_WINDOW_SEC}s window",
            headers={"Retry-After": str(retry_after)},
        )
 
 
def get_rate_limit_config() -> dict:
    """Snapshot of limiter state for /health endpoint."""
    return _limiter.stats()