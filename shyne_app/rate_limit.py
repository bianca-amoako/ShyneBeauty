import threading
import time
from collections import defaultdict

_SENSITIVE_POST_PATHS = frozenset({
    "/change-password",
    "/account/settings",
})

_SENSITIVE_POST_LIMIT = 30   # requests per minute
_ADMIN_LIMIT = 60            # requests per minute
_WINDOW = 60.0               # seconds


class _RateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._buckets: dict = defaultdict(list)

    def is_allowed(self, key: str, limit: int, window: float) -> bool:
        now = time.monotonic()
        cutoff = now - window
        with self._lock:
            timestamps = self._buckets[key]
            while timestamps and timestamps[0] < cutoff:
                timestamps.pop(0)
            if len(timestamps) >= limit:
                return False
            timestamps.append(now)
            return True

    def cleanup(self, max_keys: int = 10_000) -> None:
        with self._lock:
            if len(self._buckets) <= max_keys:
                return
            now = time.monotonic()
            stale = [k for k, v in self._buckets.items() if not v or v[-1] < now - 120]
            for k in stale:
                del self._buckets[k]


_limiter = _RateLimiter()


def check_rate_limit(ip: str, path: str, method: str) -> bool:
    if method == "POST" and path in _SENSITIVE_POST_PATHS:
        return _limiter.is_allowed(f"post:{ip}:{path}", _SENSITIVE_POST_LIMIT, _WINDOW)

    if path.startswith("/admin"):
        return _limiter.is_allowed(f"admin:{ip}", _ADMIN_LIMIT, _WINDOW)

    return True
