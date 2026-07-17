"""Small, event-loop-local connection accounting for public listeners."""

from __future__ import annotations

from collections import Counter


class ConnectionLimiter:
    """Bound total and per-address connections without blocking the event loop."""

    def __init__(self, *, max_connections: int, max_per_ip: int) -> None:
        self.max_connections = max(1, int(max_connections))
        self.max_per_ip = max(1, int(max_per_ip))
        self._active = 0
        self._by_ip: Counter[str] = Counter()

    @staticmethod
    def _key(client_ip: str | None) -> str:
        return str(client_ip or "unknown").strip() or "unknown"

    def acquire(self, client_ip: str | None) -> bool:
        key = self._key(client_ip)
        if self._active >= self.max_connections or self._by_ip[key] >= self.max_per_ip:
            return False
        self._active += 1
        self._by_ip[key] += 1
        return True

    def release(self, client_ip: str | None) -> None:
        key = self._key(client_ip)
        if self._by_ip[key] > 1:
            self._by_ip[key] -= 1
        else:
            self._by_ip.pop(key, None)
        self._active = max(0, self._active - 1)

    @property
    def active(self) -> int:
        return self._active
