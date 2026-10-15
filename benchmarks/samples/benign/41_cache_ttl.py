"""TTL cache item with expiry timestamp."""
import time

class ExpiringItem:
    def __init__(self, value, ttl_seconds: float):
        self.value = value
        self.expires_at = time.time() + ttl_seconds

    def is_expired(self) -> bool:
        return time.time() > self.expires_at
