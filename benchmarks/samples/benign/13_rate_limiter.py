"""Token bucket rate limiter in pure Python."""
import time

class TokenBucket:
    def __init__(self, capacity: int, refill_rate_per_sec: float):
        self.capacity = capacity
        self.refill_rate = refill_rate_per_sec
        self.tokens = float(capacity)
        self.last_update = time.time()

    def consume(self, amount: int = 1) -> bool:
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(float(self.capacity), self.tokens + elapsed * self.refill_rate)
        self.last_update = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False
