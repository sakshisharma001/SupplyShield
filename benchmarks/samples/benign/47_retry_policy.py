"""Simple exponential backoff calculator."""
def get_backoff_delay(attempt: int, base_delay: float = 0.5, max_delay: float = 10.0) -> float:
    delay = base_delay * (2 ** attempt)
    return min(delay, max_delay)
