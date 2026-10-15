"""Password entropy and strength evaluator."""
import math

def calculate_entropy(password: str) -> float:
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(not c.isalnum() for c in password): pool += 32
    if pool == 0 or len(password) == 0:
        return 0.0
    return len(password) * math.log2(pool)
