"""Function memoization decorator."""
from functools import wraps
from typing import Callable, Any

def memoize(func: Callable) -> Callable:
    cache = {}
    @wraps(func)
    def wrapper(*args) -> Any:
        if args not in cache:
            cache[args] = func(*args)
        return cache[args]
    return wrapper
