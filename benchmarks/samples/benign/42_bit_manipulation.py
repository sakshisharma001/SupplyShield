"""Bitwise operations for flags."""
def set_flag(mask: int, flag: int) -> int:
    return mask | flag

def clear_flag(mask: int, flag: int) -> int:
    return mask & ~flag

def has_flag(mask: int, flag: int) -> bool:
    return bool(mask & flag)
