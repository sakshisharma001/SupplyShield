"""RGB, HEX, and HSL color converters."""
from typing import Tuple

def hex_to_rgb(hex_code: str) -> Tuple[int, int, int]:
    clean = hex_code.lstrip("#")
    return int(clean[0:2], 16), int(clean[2:4], 16), int(clean[4:6], 16)

def rgb_to_hex(r: int, g: int, b: int) -> str:
    return f"#{r:02x}{g:02x}{b:02x}"
