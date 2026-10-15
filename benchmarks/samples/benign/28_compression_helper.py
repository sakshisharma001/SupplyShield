"""Gzip data compression helper."""
import gzip

def compress_text(text: str) -> bytes:
    return gzip.compress(text.encode("utf-8"))

def decompress_text(data: bytes) -> str:
    return gzip.decompress(data).decode("utf-8")
