"""Standard base64 encoding and decoding for binaries."""
import base64

def encode_thumbnail_bytes(image_bytes: bytes) -> str:
    return base64.b64encode(image_bytes).decode("ascii")
