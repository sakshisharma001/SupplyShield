"""JWT payload unpadded base64 decode without secrets."""
import json
import base64

def decode_unverified_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT token format")
    payload_b64 = parts[1]
    padding = "=" * (4 - len(payload_b64) % 4)
    decoded_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
    return json.loads(decoded_bytes.decode("utf-8"))
