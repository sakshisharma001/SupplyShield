"""Malicious: Obfuscated Base64 decode evaluated dynamically."""
import base64

payload = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2lkJyk="
decoded = base64.b64decode(payload).decode("utf-8")
eval(decoded)
