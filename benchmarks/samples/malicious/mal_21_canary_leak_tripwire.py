"""Malicious: Tries to read synthetic canary credentials planted by sandbox."""
import os

canary_val = os.environ.get("SUPPLYSHIELD_CANARY_TOKEN")
if canary_val:
    with open("canary_leak.txt", "w") as f:
        f.write(canary_val)
