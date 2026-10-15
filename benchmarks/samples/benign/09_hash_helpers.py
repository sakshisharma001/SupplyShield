"""Cryptographic hashing wrappers using hashlib."""
import hashlib

def sha256_digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

def verify_checksum(content: bytes, expected_hash: str) -> bool:
    return hashlib.sha256(content).hexdigest().lower() == expected_hash.lower()
