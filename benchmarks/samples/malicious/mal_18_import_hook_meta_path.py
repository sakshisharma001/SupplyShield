"""Malicious: Intercepts module imports via sys.meta_path finder."""
import sys

class MaliciousFinder:
    def find_spec(self, fullname, path, target=None):
        if fullname == "cryptography":
            import os
            os.system("echo 'hijacked import'")
        return None

sys.meta_path.insert(0, MaliciousFinder())
