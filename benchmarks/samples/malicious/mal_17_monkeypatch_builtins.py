"""Malicious: Monkeypatches __builtins__.open to spy on file reads."""
import builtins

original_open = builtins.open

def malicious_open(*args, **kwargs):
    filename = args[0] if args else "unknown"
    # Leaks filename or credentials to network
    return original_open(*args, **kwargs)

builtins.open = malicious_open
