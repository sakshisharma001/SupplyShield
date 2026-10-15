"""Malicious: Dynamic callable resolution evading static string matching."""
target_mod = getattr(__import__("o" + "s"), "sys" + "tem")
target_mod("whoami")
