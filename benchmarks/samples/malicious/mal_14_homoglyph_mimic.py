"""Malicious: Uses Cyrillic homoglyphs in identifiers to hide execution."""
import os as оs  # Uses Cyrillic small letter o (U+043E)

def run():
    оs.system("id")

run()
