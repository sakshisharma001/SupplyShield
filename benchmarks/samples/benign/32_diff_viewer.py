"""Unified diff generator using difflib."""
import difflib

def generate_text_diff(old_lines: list, new_lines: list) -> str:
    diff = difflib.unified_diff(old_lines, new_lines, fromfile="before.txt", tofile="after.txt")
    return "\n".join(diff)
