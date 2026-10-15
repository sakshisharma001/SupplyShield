"""Generates Table of Contents from markdown headings."""
import re
from typing import List, Tuple

def extract_headings(markdown_text: str) -> List[Tuple[int, str]]:
    headings = []
    for line in markdown_text.splitlines():
        match = re.match(r'^(#{1,6})\s+(.*)$', line)
        if match:
            level = len(match.group(1))
            title = match.group(2).strip()
            headings.append((level, title))
    return headings
