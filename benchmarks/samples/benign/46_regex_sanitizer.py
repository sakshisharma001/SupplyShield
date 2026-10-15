"""Sanitize dynamic input for regex queries."""
import re

def escape_regex_term(query: str) -> str:
    return re.escape(query)
