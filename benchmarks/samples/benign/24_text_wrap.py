"""Paragraph text wrapping using standard textwrap."""
import textwrap

def format_terminal_box(message: str, width: int = 60) -> str:
    lines = textwrap.wrap(message, width=width)
    border = "+" + "-" * (width + 2) + "+"
    formatted = [border]
    for line in lines:
        formatted.append(f"| {line:<{width}} |")
    formatted.append(border)
    return "\n".join(formatted)
