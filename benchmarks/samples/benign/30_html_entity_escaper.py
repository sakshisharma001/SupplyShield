"""HTML escaping utilities."""
import html

def sanitize_user_input(raw_html: str) -> str:
    return html.escape(raw_html, quote=True)
