"""Email format validation using regex."""
import re

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def is_valid_email(email: str) -> bool:
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_REGEX.match(email))
