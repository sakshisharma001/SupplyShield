"""HTTP cookie string parsing."""
from http import cookies

def parse_raw_cookies(cookie_header: str):
    simple_cookie = cookies.SimpleCookie()
    simple_cookie.load(cookie_header)
    return {k: v.value for k, v in simple_cookie.items()}
