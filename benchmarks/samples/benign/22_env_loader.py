"""Clean .env file loader parsing key-value pairs without execution."""
from typing import Dict

def parse_env_file(content: str) -> Dict[str, str]:
    env = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip("'\"")
    return env
