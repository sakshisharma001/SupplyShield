"""Semantic version string comparator."""
from typing import Tuple

def parse_semver(version: str) -> Tuple[int, int, int]:
    clean = version.lstrip("v").split("-")[0]
    parts = clean.split(".")
    return int(parts[0]), int(parts[1]), int(parts[2])
