"""Safe local file extension filtering with pathlib."""
from pathlib import Path
from typing import List

def get_py_filenames(root_dir: str) -> List[str]:
    p = Path(root_dir)
    return [f.name for f in p.glob("*.py")]
