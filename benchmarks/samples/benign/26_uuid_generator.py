"""UUID generation helpers."""
import uuid

def generate_prefixed_id(prefix: str = "item") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"
