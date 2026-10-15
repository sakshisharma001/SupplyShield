"""Configuration loader using standard json."""
import json
from typing import Dict, Any

def parse_settings(json_raw: str) -> Dict[str, Any]:
    try:
        return json.loads(json_raw)
    except json.JSONDecodeError as err:
        return {"error": str(err), "valid": False}

def serialize_settings(data: Dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True)
