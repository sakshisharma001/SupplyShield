"""URL query string parser using urllib.parse."""
import urllib.parse
from typing import Dict, List

def parse_query_params(url_string: str) -> Dict[str, List[str]]:
    parsed = urllib.parse.urlparse(url_string)
    return urllib.parse.parse_qs(parsed.query)
