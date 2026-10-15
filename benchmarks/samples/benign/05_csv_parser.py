"""CSV data reader and processor."""
import csv
import io
from typing import List, Dict

def parse_csv_stream(csv_content: str) -> List[Dict[str, str]]:
    stream = io.StringIO(csv_content)
    reader = csv.DictReader(stream)
    return [row for row in reader]

def write_csv_stream(rows: List[Dict[str, str]], fieldnames: List[str]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()
