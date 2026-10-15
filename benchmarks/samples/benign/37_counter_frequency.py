"""Word frequency counter with collections.Counter."""
from collections import Counter
import re

def top_frequent_words(text: str, n: int = 5):
    words = re.findall(r"\b[a-z]{3,}\b", text.lower())
    return Counter(words).most_common(n)
