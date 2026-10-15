"""Mock Bloom filter with multiple hash seeds."""
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
