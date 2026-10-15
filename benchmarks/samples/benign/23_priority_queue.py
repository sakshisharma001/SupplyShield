"""Heap-based priority queue wrapper."""
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
