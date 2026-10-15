"""Breadth-first and depth-first search in pure Python."""
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
