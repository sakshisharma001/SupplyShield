"""Merge overlapping intervals algorithm."""
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
