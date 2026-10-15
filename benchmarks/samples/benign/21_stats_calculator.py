"""Mean, median, and variance calculations."""
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
