"""
Sample 1: Legitimate Clean Math Package
Calculates statistical metrics with zero malicious behavior.
"""

def add(a: float, b: float) -> float:
    return a + b

def multiply(a: float, b: float) -> float:
    return a * b

def calculate_average(numbers: list) -> float:
    if not numbers:
        return 0.0
    return sum(numbers) / len(numbers)

if __name__ == "__main__":
    data = [10, 20, 30, 40, 50]
    print(f"[SafePackage] Calculated Average: {calculate_average(data)}")
