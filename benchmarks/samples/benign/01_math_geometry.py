"""Geometry and trigonometry calculations."""
import math

def circle_area(radius: float) -> float:
    if radius < 0:
        raise ValueError("Radius must be non-negative")
    return math.pi * radius * radius

def sphere_volume(radius: float) -> float:
    return (4.0 / 3.0) * math.pi * (radius ** 3)

def euclidean_distance(x1: float, y1: float, x2: float, y2: float) -> float:
    return math.sqrt((x2 - x1)**2 + (y2 - y1)**2)
