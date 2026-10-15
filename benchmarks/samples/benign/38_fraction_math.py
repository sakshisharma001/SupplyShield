"""Fraction calculation using fractions standard module."""
from fractions import Fraction

def add_fractions(n1: int, d1: int, n2: int, d2: int) -> str:
    f = Fraction(n1, d1) + Fraction(n2, d2)
    return f"{f.numerator}/{f.denominator}"
