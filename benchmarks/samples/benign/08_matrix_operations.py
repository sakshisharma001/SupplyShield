"""Simple pure Python matrix math."""
from typing import List

Matrix = List[List[float]]

def matrix_add(a: Matrix, b: Matrix) -> Matrix:
    rows = len(a)
    cols = len(a[0])
    return [[a[r][c] + b[r][c] for c in range(cols)] for r in range(rows)]

def matrix_transpose(m: Matrix) -> Matrix:
    return [[m[j][i] for j in range(len(m))] for i in range(len(m[0]))]
