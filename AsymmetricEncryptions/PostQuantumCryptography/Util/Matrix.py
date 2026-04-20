from __future__ import annotations
from AsymmetricEncryptions.PostQuantumCryptography.Util.Polynomial import Polynomial
from hashlib import sha256

class Matrix:

    def __init__(self, n: int, m: int):
        self.n = n
        self.m = m
        self.mat = []
        for r in range(n):
            self.mat.append([])
            for c in range(m):
                self.mat[r].append(0)

    def fill_empty(self, q=3329, degree=256):
        for r in range(self.n):
            for c in range(self.m):
                self.mat[r][c] = Polynomial(q, degree)

    def transpose(self):
        self.mat = [list(row) for row in zip(*self.mat)]

    def __mul__(self, other: Matrix):
        if not isinstance(other, Matrix): return None
        if self.m == 1 and other.n == 1 and self.n == other.m:
            re = 0
            if isinstance(other.mat[0][0], Polynomial):
                re = Polynomial(other.mat[0][0].q, other.mat[0][0].degree)
            for r in range(self.n):
                re = re + self.mat[r][0] * other.mat[0][r]

            return re

        if other.m == 1 and other.n == self.n:
            # column vector
            mat = Matrix(self.n, 1)
            if isinstance(other.mat[0][0], Polynomial):
                mat.fill_empty()
            for r in range(self.n):
                for c in range(self.m):
                    mat.mat[r][0] = mat.mat[r][0] + self.mat[r][c] * other.mat[c][0]
            return mat
        if other.n == 1:
            # row vec
            mat = Matrix(1, self.m)
            if isinstance(other.mat[0][0], Polynomial):
                mat.fill_empty()
            for r in range(self.n):
                for c in range(self.m):
                    mat.mat[0][c] = mat.mat[0][c] + self.mat[r][c] * other.mat[0][r]
            return mat
        return None

    def __add__(self, other: Matrix | Polynomial):
        if isinstance(other, Polynomial):
            mat = Matrix(self.n, self.m)
            for r in range(self.n):
                for c in range(self.m):
                    mat.mat[r][c] = self.mat[r][c] + other
            return mat
        if not isinstance(other, Matrix): return None
        if self.n == other.n and self.m == other.m:
            mat = Matrix(self.n, self.m)
            if isinstance(other.mat[0][0], Polynomial):
                mat.fill_empty()
            for r in range(self.n):
                for c in range(self.m):
                    mat.mat[r][c] = self.mat[r][c] + other.mat[r][c]
            return mat
        if other.m == 1:
            # vector
            mat = Matrix(self.n, self.m)
            if isinstance(other.mat[0][0], Polynomial):
                mat.fill_empty()
            for r in range(self.n):
                for c in range(self.m):
                    mat.mat[r][c] = self.mat[r][c] + other.mat[c][0]
            return mat
        if other.n == 1:
            mat = Matrix(self.n, self.m)
            if isinstance(other.mat[0][0], Polynomial):
                mat.fill_empty()
            for r in range(self.n):
                for c in range(self.m):
                    mat.mat[r][c] = self.mat[r][c] + other.mat[0][c]
            return mat
        return None

    def __sub__(self, other):
        if isinstance(other, Polynomial):
            mat = Matrix(self.n, self.m)
            for r in range(self.n):
                for c in range(self.m):
                    mat.mat[r][c] = self.mat[r][c] - other
            return mat
        if not isinstance(other, Matrix): return None
        if other.m == 1:
            # vector
            mat = Matrix(self.n, self.m)
            if isinstance(other.mat[0][0], Polynomial):
                mat.fill_empty()
            for r in range(self.n):
                for c in range(self.m):
                    mat.mat[r][c] = self.mat[r][c] - other.mat[c][0]
            return mat
        if other.n == 1:
            mat = Matrix(self.n, self.m)
            if isinstance(other.mat[0][0], Polynomial):
                mat.fill_empty()
            for r in range(self.n):
                for c in range(self.m):
                    mat.mat[r][c] = self.mat[r][c] - other.mat[0][c]
            return mat
        if other.n == self.n and other.m == self.m:
            mat = Matrix(self.n, self.m)
            if isinstance(other.mat[0][0], Polynomial):
                mat.fill_empty()
            for r in range(self.n):
                for c in range(self.m):
                    mat.mat[r][c] = self.mat[r][c] - other.mat[r][c]
            return mat
        return None

    def __str__(self):
        s = "---" * self.n + "\n"
        for r in range(self.n):
            for c in range(self.m):
                s += f"{self.mat[r][c]} | "
            s += "\n"
        s += "---" * self.n
        return s

    @staticmethod
    def random_mat_poly(q: int, degree=256, seed: bytes = b"", n: int = 3, m: int = 3) -> Matrix:
        mat = Matrix(n, m)
        seed = sha256(seed).digest()
        for r in range(n):
            for c in range(m):
                mat.mat[r][c], _ = Polynomial.generate_polynomial(q, degree, seed)
                seed = sha256(seed).digest()
        return mat

    @staticmethod
    def random_mat_low_poly(q: int, degree=256, seed: bytes = b"", n: int = 3, m: int = 3) -> Matrix:
        mat = Matrix(n, m)
        seed = sha256(seed).digest()
        for r in range(n):
            for c in range(m):
                mat.mat[r][c], _ = Polynomial.generate_low_polynomial(q, degree, seed)
                seed = sha256(seed).digest()
        return mat
if __name__ == "__main__":
    B = Matrix(2, 2)
    B.mat[0][0] = -1
    B.mat[0][1] = 2
    B.mat[1][0] = 4
    B.mat[1][1] = 2
    print(B)
    r = Matrix(2, 1)
    r.mat[0][0] = 3
    r.mat[1][0] = -2
    print(r)
    print(B * r)
    B = Matrix(2, 2)
    B.mat[0][0] = -3
    B.mat[0][1] = 2
    B.mat[1][0] = 1
    B.mat[1][1] = 4
    print(B)
    r = Matrix(1, 2)
    r.mat[0][0] = 1
    r.mat[0][1] = 2
    print(r)
    print(B * r)




