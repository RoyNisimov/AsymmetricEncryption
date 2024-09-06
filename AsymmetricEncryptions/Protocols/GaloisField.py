from __future__ import annotations

class GaloisField:

    def __init__(self, v: [int], primitive_poly: [int], deg: int = 128):
        self.v: [int] = v
        self.deg: int = deg
        self.primitive_poly: [int] = primitive_poly

    def set_v(self, v):
        self.v = v

    @staticmethod
    def pad(a: GaloisField, b: GaloisField) -> (GaloisField, GaloisField):
        if len(a.v) == len(b.v): return a, b
        if len(a.v) < len(b.v):
            # a needs padding
            p: int = len(b.v) - len(a.v)
            v: list[int] = a.v.copy()
            [v.insert(0, 0) for _ in range(p)]
            a.set_v(v)
        if len(a.v) > len(b.v):
            # b needs padding
            p: int = len(a.v) - len(b.v)
            v: list[int] = b.v.copy()
            [v.insert(0, 0) for _ in range(p)]
            b.set_v(v)
        return a, b


    def __add__(self, other: GaloisField) -> GaloisField:
        a: GaloisField = self.copy()
        b: GaloisField = other.copy()
        a, b = GaloisField.pad(a, b)
        return GaloisField([a.v[i] ^ b.v[i] for i in range(len(a.v))], self.primitive_poly, deg=self.deg)

    def strip0(self) -> GaloisField:
        v = self.v.copy()
        while v[0] == 0:
            v.pop(0)
        return GaloisField(v, self.primitive_poly, deg=self.deg)


    def __sub__(self, other: GaloisField) -> GaloisField:
        return self + other

    def copy(self):
        return GaloisField(self.v.copy(), self.primitive_poly.copy(), self.deg)

    def __mul__(self, other: GaloisField) -> GaloisField:
        r = GaloisField([0] * len(self.v), self.primitive_poly, self.deg)
        a = self.copy()
        b = other.copy()
        while 1 in a.v:
            r = r + b
            a = a >> 1
            b = b << 1
            a, b = GaloisField.pad(a, b)
        return r

    def __lshift__(self, other: int) -> GaloisField:
        v = self.v.copy()
        [v.append(0) for _ in range(other)]
        return GaloisField(v, self.primitive_poly, self.deg)

    def __rshift__(self, other: int) -> GaloisField:
        v: list[int] = self.v.copy()
        [v.insert(0, 0) for _ in range(other)]
        v = v[:-other]
        return GaloisField(v, self.primitive_poly, self.deg)

    def __str__(self):
        return str(self.v)
