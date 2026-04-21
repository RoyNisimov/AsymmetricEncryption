from __future__ import annotations


class Term:

    def __init__(self, coeff: int, degree: int):
        if isinstance(coeff, Term): coeff = coeff.coeff
        self.coeff = coeff
        self.degree = degree


    def __mod__(self, other: int):
        if isinstance(other, int):
            a = self.coeff % other
            if a > other // 2:
                a = a-other
            return Term(a, self.degree)


        return self

    def compress(self, d: int=10, q: int = 3329):
        self.coeff = ((self.coeff << d) + (q // 2)) // q % (1 << d)

    def decompress(self, d: int=10, q: int = 3329):
        self.coeff = ((self.coeff * q) + (1 << (d - 1))) >> d


    def modpom(self, deg):
        if self.degree >= deg:
            flip_sign, r = divmod(self.degree, deg)
            coeff = self.coeff * pow(-1, flip_sign)
            degree = r
            return Term(coeff, degree)
        return self

    def __str__(self):
        if self.coeff == 0: return "0"
        if self.coeff == 1: return f"x^{self.degree}"
        if self.degree == 0: return f"{self.coeff}"
        if self.degree == 1: return f"{self.coeff}x"
        return f"{self.coeff}x^{self.degree}"

    def __mul__(self, other: int | Term):
        if isinstance(other, int): return Term(self.coeff*other, self.degree)
        if isinstance(other, Term): return Term(self.coeff*other.coeff, self.degree + other.degree)
        return self

    def mulmod(self, t: Term, q: int=3329, n: int=256):
        return Term((self.coeff * t.coeff) % -q, self.degree + t.degree)

    def add_coeff(self, other: Term, q=None):
        if other.degree != self.degree:
            return self
        if q is not None:
            return Term((self.coeff + other.coeff) % q, self.degree)
        return Term(self.coeff + other.coeff, self.degree)

    def round(self, q):
        if -q//4 < self.coeff < q//4:
            self.coeff = 0
            return
        self.coeff = 1





if __name__ == "__main__":
    f = Term(51, 111)
    print(f)
    a = f % 50
    print(f)
    print(a)

    f = Term(2, 4)
    b = Term(5, 6)
    print(f)
    print(b)
    print(b * f)
    print(Term(2, 4).add_coeff(Term(5, 4)))