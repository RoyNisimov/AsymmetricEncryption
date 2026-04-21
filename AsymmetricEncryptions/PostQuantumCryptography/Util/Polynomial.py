from __future__ import annotations
from AsymmetricEncryptions.PostQuantumCryptography.Util.Term import Term
from AsymmetricEncryptions.Protocols.PRF import PRF
from AsymmetricEncryptions.General.BytesAndInts import BytesAndInts

class Polynomial:

    def __init__(self, q:int , degree=256, coeff:list[int] = None):
        if coeff == None: coeff: list[int] = []
        self.q = q
        self.degree = degree
        self.terms: list[Term] = []
        for i in range(degree):
            x = 0
            if i<len(coeff): x = coeff[i]
            self.terms.append(Term(x, i) % q)


    def __str__(self):
        s = ""
        for i, t in enumerate(self.terms):
            s += f"{t}"
            if i + 1 < len(self.terms): s += " + "
        return s

    def __add__(self, other: Polynomial | Term | int):
        l = self.terms.copy()
        if isinstance(other, int):
            l[0] += other
            return Polynomial(self.q, self.degree, l)
        if isinstance(other, Term):
            if other.degree > len(l): return self
            l[other.degree] = l[other.degree].add_coeff(other, self.q)
            return Polynomial(self.q, self.degree, l)
        if not isinstance(other, Polynomial): return self
        for i, t in enumerate(self.terms):
            if i < len(other.terms):
                l[i] = l[i].add_coeff(other.terms[i], self.q)
            else:
                break
        return Polynomial(self.q, self.degree, l)

    def round(self):
        for t in self.terms:
            t.round(self.q)

    def compress(self, d: int=4):
        for i, t in enumerate(self.terms):
            t.compress(d, self.q)

    def decompress(self, d: int=4):
        for i, t in enumerate(self.terms):
            t.decompress(d, self.q)

    @staticmethod
    def generate_low_polynomial(q: int, degree=256, seed: bytes = None) -> tuple[Polynomial, int]:
        theta = 4
        prf = PRF(seed)
        coeff = []
        for _ in range(degree):
            c = prf.digest() % theta
            if c > theta//2: c = c - theta
            coeff.append(c)
        p = Polynomial(q, degree, coeff)
        return p, prf.starting_seed


    def round_to_absolutes(self):
        for i, t in enumerate(self.terms):
            c = (self.terms[i].coeff + self.q) % self.q
            if self.q // 4 < c < 3 * self.q // 4:
                self.terms[i].coeff = 1
            else:
                self.terms[i].coeff = 0

    def __sub__(self, other: Polynomial):
        return self + other*-1

    def __mul__(self, other: int | Polynomial):
        if isinstance(other, int):
            l = self.terms.copy()
            for i in range(len(l)):
                l[i] = ((l[i] * other) % self.q)
            return Polynomial(self.q, self.degree, l)
        if isinstance(other, Polynomial):
            b = [Term(0, i) for i in range(len(self.terms))]
            for i in range(len(self.terms)):
                for j in range(len(other.terms)):
                    t = (self.terms[i] * other.terms[j]) % self.q
                    t = t.modpom(self.degree) % self.q
                    b[t.degree] = (b[t.degree].add_coeff(t)).modpom(self.degree) % self.q
            return Polynomial(self.q, self.degree, b)

        return self

    @staticmethod
    def generate_polynomial(q: int, degree=256, seed: bytes = None) -> tuple[Polynomial, int]:
        prf = PRF(seed)
        coeff = []
        for _ in range(degree):
            coeff.append(prf.digest() % q)
        p = Polynomial(q, degree, coeff)
        return p, prf.starting_seed

    @staticmethod
    def transcribe_polynomial(m: bytes, q: int = 3329, degree: int = 256):
        integer_value = BytesAndInts.byte2Int(m)
        binary_string = bin(integer_value).replace('0b', '')
        l = [int(c) for c in binary_string][::-1]
        return Polynomial(q, degree, l)


if __name__ == "__main__":
    a = Polynomial(3329, 4, [-4, 1, 5, 10])
    b = Polynomial(3329, 4, [4, 1, 5, 2])

    print(a - b)

