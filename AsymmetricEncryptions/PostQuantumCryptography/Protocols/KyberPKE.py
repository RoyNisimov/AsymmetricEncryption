from __future__ import annotations
from AsymmetricEncryptions.PostQuantumCryptography.Util import Matrix, Polynomial
from AsymmetricEncryptions.General.BytesAndInts import BytesAndInts
from secrets import token_bytes

class KyberPKE:

    def __init__(self, private_seed=None, q: int = 3329, degree: int = 256,n: int = 2, m: int = 2):
        if private_seed is None: token_bytes(16)
        self.private_seed = private_seed
        self.error_seed = token_bytes(16)
        self.generator_seed = token_bytes(16)

        self.s = Matrix.random_mat_low_poly(q=q, degree=degree, seed=self.private_seed, n=n, m=1)
        self.B = Matrix.random_mat_poly(q=q, degree=degree, seed=self.generator_seed, n=n, m=m)
        self.e = Matrix.random_mat_low_poly(q=q, degree=degree, seed=self.error_seed, n=n, m=1)



        self.public = self.B * self.s + self.e

    @staticmethod
    def encrypt(msg: bytes, B_seed: bytes, Bse: Matrix, q: int = 3329, degree: int = 256, n: int = 2, m: int = 2) -> tuple[Matrix, Matrix]:
        error_seed = token_bytes(16)
        error_seed2 = token_bytes(16)
        r_seed = token_bytes(16)

        e1 = Matrix.random_mat_low_poly(q=q, degree=degree, seed=error_seed, n=1, m=m)
        e2, _ = Polynomial.generate_low_polynomial(q, degree, error_seed2)
        r = Matrix.random_mat_low_poly(q=q, degree=degree, seed=r_seed, n=1, m=m)

        B = Matrix.random_mat_poly(q=q, degree=degree, seed=B_seed, n=n, m=m)

        inflated_m = Polynomial.transcribe_polynomial(msg, q, degree) * (q//2)
        Bsere2m = Bse * r + inflated_m + e2
        Bre1 = B * r + e1
        Bre1.compress(10)
        Bsere2m.compress(4)
        return Bre1, Bsere2m

    def decrypt(self, Bre1: Matrix, Bsere2m: Matrix):
        Bre1.decompress(10)
        Bsere2m.decompress(4)
        d: Polynomial = Bsere2m - (self.s * Bre1)
        d.round_to_absolutes()
        bits = "".join(f"{d.terms[i].coeff}" for i in range(d.degree))[::-1]
        return BytesAndInts.int2Byte(int(bits, 2))




    def get_public_key(self) -> tuple[Matrix, bytes]:
        return self.public, self.generator_seed

if __name__ == "__main__":
    k = KyberPKE(b"test")
    print(k.get_public_key()[0], k.get_public_key()[1])
    c, c1 = KyberPKE.encrypt(b"\x06",  B_seed=k.get_public_key()[1],  Bse=k.get_public_key()[0])

    d = k.decrypt(c, c1)
    print(d)




