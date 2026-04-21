from __future__ import annotations
from AsymmetricEncryptions.PostQuantumCryptography.Protocols.KyberPKE import KyberPKE
from AsymmetricEncryptions.PostQuantumCryptography.Util import Matrix, Polynomial
from AsymmetricEncryptions.Protocols.PRF import PRF
from AsymmetricEncryptions.General.BytesAndInts import BytesAndInts
from secrets import token_bytes
from hashlib import sha3_256, sha3_512

class KyberKEM:

    def __init__(self, seed=b""):
        if seed == b"":
            seed = token_bytes(16)
        self.pke = KyberPKE(seed, 3329, 256, 2, 2)

    def get_public(self) -> tuple[Matrix, bytes]:
        return self.pke.get_public_key()

    @staticmethod
    def initialise_handshake(Bse: Matrix, B_seed: bytes, q: int = 3329, degree: int = 256, n: int = 2, m: int = 2) -> tuple[tuple[Matrix, Polynomial], bytes, bytes]:
        p_row = token_bytes(32)
        h_plus = sha3_512(p_row).digest()
        k = h_plus[:32]
        L = h_plus[32:]
        prf = PRF(L)
        r_seed = BytesAndInts.int2Byte(prf.digest())
        e1_seed = BytesAndInts.int2Byte(prf.digest())
        e2_seed = BytesAndInts.int2Byte(prf.digest())
        ct = KyberPKE.encrypt(p_row, B_seed, Bse, q, degree, n, m, e1_seed, e2_seed, r_seed)
        return ct, k, p_row

    def finish_handshake(self, ct: tuple[Matrix, Polynomial]) -> bytes:
        p_row_prime = self.pke.decrypt(ct[0].copy(), ct[1].copy())
        h_plus = sha3_512(p_row_prime).digest()
        k = h_plus[:32]
        L = h_plus[32:]
        prf = PRF(L)
        r_seed = BytesAndInts.int2Byte(prf.digest())
        e1_seed = BytesAndInts.int2Byte(prf.digest())
        e2_seed = BytesAndInts.int2Byte(prf.digest())
        Bse, B_seed = self.get_public()
        ct_prime = KyberPKE.encrypt(p_row_prime, B_seed, Bse, 3329, 256, 2, 2, error_seed=e1_seed, error_seed2=e2_seed, r_seed=r_seed)
        if ct_prime == ct: return k
        return None



if __name__ == "__main__":
    k = KyberKEM()
    ct, key, row = KyberKEM.initialise_handshake(k.get_public()[0], k.get_public()[1])
    kprime = k.finish_handshake(ct)
    print(kprime, key)





