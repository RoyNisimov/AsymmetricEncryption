from AsymmetricEncryptions.PublicPrivateKey.ECC import ECKey, ECPoint, ECCurve
from AsymmetricEncryptions.General import BytesAndInts
from hashlib import sha256
from warnings import warn
import secrets

class ECDSA:

    def __init__(self, private_key: ECKey, public_key: ECKey, nonces: set = None):
        self.private_key = private_key
        self.public_key = public_key
        self.nonces = set()
        if nonces is not None:
            self.nonces = nonces

    def sign(self, m: bytes, k=None):
        e: int = BytesAndInts.byte2Int(sha256(m).digest())
        if k is None:
            k: int = secrets.randbelow(self.private_key.curve.n - 1)
            hash_k = sha256(f"{k}".encode()).digest()
            if hash_k in self.nonces: return self.sign(m)
            self.nonces.add(hash_k)
        else: warn(f"\nIf k is static and not random the security is compromised.\n\nm: {m}, k: {k}\n\n")

        r: ECPoint = self.private_key.curve.g() * k
        r: int = r.x
        if r == 0:
            return self.sign(m)
        inv_k: int = self.private_key.curve.find_inverse(k)
        s = (inv_k * (e + r*self.private_key.private_key)) % self.private_key.curve.n
        if s == 0: return self.sign(m)
        return r, s

    @staticmethod
    def verify(m: bytes, public_key: ECKey, signature: tuple[int, int]) -> bool:
        if not  public_key.public_key != public_key.curve.infinity(): return False
        if not  public_key.curve.is_on_curve(public_key.public_key): return False
        if not public_key.public_key * public_key.curve.n == public_key.curve.infinity(): return False
        r, s = signature
        if not 1 < r < (public_key.curve.n - 1) or not 1 < s < (public_key.curve.n - 1): return False
        e: int = BytesAndInts.byte2Int(sha256(m).digest())
        inv_s = public_key.curve.find_inverse(s)
        u1: int = (e * inv_s) % public_key.curve.n
        u2: int = (r * inv_s) % public_key.curve.n
        G: ECPoint = public_key.curve.g()
        w = G * u1 + public_key.public_key * u2
        if w == public_key.curve.infinity(): return False
        return r == w.x

    @staticmethod
    def find_private_key_when_nonce_is_reused(sigA: tuple[int, int], mA: bytes, sigB: tuple[int, int], mB: bytes, public_key: ECKey):
        rA, sA = sigA
        rB, sB = sigB
        assert rA == rB and sA != sB
        eA: int = BytesAndInts.byte2Int(sha256(mA).digest())
        eB: int = BytesAndInts.byte2Int(sha256(mB).digest())
        n: int = public_key.curve.n
        k = ((eA - eB) % n) * pow((sA - sB) % n, -1, n)
        priv = ((sA * k - eA) % n) * pow(rA, -1, n)
        priv %= n
        return priv
