from AsymmetricEncryptions.PublicPrivateKey.RSA import RSAKey, RSA
from AsymmetricEncryptions.PublicPrivateKey.DLIES import DLIESKey
from AsymmetricEncryptions.Protocols.SchnorrPOK import POK
from AsymmetricEncryptions.General import XOR, BytesAndInts
from AsymmetricEncryptions.Exceptions import MACError
from hashlib import sha256
import hmac
import secrets

"""Implementation of a group signature scheme named "Pretty Secure Group Signature" designed by Roy Nisimov (That's me), this could be insecure, I don't know everything"""

class PSGS:
    def __init__(self, nBit: int):
        self.private_key_d, self.public_e_n = RSA.generate_key_pair(nBit)
        g_p = DLIESKey.new(nBit)
        self.g = g_p.g
        self.p = g_p.n
        self.public_keys = []

    def get_pub(self) -> RSAKey and int and int:
        return self.public_e_n, self.g, self.p

    @staticmethod
    def build_key(public_params: RSAKey and int and int):
        x = secrets.randbelow(public_params[2])
        k = DLIESKey.build(public_params[1], public_params[2], x)
        return k.public, k

    def sign_member_key(self, proof: tuple[int, int, DLIESKey], y: DLIESKey):
        if not y == proof[2]: raise MACError("Keys don't match with proof!")
        if not self.g == y.g: raise MACError("Keys don't match with proof!")
        if not self.p == y.n: raise MACError("Keys don't match with proof!")
        v = POK.verify(proof)
        if not v: raise MACError("Proof failed!")
        # member knows the private key x!
        self.public_keys.append(y)
        return pow(y.y, self.private_key_d.d, self.public_e_n.n)

    @staticmethod
    def sign(m: bytes, g: int, p: int, e: int, n: int, sy: int, symmetric_encryption_function: callable = XOR.repeated_key_xor_with_scrypt_kdf) -> bytes and tuple[int, int, bytes]:
        m = sha256(m).digest()
        k: bytes = sha256(m + f"{g}{p}{e}{n}".encode("utf-8")).digest()
        cipher = symmetric_encryption_function(m, k)
        mac = hmac.new(cipher, k, sha256).digest()
        # 32 bytes of mac
        sig_a = mac + cipher
        # sig b part
        z = secrets.token_bytes(16)
        c1 = BytesAndInts.byte2Int(sha256(k + z).digest())
        c2 = BytesAndInts.byte2Int(sha256(f"{g}{p}".encode() + m).digest())
        S = pow(sy, c1, n)
        r = pow(S, c2, n)
        sig_b = (r, S, z)
        return sig_a, sig_b

    @staticmethod
    def verify(sig: bytes and tuple[int, int, bytes], m: bytes, g: int, p: int, e: int, n: int, symmetric_decryption_function: callable = XOR.repeated_key_xor_with_scrypt_kdf) -> None:
        m = sha256(m).digest()
        sig_a = sig[0]
        sig_b = sig[1]
        k: bytes = sha256(m + f"{g}{p}{e}{n}".encode("utf-8")).digest()
        found_hmac = sig_a[:32]
        ciphertext = sig_a[32:]
        mac = hmac.new(ciphertext, k, sha256).digest()
        v = hmac.compare_digest(mac, found_hmac)
        if not v: raise MACError("Mac's don't match, person isn't from the group")
        pt = symmetric_decryption_function(ciphertext, k)
        if not pt == m: raise MACError(f"Signature is faulty, m and pt don't match\nm: {m}\npt: {pt}")
        # verify sig_b:
        z = sig_b[2]
        c1 = BytesAndInts.byte2Int(sha256(k + z).digest())
        c2 = BytesAndInts.byte2Int(sha256(f"{g}{p}".encode() + m).digest())
        r = sig_b[0]
        S = sig_b[1]
        v = pow(r, e, n)
        w = pow(pow(S, c2, n), e, n)
        if v != w: raise MACError("Signature is faulty, Signer's identity is hidden")
        v = pow(pow(r, e, n), c1, n)
        w = pow(pow(pow(S, c2, n), e, n), c1, n)
        if v != w: raise MACError("Signature is faulty, Signer's identity is hidden")


    def trace(self,sig: bytes and tuple[int, int, bytes], m: bytes, g: int, p: int, e: int, n: int, symmetric_decryption_function: callable = XOR.repeated_key_xor_with_scrypt_kdf) -> DLIESKey or None:
        PSGS.verify(sig, m, g, p, e, n)
        m = sha256(m).digest()
        k: bytes = sha256(m + f"{g}{p}{e}{n}".encode("utf-8")).digest()
        sig_b = sig[1]
        z = sig_b[2]
        c1 = BytesAndInts.byte2Int(sha256(k + z).digest())
        S = sig_b[1]
        for y in self.public_keys:
            if pow(S, e, n) == pow(y.y, c1, n):
                return y
        return None


