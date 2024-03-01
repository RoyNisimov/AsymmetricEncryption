from __future__ import annotations
from .LWEKey import LWEKey
from AsymmetricEncryptions.General import BytesAndInts
import secrets


class LWE:
    """
    Learning With Errors
    """
    def __init__(self, key: LWEKey):
        self.key: LWEKey = key

    @staticmethod
    def encrypt_one_bit(key: LWEKey, m: int) -> tuple[int, int]:
        """
        Encrypts one bit, m will be either 0 or 1
        """
        m: int = m % 2
        number_of_samples: int = secrets.randbelow(key.q % len(key.A) + 1)
        while number_of_samples == 1: number_of_samples: int = secrets.randbelow(key.q % len(key.A) + 1)
        u: list[int] = []
        v: list[int] = []
        for _ in range(number_of_samples):
            r: int = secrets.randbelow(len(key.A))
            u.append(key.A[r])
            v.append(key.B[r])
        half_q_times_m: int = (key.q // 2) * m
        return (sum(u) % key.q), (sum(v) - half_q_times_m) % key.q

    def decrypt_one_bit(self, ciphertext: tuple[int, int]) -> int:
        """
        Decrypts a bit
        """
        u, v = ciphertext
        dec: int = (v - (self.key.s * u)) % self.key.q
        return int(dec > (self.key.q // 2))


    @staticmethod
    def encrypt_message(key: LWEKey, message: bytes) -> list[tuple[int, int]]:
        """
        Encrypts a message (bytes)
        """
        m: int = BytesAndInts.byte2Int(message)
        out: list[int] = []
        for bit in format(m, "b"):
            bit = int(bit)
            out.append(LWE.encrypt_one_bit(key, bit))
        return out

    def decrypt_message(self, ciphertexts: list[tuple[int, int]]) -> bytes:
        """
        Decrypts a ciphertext
        """
        st: str = ""
        for index, i in enumerate(ciphertexts):
            st += str(self.decrypt_one_bit(i))
        return BytesAndInts.int2Byte(int(st, 2))
