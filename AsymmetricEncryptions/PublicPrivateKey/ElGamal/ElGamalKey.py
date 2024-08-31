from __future__ import annotations
import secrets
from AsymmetricEncryptions.General import PrimeNumberGen, XOR, Exportation
from AsymmetricEncryptions.Interfaces import IKey
import hashlib

class ElGamalKey(IKey):
    """ElGamal key object"""
    def __init__(self, p: int, g: int, y: int, x: int or None = None) -> None:
        """Use .new()"""
        self.p: int = p
        self.g: int = g
        self.y: int = y
        self.x: int = x
        self.has_private: bool = False
        if x:
            self.has_private = True
            self.public: ElGamalKey = ElGamalKey(p=p, g=g, y=y, x=None)

    def __eq__(self, other):
        if not isinstance(other, ElGamalKey): return False
        return hashlib.sha256(f"{self}".encode()).hexdigest() == hashlib.sha256(f"{other}".encode()).hexdigest()

    def __str__(self) -> str:
        r: str = ""
        if self.has_private:
            r += f"""
Private Key:

p = {self.p}
q = {self.g}
x = {self.x}
y = {self.y}
"""
        r += f"""
Public Key:

p = {self.p}
q = {self.g}
y = {self.y}
"""
        return r

    @staticmethod
    def new(nBit) -> ElGamalKey:
        """
        Returns a new ElGamalKey object
        :param nBit: key length
        :return: ElGamalKey
        """
        if not isinstance(nBit, int):
            raise TypeError("bit_number must be an integer")
        if nBit < 0:
            raise ValueError("Bit number must be unsigned!")
        if not nBit % 2 == 0:
            raise ValueError("Bit number must be a power of two!")
        from AsymmetricEncryptions.General.PowerOf2 import isPowerOfTwo
        if not isPowerOfTwo(nBit):
            raise ValueError("Bit number must be a power of two!")
        p: int = PrimeNumberGen.generate(nBit)
        g: int = secrets.randbelow(p)
        x: int = secrets.randbelow(p)
        y: int = pow(g, x, p)
        return ElGamalKey(p=p, g=g, y=y, x=x)


    def export(self, file_name: str, pwd: bytes = b"\x00", *, enc_func=XOR.repeated_key_xor) -> None:
        """
        Exports the key.
        :param file_name: File name
        :param pwd: Passphrase
        :param enc_func: Symmetric encryption function (Without touching it, it's XOR / OTP)
        :return: None
        """
        data_dict: dict = {"p": self.p, "g": self.g, "y": self.y, "x": self.x}
        Exportation.export(file_name=file_name, pwd=pwd, data_dict=data_dict, exportation_func=enc_func)

    @staticmethod
    def load(file_name: str, pwd: bytes = b"\x00", *, dec_func=XOR.repeated_key_xor) -> ElGamalKey:
        """
        Loads a key from a file.
        :param file_name: File name
        :param pwd: Passphrase
        :param dec_func: Symmetric decryption function (Without touching it, it's XOR / OTP)
        :return: ElGamalKey if it succeeds.
        """
        return ElGamalKey(**Exportation.load(file_name=file_name, pwd=pwd, dec_func=dec_func))
