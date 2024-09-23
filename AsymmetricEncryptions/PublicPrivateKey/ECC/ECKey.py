from __future__ import annotations
from .ECPoint import ECPoint
from .ECCurve import ECCurve
from AsymmetricEncryptions.General import XOR, Exportation
import secrets
from hashlib import sha256
class ECKey:
    """Key object of ECC"""
    def __init__(self, pub: ECPoint, priv: int = None) -> None:
        """Use .new()"""
        self.private_key = priv
        self.public_key = pub
        self.curve = pub.curve

    def find_inverse(self):
        assert self.private_key is not None
        return pow(self.private_key, -1, self.curve.n)

    def get_public_key(self) -> ECKey:
        return ECKey(pub=self.public_key, priv=None)

    @staticmethod
    def new(curve: ECCurve) -> ECKey:
        """Creates a new ECKey pair"""
        priv: int = secrets.randbelow(curve.p)
        pub: ECPoint = curve.G * priv
        return ECKey(pub, priv)

    def export(self, file_name: str, pwd: bytes = b"\x00", *, enc_func=XOR.repeated_key_xor) -> None:
        """
        Exports the key into a file.
        :param file_name: The file to export into.
        :param pwd: Passphrase
        :param enc_func: symmetric encryption function (XOR / OTP here)
        :return: None
        """
        data_dict: dict = {"curve": self.public_key.curve.export(), "pub_x": self.public_key.x, "pub_y": self.public_key.y, "priv": self.private_key}
        Exportation.Exportation.export(file_name=file_name, pwd=pwd, data_dict=data_dict, exportation_func=enc_func)

    @staticmethod
    def load(file_name: str, pwd: bytes = b"\x00", *, dec_func=XOR.repeated_key_xor) -> ECKey:
        """
        Loads a key from a file
        :param file_name: The file name
        :param pwd: The password
        :param dec_func: symmetric decryption function (XOR / OTP here)
        :return: ECKey
        """
        data: dict = Exportation.Exportation.load(file_name=file_name, pwd=pwd, dec_func=dec_func)
        pub: ECPoint = ECPoint(ECCurve.load(data["curve"]), data["pub_x"], data["pub_y"])
        return ECKey(pub, data["priv"])


    def __str__(self):
        return f"{self.private_key = }\nself.public_key = {self.public_key}"

    def __eq__(self, other: ECKey) -> bool:
        if not isinstance(other, ECKey): return False
        return sha256(f"{self}".encode()).hexdigest() == sha256(f"{other}".encode()).hexdigest()
