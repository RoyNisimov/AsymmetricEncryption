from __future__ import annotations
from AsymmetricEncryption.PublicPrivateKey.ECC.EllipticCurveNISTP256 import EllipticCurveNISTP256, ECPoint
import secrets
class ECKey:
    def __init__(self) -> None:
        self.private_key = secrets.randbelow(EllipticCurveNISTP256().n)
        self.public_key = EllipticCurveNISTP256().g() * self.private_key

    def __str__(self):
        return f"{self.private_key = }\n{self.public_key}"