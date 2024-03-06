from __future__ import annotations
from AsymmetricEncryptions.PublicPrivateKey.DLIES import DLIESKey
from AsymmetricEncryptions.Protocols import POK, KDF
from AsymmetricEncryptions.General import PrimeNumberGen, BytesAndInts
import secrets
import warnings
"""
The YAK is a public-key authenticated key-agreement protocol, proposed by Feng Hao in 2010.
It is claimed to be the simplest authenticated key exchange protocol among the related schemes, including MQV, HMQV, Station-to-Station protocol, SSL/TLS etc.
he authentication is based on public key pairs. As with other protocols, YAK normally requires a Public Key Infrastructure to distribute authentic public keys to the communicating parties. 
The security of YAK is disputed.
"""
class YAK:
    def __init__(self, g: int, q: int):
        self.g: int = g
        self.q: int = q

    @staticmethod
    def new(nBit: int = 2048) -> YAK:
        """
        Generates a new YAK object
        @param nBit: how big q is
        @return: YAK object
        """
        warnings.warn("YAK security is debatable")
        q: int = PrimeNumberGen.generate(nBit)
        g: int = secrets.randbelow(q)
        return YAK(g, q)

    def get_gq(self) -> tuple[int, int]:
        return self.g, self.q



    def stage_1(self) -> list[int, tuple[int, tuple[int, int, DLIESKey]]]:
        """
        First stage of the key exchange
        @return: list[int, tuple[int, tuple[int, int, DLIESKey]]]. [0] is private! Send only [1]!
        """
        x_or_y: int = secrets.randbelow(self.q - 1)
        g_x_or_y: int = self.helper(x_or_y)
        msg: bytes = BytesAndInts.int2Byte(x_or_y)
        dummy_key: DLIESKey = DLIESKey.build(self.g, self.q, x_or_y)
        proof: tuple[int, int, DLIESKey] = POK(dummy_key).prove(msg)
        return [x_or_y, (g_x_or_y, proof)]

    def helper(self, x: int) -> int:
        return pow(self.g, x, self.q)


    def stage_2(self, x_or_y: int, private_key: DLIESKey, other: tuple[int, tuple[int, int, DLIESKey]], public_key: DLIESKey) -> bytes:
        """
        The final stage of YAK
        @param x_or_y: The private int, (stage_1[0])
        @param private_key: You're private key
        @param other: stage_1[1]
        @param public_key: The other's public key.
        @return: Key as bytes
        """
        g_x_or_y, proof = other
        assert POK.verify(proof)
        K = pow((g_x_or_y * public_key.y), x_or_y + private_key.x, self.q)
        return KDF.derive_key(BytesAndInts.int2Byte(K))

