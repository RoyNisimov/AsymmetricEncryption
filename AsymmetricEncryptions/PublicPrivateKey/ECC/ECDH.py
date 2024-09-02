from AsymmetricEncryptions.PublicPrivateKey.ECC import ECPoint, ECKey

class ECDH:
    """Elliptic Curve Diffie-Hellman"""
    def __init__(self, key_pairA: ECKey) -> None:
        """
        :param key_pairA: Alice's key pair
        """
        self.key_pairA: ECKey = key_pairA

    def Stage1(self, B: ECPoint) -> ECPoint:
        """
        :param B: Bob's public key
        :return: Shared ECPoint (Use KDF.derive_key(bytes(shared_point)) to get a key)
        """
        return B * self.key_pairA.private_key

    @staticmethod
    def Stage2(key_pairB: ECKey, A: ECPoint) -> ECPoint:
        """
        :param key_pairB: Bob's private key pair
        :param A: Alice's public key
        :return: Shared ECPoint (Use KDF.derive_key(bytes(shared_point)) to get a key)
        """
        return A * key_pairB.private_key


