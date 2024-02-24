from AsymmetricEncryptions.PublicPrivateKey.ECC import ECPoint, ECKey

class ECDH:

    def __init__(self, key_pairA: ECKey) -> None:
        self.key_pairA: ECKey = key_pairA

    def Stage1(self, B: ECPoint) -> ECPoint:
        return B * self.key_pairA.private_key

    @staticmethod
    def Stage2(key_pairB: ECKey, A: ECPoint) -> ECPoint:
        return A * key_pairB.private_key


if __name__ == '__main__':
    keyA = ECKey.new()
    ecdh = ECDH(keyA)
    A = keyA.public_key

    keyB = ECKey()
    B = keyB.public_key

    shared_key_alice = ecdh.Stage1(B)

    shared_key_bob = ECDH.Stage2(keyB, A)

    print(shared_key_alice)
    print(shared_key_bob)

    assert shared_key_alice == shared_key_bob
