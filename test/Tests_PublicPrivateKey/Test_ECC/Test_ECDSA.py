from unittest import TestCase
from AsymmetricEncryptions.PublicPrivateKey.ECC import EllipticCurveNISTP256, ECKey, ECPoint, ECDSA
from secrets import randbelow
class TestECDSA(TestCase):
    def test_sign_and_verify(self):
        # Do this
        priv = ECKey.new(curve := EllipticCurveNISTP256.get_curve())
        pub = priv.get_public_key()
        m = b"Super cool message"
        signer = ECDSA(priv, pub)
        sig = signer.sign(m)
        v = ECDSA.verify(m, pub, sig)
        self.assertEqual(v, True)
        priv = ECKey.new(curve)
        pub = priv.get_public_key()
        m = b"Super cool message"
        signer = ECDSA(priv, pub)
        sig = signer.sign(m)
        v = ECDSA.verify(m+b"Not so cool", pub, sig)
        self.assertEqual(v, False)
        priv = ECKey.new(curve)
        pub = priv.get_public_key()
        m = b"Super cool message"
        signer = ECDSA(priv, pub)
        sig = signer.sign(m)
        sig = (sig[0], -1)
        v = ECDSA.verify(m, pub, sig)
        self.assertEqual(v, False)
        sig = (-1, sig[1])
        v = ECDSA.verify(m, pub, sig)
        self.assertEqual(v, False)

    def test_find_priv(self):
        # Never, ever, do this. this is to show that a misuse can cause a private key leakage. k needs to be random. You could (And maybe should) pass a hash of H(m || private_key) through a PRNG and put k as that.
        priv = ECKey.new(curve := EllipticCurveNISTP256.get_curve())
        pub = priv.get_public_key()
        mA = b"Super cool message A"
        mB = b"Super cool message B"
        signer = ECDSA(priv, pub)
        k = randbelow(curve.n-1)
        sigA = signer.sign(mA, k)
        # k is shared, thus a private key can be leaked. (Same with regular DSA)
        sigB = signer.sign(mB, k)
        private = ECDSA.find_private_key_when_nonce_is_reused(sigA, mA, sigB, mB, pub)
        self.assertEqual(priv.private_key, private)
