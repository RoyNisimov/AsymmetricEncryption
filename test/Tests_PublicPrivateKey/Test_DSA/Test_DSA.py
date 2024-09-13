from unittest import TestCase
from AsymmetricEncryptions.PublicPrivateKey.DSA import DSA
from AsymmetricEncryptions.Exceptions import MACError

class TestRSA(TestCase):
    def test_sign_and_verify(self):
        message: bytes = b"DSA test"
        priv, pub = DSA.generate_key_pair(1024)
        cipher = DSA(priv)
        sig = cipher.sign(message)
        cipher = DSA(pub)
        self.assertEqual(cipher.verify(sig, message), None)

    def test_sign_and_verify_err(self):
        message: bytes = b"DSA test"
        priv, pub = DSA.generate_key_pair(1024)
        cipher = DSA(priv)
        sig = cipher.sign(message)
        cipher = DSA(pub)
        self.assertRaises(MACError,cipher.verify,[sig[0] -1, sig[1]], message)

