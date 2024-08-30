from unittest import TestCase
from AsymmetricEncryptions.PublicPrivateKey.RSA import RSA
from AsymmetricEncryptions import BytesAndInts, Exceptions
from secrets import token_bytes
class TestRSA(TestCase):

    def test_generate_key_pair(self):
        priv, pub = RSA.generate_key_pair(256)
        self.assertEqual((pub.e * priv.d) % priv.tot_n, 1)

    def test_generate_key_pair_type(self):
        self.assertRaises(TypeError, RSA.generate_key_pair, "test")
        self.assertRaises(TypeError, RSA.generate_key_pair, b"test")

    def test_generate_key_pair_values(self):
        self.assertRaises(ValueError, RSA.generate_key_pair, -2)
        self.assertRaises(ValueError, RSA.generate_key_pair, 5)

    def test_encrypt(self):
        priv, pub = RSA.generate_key_pair(256)
        cipher = RSA(pub)
        c = cipher.encrypt(b"\x03")
        self.assertEqual(c, BytesAndInts.int2Byte(pow(3, pub.e, pub.n)))

    def test_encrypt_type(self):
        priv, pub = RSA.generate_key_pair(256)
        cipher = RSA(pub)
        self.assertRaises(TypeError, cipher.encrypt, "test")

    def test_load(self):
        priv, pub = RSA.generate_key_pair(256)
        cipher = RSA(pub)
        c = cipher.encrypt(b"test")
        cipher = RSA(priv)
        self.assertEqual(b"test", cipher.decrypt(c))

    def test_sign_verify(self):
        priv, pub = RSA.generate_key_pair(256)
        cipher = RSA(priv)
        b = token_bytes(16)
        sig = cipher.sign(b)
        self.assertEqual(cipher.verify(sig, b), None)
        priv, pub = RSA.generate_key_pair(256)
        cipher = RSA(priv)
        b = token_bytes(16)
        sig = cipher.sign(b)
        self.assertRaises(Exceptions.MACError, cipher.verify,sig[:-1], b)

