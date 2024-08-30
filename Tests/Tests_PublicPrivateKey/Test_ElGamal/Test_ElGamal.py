from unittest import TestCase
from AsymmetricEncryptions.PublicPrivateKey.ElGamal import ElGamal
from AsymmetricEncryptions import BytesAndInts, Exceptions
from secrets import token_bytes
class TestRSA(TestCase):

    def test_generate_key_pair(self):
        priv, pub = ElGamal.generate_key_pair(256)
        self.assertEqual(pub.y, pow(pub.g, priv.x, pub.p))

    def test_generate_key_pair_type(self):
        self.assertRaises(TypeError, ElGamal.generate_key_pair, "test")
        self.assertRaises(TypeError, ElGamal.generate_key_pair, b"test")

    def test_generate_key_pair_values(self):
        self.assertRaises(ValueError, ElGamal.generate_key_pair, -2)
        self.assertRaises(ValueError, ElGamal.generate_key_pair, 5)

    def test_encrypt(self):
        priv, pub = ElGamal.generate_key_pair(256)
        cipher = ElGamal(pub)
        c = cipher.encrypt(b"\x03")
        self.assertEqual(b"\x03", ElGamal(priv).decrypt(c))

    def test_encrypt_type(self):
        priv, pub = ElGamal.generate_key_pair(256)
        cipher = ElGamal(pub)
        self.assertRaises(TypeError, cipher.encrypt, "test")

    def test_load(self):
        priv, pub = ElGamal.generate_key_pair(256)
        cipher = ElGamal(pub)
        c = cipher.encrypt(b"test")
        cipher = ElGamal(priv)
        self.assertEqual(b"test", cipher.decrypt(c))

    def test_sign_verify(self):
        priv, pub = ElGamal.generate_key_pair(1024)
        cipher = ElGamal(priv)
        b = token_bytes(8)
        sig = cipher.sign(b)
        self.assertEqual(cipher.verify(sig), None)
        priv, pub = ElGamal.generate_key_pair(1024)
        cipher = ElGamal(priv)
        b = token_bytes(16)
        sig = cipher.sign(b)
        fake_sig = [b"t", b"es", b"t"]
        self.assertRaises(Exceptions.MACError, cipher.verify, fake_sig)
        changed_sig = (sig[0][:-1], sig[1], sig[2])
        self.assertRaises(Exceptions.MACError, cipher.verify, changed_sig)


