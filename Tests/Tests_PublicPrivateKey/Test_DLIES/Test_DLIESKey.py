from unittest import TestCase
from AsymmetricEncryptions.PublicPrivateKey.DLIES import DLIESKey

class TestRSAKey(TestCase):
    def test_new(self):
        priv = DLIESKey.new(256)
        pub: DLIESKey = priv.public
        self.assertEqual(pub.y, pow(priv.g, priv.x, priv.n))

    def test_new_values(self):
        self.assertRaises(ValueError, DLIESKey.new, -1)
        self.assertRaises(ValueError, DLIESKey.new, 4209)

    def test_export_and_load(self):
        priv: DLIESKey = DLIESKey.new(256)
        priv.export("..\\..\\..\\TestFiles\\DLIESKeyTestFileUnprotected.key", b"")
        loaded_priv = DLIESKey.load("..\\..\\..\\TestFiles\\DLIESKeyTestFileUnprotected.key", b"")
        self.assertEqual(priv, loaded_priv)
        priv: DLIESKey = DLIESKey.new(256)
        priv.export("..\\..\\..\\TestFiles\\DLIESKeyTestFileProtected.key", b"Pass")
        loaded_priv = DLIESKey.load("..\\..\\..\\TestFiles\\DLIESKeyTestFileProtected.key", b"Pass")
        self.assertEqual(priv, loaded_priv)



