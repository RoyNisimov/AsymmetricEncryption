from __future__ import annotations
from AsymmetricEncryptions.PublicPrivateKey.LWE import LWEKey
from AsymmetricEncryptions import KDF
from unittest import TestCase
import secrets

class TestLWEKey(TestCase):

    def test_export_load(self):
        s_key = KDF.derive_key(secrets.token_bytes(16))
        priv_key = LWEKey.new(128)
        priv_key.export("..\\..\\..\\TestFiles\\LWEKeyTestFileUnprotected.key", b"")
        new_key = LWEKey.load("..\\..\\..\\TestFiles\\LWEKeyTestFileUnprotected.key", b"")
        self.assertEqual(new_key, priv_key)
        priv_key = LWEKey.new(128)
        priv_key.export("..\\..\\..\\TestFiles\\LWEKeyTestFileProtected.key", s_key)
        new_key = LWEKey.load("..\\..\\..\\TestFiles\\LWEKeyTestFileProtected.key", s_key)
        self.assertEqual(new_key, priv_key)


