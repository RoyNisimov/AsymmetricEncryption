from AsymmetricEncryptions.PublicPrivateKey.RSA import RSAKey, RSA
from AsymmetricEncryptions.Protocols.RingSignatures import RingSignatures
import secrets
from unittest import TestCase

class TestRingSignature(TestCase):
    def test_sign_and_verify(self):
        # Gen
        ksize = 1024
        gsize = secrets.randbelow(7)
        og_priv, _ = RSA.generate_key_pair(ksize)
        og_priv: RSAKey
        keys = []
        for i in range(gsize - 1):
            _, pub = RSA.generate_key_pair(ksize)
            keys.append(pub)
        msg1 = secrets.token_bytes(16)
        p = secrets.randbelow(len(keys))
        keys.insert(p, og_priv)
        r = RingSignatures(keys)
        sig, RK = r.sign_message(msg1, p)
        ver = RingSignatures(RK).verify_message(msg1, sig)
        self.assertEqual(ver, True)