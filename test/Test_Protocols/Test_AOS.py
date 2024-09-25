from unittest import TestCase
from AsymmetricEncryptions.PublicPrivateKey.ECC import ECKey, EllipticCurveNISTP256
from AsymmetricEncryptions.Protocols.AOSRingSignatures import AOS
from secrets import randbelow, token_bytes, SystemRandom

class TestAOS(TestCase):

    def test_ring(self):
        m = token_bytes(16)
        n = randbelow(20)
        while n < 2:
            n = randbelow(20)
        signer = ECKey.new(curve := EllipticCurveNISTP256.get_curve())
        keys = [ECKey.new(curve).get_public_key() for _ in range(n)]
        rs = AOS(keys, signer)
        sigma, rk = rs.sign(m)
        v = AOS.verify(rk, m, sigma)
        self.assertEqual(v, True)
        v = AOS.verify(rk, m+b" Ring", sigma)
        self.assertEqual(v, False)
        nrk = rk.copy()
        SystemRandom().shuffle(nrk)
        v = AOS.verify(nrk, m, sigma)
        self.assertEqual(v, False)
        v = AOS.verify(rk, m, (sigma[0] + 1, sigma[1]))
        self.assertEqual(v, False)
        v = AOS.verify(rk, m, (sigma[0], sigma[1] + [2]))
        self.assertEqual(v, False)
        sigma[1][0] = 1
        v = AOS.verify(rk, m, (sigma[0], sigma[1]))
        self.assertEqual(v, False)