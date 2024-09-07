from __future__ import annotations
from unittest import TestCase
from AsymmetricEncryptions.Protocols.SSS import SSS
from secrets import token_bytes, SystemRandom


class TestSSS(TestCase):

    def test_init(self):
        self.assertRaises(ValueError, SSS, -1)
        self.assertRaises(ValueError, SSS, 4)

    def test_make_random_shares_and_recover(self):
        secret = token_bytes(16)
        mini = SystemRandom().randint(3, 16)
        maxi = SystemRandom().randint(16, 20)
        sss = SSS(mini=mini, maxi=maxi)
        shares = sss.make_random_shares(secret, mini, maxi)
        recover = sss.recover_secret(shares[:mini])
        self.assertEqual(recover, secret)
        self.assertRaises(ValueError, sss.recover_secret, shares[:(mini - 1)])
        self.assertRaises(ValueError, sss.recover_secret, [shares[0], shares[0]])
        self.assertRaises(ValueError, sss.make_random_shares, 4.1, -1, -2)

    def test_value(self):
        self.assertRaises(ValueError, SSS(3).make_random_shares, b"test"*5, 4, 5)

# secret = b"test"
# sss = SSS()
# shares = sss.make_random_shares(secret, 3, 5)
# recover = sss.recover_secret(shares[:3])
# print(recover)