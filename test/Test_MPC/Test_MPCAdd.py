from unittest import TestCase
from secrets import randbelow

class TestMPCAdd(TestCase):

    def test_add(self):
        # Addition of A B and C over modulus n, if n == 0 then there's no modulus
        from AsymmetricEncryptions.MPC.MPC_Addition import MPCAddition
        n = randbelow(40)
        m = randbelow(1024)
        rs = [randbelow(m) for _ in range(n)]
        parties = [MPCAddition(rs[i], n, m) for i in range(n)]
        shares = [parties[i].get_shares() for i in range(len(parties))]
        total = list(zip(*shares))
        ss = [parties[i].s(total[i]) for i in range(n)]
        su = sum(ss) % m
        self.assertEqual(su, sum(rs) % m)

    def test_add_without_mod(self):
        # Addition of A B and C over modulus n, if n == 0 then there's no modulus
        from AsymmetricEncryptions.MPC.MPC_Addition import MPCAddition
        n = randbelow(40)
        m = 0
        rs = [randbelow(1024) for _ in range(n)]
        parties = [MPCAddition(rs[i], n, m) for i in range(n)]
        shares = [parties[i].get_shares() for i in range(len(parties))]
        total = list(zip(*shares))
        ss = [parties[i].s(total[i]) for i in range(n)]
        su = sum(ss)
        self.assertEqual(su, sum(rs))