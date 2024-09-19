from unittest import TestCase
from secrets import randbelow
from AsymmetricEncryptions.MPC.DiningCryptographers import Cryptographer

class TestDC(TestCase):

    def test_dining_protocol_not_paid(self):
        n = randbelow(20)
        while n < 3:
            n = randbelow(20)
        cryptographers = [Cryptographer(n, i, name=f"{i}") for i in range(n)]
        for cryptographer in cryptographers:
            cryptographer.other_cryptographers = cryptographers.copy()
            cryptographer.establish_bits()
        self.assertEqual(cryptographers[randbelow(n)].dine(), 0)

    def test_dining_protocol_paid(self):
        n = randbelow(20)
        while n < 3:
            n = randbelow(20)
        someone_paid = False
        cryptographers = []
        for i in range(n):
            pay = False
            if not someone_paid:
                pay = bool(randbelow(2))
                if pay: someone_paid = True
            cryptographers.append(Cryptographer(n, i, paid=pay, name=f"{i}"))
        for cryptographer in cryptographers:
            cryptographer.other_cryptographers = cryptographers.copy()
            cryptographer.establish_bits()
        self.assertEqual(cryptographers[randbelow(n)].dine(), int(someone_paid))
