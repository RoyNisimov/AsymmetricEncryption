from secrets import randbelow

class Cryptographer:

    def __init__(self, n: int, position=0, other_cryptographers=None, paid=False, name="A"):
        self.n = n
        self._paid = paid
        self.position = position
        if other_cryptographers is None: other_cryptographers = []
        self.other_cryptographers = other_cryptographers
        self.bits = [None] * n
        self.name = name



    def establish_bits(self):
        for i, cryptographer in enumerate(self.other_cryptographers):
            if self.other_cryptographers[i] == self: continue
            b = randbelow(2)
            self.bits[i] = b
            cryptographer.bits[self.position] = b

    def __str__(self):
        return f"{self.name}"


    def announce(self):
        self.bits[self.position] = int(self._paid)
        x = 0
        for i in self.bits:
            x = x ^ i
        return x

    def dine(self):
        bits = []
        for cryptographer in self.other_cryptographers:
            bits.append(cryptographer.announce())
        x = 0
        for i in bits:
            x = x ^ i
        return x
