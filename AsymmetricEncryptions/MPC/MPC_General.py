from secrets import randbelow

class MPCGeneral:

    @staticmethod
    def make_shares(p: int, n: int, m: int = 0) -> list[int]:
        l = []
        c = p
        if m > 0:
            for _ in range(n - 1):
                r = randbelow(m)
                c = (c - r) % m
                l.append(r)
            l.append(c)
        else:
            for _ in range(n - 1):
                r = randbelow(p)
                c = (c - r)
                l.append(r)
            l.append(c)
        return l.copy()

    @staticmethod
    def combine_shares(shares: list[int], m: int = 0) -> int:
        s = 0
        if s != 0:
            for share in shares:
                s = (s + share) % m
        else:
            for share in shares:
                s = (s + share)
        return s
