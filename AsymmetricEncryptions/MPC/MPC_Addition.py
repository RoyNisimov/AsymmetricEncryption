
from .MPC_General import MPCGeneral
class MPCAddition:

    def __init__(self, p: int, n: int, m: int = 0):
        self.p = p
        self.m = m
        self.n = n
        self.shares = MPCGeneral.make_shares(p, n, m)

    def get_shares(self) -> list[int]:
        return self.shares.copy()



    def s(self, shared: list[int]) -> int:
        return MPCGeneral.combine_shares(shared, self.m)
