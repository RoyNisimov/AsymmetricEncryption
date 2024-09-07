from __future__ import division
from __future__ import print_function
import secrets
import functools


class SSS:
    """Code is edited from Wikipedia"""

    def __init__(self, prime: int = pow(2, 10141) - 1):
        self._PRIME = prime

        self._RINT: int = functools.partial(secrets.SystemRandom().randint, 0)

    @staticmethod
    def _eval_at( poly, x, prime):
        """Evaluates polynomial (coefficient tuple) at x, used to generate a
        shamir pool in make_random_shares below.
        """
        accum = 0
        for coeff in reversed(poly):
            accum *= x
            accum += coeff
            accum %= prime
        return accum

    def make_random_shares(self, secret: bytes, minimum, shares):
        from AsymmetricEncryptions import BytesAndInts
        """
        Generates a random shamir pool for a given secret, returns share points.
        """
        secret = BytesAndInts.byte2Int(secret)
        prime = self._PRIME
        assert secret < prime, "The secret is too large!"
        if minimum > shares:
            raise ValueError("Pool secret would be irrecoverable.")
        poly = [secret] + [self._RINT(prime - 1) for i in range(minimum - 1)]
        points = [(i, SSS._eval_at(poly, i, prime))
                  for i in range(1, shares + 1)]
        return points

    @staticmethod
    def _extended_gcd(a, b):
        """
        Division in integers modulus p means finding the inverse of the
        denominator modulo p and then multiplying the numerator by this
        inverse (Note: inverse of A is B such that A*B % p == 1). This can
        be computed via the extended Euclidean algorithm
        http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
        """
        x = 0
        last_x = 1
        y = 1
        last_y = 0
        while b != 0:
            quot = a // b
            a, b = b, a % b
            x, last_x = last_x - quot * x, x
            y, last_y = last_y - quot * y, y
        return last_x, last_y

    @staticmethod
    def _divmod(num, den, p):
        """Compute num / den modulo prime p

        To explain this, the result will be such that:
        den * _divmod(num, den, p) % p == num
        """
        inv, _ = SSS._extended_gcd(den, p)
        return num * inv

    def _lagrange_interpolate(self, x, x_s, y_s, p):
        """
        Find the y-value for the given x, given n (x, y) points;
        k points will define a polynomial of up to kth order.
        """
        k = len(x_s)
        assert k == len(set(x_s)), "points must be distinct"

        def PI(vals):  # upper-case PI -- product of inputs
            accum = 1
            for v in vals:
                accum *= v
            return accum
        nums = []  # avoid inexact division
        dens = []
        for i in range(k):
            others = list(x_s)
            cur = others.pop(i)
            nums.append(PI(x - o for o in others))
            dens.append(PI(cur - o for o in others))
        den = PI(dens)
        num = sum([SSS._divmod(nums[i] * den * y_s[i] % p, dens[i], p)
                   for i in range(k)])
        return (SSS._divmod(num, den, p) + p) % p


    def recover_secret(self, shares: list[tuple[int, int]]) -> bytes:
        """
        Recover the secret from share points
        (points (x,y) on the polynomial).
        """
        from AsymmetricEncryptions import BytesAndInts
        prime = self._PRIME
        if len(shares) < 3:
            raise ValueError("need at least t shares")
        x_s, y_s = zip(*shares)
        return BytesAndInts.int2Byte(self._lagrange_interpolate(0, x_s, y_s, prime))