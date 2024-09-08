from __future__ import division
from __future__ import print_function
import secrets
import functools
from AsymmetricEncryptions.General.PrimeNumberGen import PrimeNumberGen
from hashlib import sha256


class SSS:
    """Code is edited from Wikipedia"""

    def __init__(self, prime: int = pow(2, 10141) - 1, mini = 2, maxi = 3):
        if prime < 2: raise ValueError("Prime must be a positive prime number")
        if prime != pow(2, 10141) - 1:
            if not PrimeNumberGen.isMillerRabinPassed(prime): raise ValueError("Prime must be a positive prime number")
        self._PRIME = prime
        self._RINT: int = functools.partial(secrets.SystemRandom().randint, 0)
        self.mini = mini
        self.maxi = maxi

    @staticmethod
    def _eval_at(poly, x, prime):
        """Evaluates polynomial (coefficient tuple) at x, used to generate a
        shamir pool in make_random_shares below.
        """
        accum = 0
        for coeff in reversed(poly):
            accum *= x
            accum += coeff
            accum %= prime
        return accum

    def make_random_shares(self, secret: bytes, minimum: int, shares: int) -> list[tuple[int, int]]:
        from AsymmetricEncryptions import BytesAndInts
        """
        Generates a random shamir pool for a given secret, returns share points.
        """
        if minimum < 2 or shares < 3: raise ValueError("Minimum and Shares must be larger than 2, 3")
        secret = BytesAndInts.byte2Int(secret)
        prime = self._PRIME
        if secret > prime:
            raise ValueError("The secret is too large!")
        if minimum > shares:
            raise ValueError("Pool secret would be irrecoverable.")
        self.mini = minimum
        self.maxi = shares
        poly = [secret] + [self._RINT(prime - 1) for _ in range(minimum - 1)]
        points = [(i, SSS._eval_at(poly, i, prime))
                  for i in range(1, shares + 1)]
        return points

    def get_prime(self) -> int:
        return self._PRIME


    def convert_list_of_bytes_and_points_to_points(self, l: list[tuple[int, int] or bytes]) -> list[tuple[int, int]]:
        r = []
        for obj in l:
            if isinstance(obj, bytes):
                r.append(SSS.convert_bytes_to_point(obj, self._PRIME))
            else:
                r.append(obj)
        return r

    def generate_for_public(self, secret: bytes, custom: list[tuple[int, int] or bytes]) -> tuple[int, int]:
        from AsymmetricEncryptions import BytesAndInts
        secret = BytesAndInts.byte2Int(secret)
        prime = self._PRIME
        if secret > prime:
            raise ValueError("The secret is too large!")
        if len(custom) == 0: raise ValueError("The secret would be irrecoverable")
        r = self._RINT(prime - 1)
        custom = self.convert_list_of_bytes_and_points_to_points(custom)
        custom.append((0, secret))
        x_s, y_s = zip(*custom)
        point = (r, self._lagrange_interpolate(r, x_s, y_s, prime))
        return point



    @staticmethod
    def convert_bytes_to_point(b: bytes, prime: int) -> tuple[int, int]:
        from AsymmetricEncryptions import BytesAndInts
        return BytesAndInts.byte2Int(b) % prime, BytesAndInts.byte2Int(sha256(b).digest()) % prime



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
        shares = self.convert_list_of_bytes_and_points_to_points(shares)
        prime = self._PRIME
        if len(shares) < self.mini:
            raise ValueError("need at least t shares")
        x_s, y_s = zip(*shares)
        return BytesAndInts.int2Byte(self._lagrange_interpolate(0, x_s, y_s, prime))