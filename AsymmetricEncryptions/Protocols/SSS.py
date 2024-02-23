import secrets
from AsymmetricEncryption.General import BytesAndInts

class SSS:
    FIELD_SIZE: int = pow(10, 5)

    @staticmethod
    def reconstruct_secret(shares: list[tuple[int, int]]) -> BytesAndInts:
        """
        Combines individual shares (points on graph)
        using Lagrange's interpolation.

        `shares` is a list of points (x, y) belonging to a
        polynomial with a constant of our key.
        """
        sums: int = 0
        for j, share_j in enumerate(shares):
            xj, yj = share_j
            prod: int = 1
            for i, share_i in enumerate(shares):
                xi, _ = share_i
                if i != j:
                    prod *= xi / (xi - xj)
            prod *= yj
            sums += prod
        a: int = int(round(sums, 0))
        return BytesAndInts.int2Byte(a)

    @staticmethod
    def polynom(x: int, coefficients: list[int]) -> int:
        """
        This generates a single point on the graph of given polynomial
        in `x`. The polynomial is given by the list of `coefficients`.
        """
        point: int = 0
        # Loop through reversed list, so that indices from enumerate match the
        # actual coefficient indices
        for coefficient_index, coefficient_value in enumerate(coefficients[::-1]):
            point += x ** coefficient_index * coefficient_value
        return point

    @staticmethod
    def coeff(t: int, secret: int) -> list[int]:
        """
        Randomly generate a list of coefficients for a polynomial with
        degree of `t` - 1, whose constant is `secret`.

        For example with a 3rd degree coefficient like this:
            3x^3 + 4x^2 + 18x + 554

            554 is the secret, and the polynomial degree + 1 is
            how many points are needed to recover this secret.
            (in this case it's 4 points).
        """
        coeff: list[int] = [secrets.SystemRandom().randrange(0, SSS.FIELD_SIZE) for _ in range(t - 1)]
        coeff.append(secret)
        return coeff

    @staticmethod
    def generate_shares(n: int, m: int, secret: bytes) -> list[tuple[int, int]]:
        """
        Split given `secret` into `n` shares with minimum threshold
        of `m` shares to recover this `secret`, using SSS algorithm.
        """
        secret: int = BytesAndInts.byte2Int(secret)
        coefficients: list[int] = SSS.coeff(m, secret)
        shares: list[tuple[int, int]] = []

        for i in range(1, n + 1):
            x = secrets.SystemRandom().randrange(1, SSS.FIELD_SIZE)
            shares.append((x, SSS.polynom(x, coefficients)))
        return shares
