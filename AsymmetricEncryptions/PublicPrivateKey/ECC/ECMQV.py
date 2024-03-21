from __future__ import annotations
# MQV (Menezes–Qu–Vanstone) is an authenticated protocol for key agreement based on the Diffie–Hellman scheme. Like other authenticated Diffie–Hellman schemes, MQV provides protection against an active attacker. The protocol can be modified to work in an arbitrary finite group, and, in particular, elliptic curve groups, where it is known as elliptic curve MQV (ECMQV).
from .ECKey import ECKey
from .ECPoint import ECPoint
from .ECCurve import ECCurve
from math import floor, ceil, log
class ECMQV:


    @staticmethod
    def bar(point: ECPoint) -> int:
        L = ceil((floor(log(point.curve.n, 2)) + 1) / 2)
        TwoPowL = pow(2, L)
        return (point.x % TwoPowL) + TwoPowL

    @staticmethod
    def Stage1n2(curve: ECCurve) -> ECKey:
        return ECKey.new(curve)

    @staticmethod
    def Stage3n4(priv_key: ECKey, xy: ECKey) -> int:
        return (xy.private_key + (ECMQV.bar(xy.public_key) * priv_key.private_key) % priv_key.public_key.curve.n) % priv_key.public_key.curve.n

    @staticmethod
    def Stage5(other_pub_key: ECKey, S: int, xy: ECKey) -> ECPoint:
        return (xy.public_key + (other_pub_key.public_key * ECMQV.bar(xy.public_key))) * other_pub_key.public_key.curve.h * S
