from __future__ import annotations
from AsymmetricEncryption.General import PrimeNumberGen, BytesAndInts, Line, Element
import secrets

class SSS2N:

    def __init__(self):
        pass

    @staticmethod
    def new(msg_to_hide: bytes, n: int, finite_field_p_bits: int = 1024) -> list[Element]:
        assert n >= 2
        msg_to_hide: int = BytesAndInts.byte2Int(msg_to_hide)
        p: int = PrimeNumberGen.generate(finite_field_p_bits)
        assert p > msg_to_hide
        slope: int = secrets.randbelow(p)
        line: Line = Line(slope, msg_to_hide, p)
        return [line.generate_element() for _ in range(n)], p

    @staticmethod
    def reassemble(elements: list[Element], p) -> bytes:
        assert len(elements) >= 2
        el1: Element = elements[0]
        el2: Element = elements[1]
        slope: int = Element.calculate_slope(el1, el2)
        # formula = y = m(x - x1) + y1, y = mx + (-mx1 + y1)
        line: Line = Line(slope, (slope * -1 * el1.x) + el1.y, p)
        return BytesAndInts.int2Byte(int(line.f(0).y))
