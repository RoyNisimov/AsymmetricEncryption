from __future__ import annotations
import hashlib

class Element:

    def __init__(self, cord: tuple[int, int]) -> None:
        self.x: int = cord[0]
        self.y: int = cord[1]
        self.cord: tuple[int, int] = (self.x, self.y)

    @staticmethod
    def fmt_elements_list(l: list[Element]) -> str:
        return "\n".join([f"{i}" for i in l])

    @staticmethod
    def calculate_slope(element: Element, other: Element) -> int:
        # returns int because only being used in SSS2N
        assert element != other
        assert element.x != other.x
        # line slope is (y1 - y2)/(x1-x2)
        return (element.y - other.y) // (element.x - other.x)


    def __eq__(self, other) -> bool:
        if not isinstance(other, Element): return False
        return hashlib.sha256(f"{self}".encode()).hexdigest() == hashlib.sha256(f"{other}".encode()).hexdigest()


    def __str__(self) -> str:
        return f"({self.x}; {self.y})"