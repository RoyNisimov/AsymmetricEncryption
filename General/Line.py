from AsymmetricEncryption.General.Element import Element
import secrets
import hashlib

class Line:
    def __init__(self, m: int, b: int, p: int):
        self.m: int = m
        self.b: int = b
        self.p: int = p


    def f(self, x: int) -> Element:
        return Element((x % self.p, (self.m * x + self.b)))

    def __str__(self) -> str:
        return f"y = {self.m}x + {self.b}"

    def __eq__(self, other) -> bool:
        if not isinstance(other, Line): return False
        return hashlib.sha256(f"{self}".encode()).hexdigest() == hashlib.sha256(f"{other}".encode()).hexdigest()

    def generate_element(self) -> Element:
        x: int = secrets.randbelow(self.p - 1)
        return self.f(x)
