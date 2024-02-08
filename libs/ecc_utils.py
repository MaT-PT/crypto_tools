from string import whitespace as ws
from typing import Iterable


def parse_int(value: str) -> int:
    value = value.strip()
    if value.startswith("0x"):
        return int(value, 16)
    if value.startswith("0b"):
        return int(value, 2)
    if value.startswith("0o"):
        return int(value, 8)
    return int(value)


class Point(tuple[int, int]):
    def __new__(cls, x: int | str | tuple[int, int], y: int | None = None) -> "Point":
        t: Iterable[int]
        if isinstance(x, tuple):
            t = x
        elif isinstance(x, str):
            t = (parse_int(n) for n in x.strip(ws + "()[]{}").split(","))
        elif y is not None:
            t = (x, y)
        else:
            raise ValueError("Missing y coordinate")
        return super().__new__(cls, t)  # type: ignore

    @property
    def x(self) -> int:
        return self[0]

    @property
    def y(self) -> int:
        return self[1]

    def __str__(self) -> str:
        return f"({self.x}, {self.y})"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}{str(self)}"

    def on_curve(self, a: int, b: int, p: int) -> bool:
        return curve_contains_point(a, b, p, self)


def curve_contains_point(a: int, b: int, p: int, P: Point | tuple[int, int]) -> bool:
    x, y = P
    return (x**3 + a * x + b - y**2) % p == 0


def calc_curve_params(p: int, P: Point, Q: Point) -> tuple[int, int]:
    py2 = pow(P.y, 2, p)
    qy2 = pow(Q.y, 2, p)
    px3 = pow(P.x, 3, p)
    qx3 = pow(Q.x, 3, p)

    a = (((py2 - qy2) - (px3 - qx3)) * pow(P.x - Q.x, -1, p)) % p

    b1 = (py2 - px3 - a * P.x) % p
    b2 = (qy2 - qx3 - a * Q.x) % p
    assert b1 == b2, "got different b values for P and Q"

    return a, b1
