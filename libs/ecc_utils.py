from typing import Generator


class Point:
    x: int
    y: int

    def __init__(self, x: int | str | tuple[int, int], y: int | None = None) -> None:
        if isinstance(x, tuple):
            self.x, self.y = x
        elif isinstance(x, str):
            self.x, self.y = [int(n.strip()) for n in x.split(",")]
        elif y is not None:
            self.x = x
            self.y = y
        else:
            raise ValueError("Missing y coordinate")

    def __str__(self) -> str:
        return f"({self.x}, {self.y})"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}{str(self)}"

    def __hash__(self) -> int:
        return hash((self.x, self.y))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return NotImplemented
        return self.x == other.x and self.y == other.y

    def __len__(self) -> int:
        return 2

    def __getitem__(self, i: int) -> int:
        return (self.x, self.y)[i]

    def __iter__(self) -> Generator[int, None, None]:
        yield self.x
        yield self.y


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
