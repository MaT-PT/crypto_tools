from functools import cache
from math import prod
from string import whitespace as ws
from typing import Iterable, NewType, Self, cast

AInvs = NewType("AInvs", tuple[int, int, int, int, int])
AInvsShort2 = NewType("AInvsShort2", tuple[int, int])
AInvsShort3 = NewType("AInvsShort3", tuple[int, int, int])
BInvs = NewType("BInvs", tuple[int, int, int, int])
CInvs = NewType("CInvs", tuple[int, int])
URST = NewType("URST", tuple[int, int, int, int])


def parse_int(value: str) -> int:
    value = value.strip()
    if value.lstrip("-").startswith("0x"):
        return int(value, 16)
    if value.lstrip("-").startswith("0b"):
        return int(value, 2)
    if value.lstrip("-").startswith("0o"):
        return int(value, 8)
    return int(value)


class Point(tuple[int, int]):
    def __new__(cls, x: int | str | tuple[int, int], y: int | None = None) -> Self:
        t: Iterable[int]
        if isinstance(x, tuple):
            t = x
        elif isinstance(x, str):
            t = [parse_int(n) for n in x.strip(ws + "()[]{}").split(",")]
            if len(t) != 2:
                raise ValueError("Invalid number of coordinates")
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

    def on_curve(self, a_invs: AInvs, p: int) -> bool:
        return curve_contains_point(a_invs, p, self)


def curve_contains_point(a_invs: AInvs, p: int, P: Point | tuple[int, int]) -> bool:
    x, y = P
    a1, a2, a3, a4, a6 = a_invs
    # y^2 + a1*x*y + a3*y = x^3 + a2*x^2 + a4*x + a6
    return (
        pow(y, 2, p) + a1 * x * y + a3 * y - pow(x, 3, p) - a2 * pow(x, 2, p) - a4 * x - a6
    ) % p == 0


def calc_curve_params(p: int | list[int], P: Point, Q: Point) -> AInvsShort2:
    if isinstance(p, list):
        p = prod(p)

    py2 = pow(P.y, 2, p)
    qy2 = pow(Q.y, 2, p)
    px3 = pow(P.x, 3, p)
    qx3 = pow(Q.x, 3, p)

    a = (((py2 - qy2) - (px3 - qx3)) * pow(P.x - Q.x, -1, p)) % p

    b1 = (py2 - px3 - a * P.x) % p
    b2 = (qy2 - qx3 - a * Q.x) % p
    assert b1 == b2, "got different b values for P and Q"

    return AInvsShort2((a, b1))


@cache
def b_invariants(a_invs: AInvs, p: int) -> BInvs:
    a1, a2, a3, a4, a6 = a_invs
    return BInvs(
        (
            (a1 * a1 + 4 * a2) % p,
            (a1 * a3 + 2 * a4) % p,
            (pow(a3, 2, p) + 4 * a6) % p,
            (pow(a1, 2, p) * a6 + 4 * a2 * a6 - a1 * a3 * a4 + a2 * pow(a3, 2, p) - pow(a4, 2, p))
            % p,
        )
    )


@cache
def c_invariants(a_invs: AInvs, p: int) -> CInvs:
    b2, b4, b6, _ = b_invariants(a_invs, p)
    return CInvs(((pow(b2, 2, p) - 24 * b4) % p, (-pow(b2, 3, p) + 36 * b2 * b4 - 216 * b6) % p))


@cache
def discriminant(a_invs: AInvs, p: int) -> int:
    b2, b4, b6, b8 = b_invariants(a_invs, p)
    return (-pow(b2, 2, p) * b8 - 8 * pow(b4, 3, p) - 27 * pow(b6, 2, p) + 9 * b2 * b4 * b6) % p


@cache
def j_invariant(a_invs: AInvs, p: int) -> int:
    c4, _ = c_invariants(a_invs, p)
    d = discriminant(a_invs, p)
    if d == 0:
        raise ValueError("j-invariant is undefined for singular curves")
    return (pow(c4, 3, p) * pow(d, -1, p)) % p


@cache
def short_weier_form2(a_invs: AInvs, p: int) -> AInvsShort2:
    a1, a2, a3, a4, a6 = a_invs
    if a1 % p == 0 and a2 % p == 0 and a3 % p == 0:
        return AInvsShort2((a4 % p, a6 % p))
    b2, b4, b6, _ = b_invariants(a_invs, p)
    if b2 == 0:
        return AInvsShort2(((8 * b4) % p, (16 * b6) % p))
    else:
        c4, c6 = c_invariants(a_invs, p)
        return AInvsShort2(((-27 * c4) % p, (-54 * c6) % p))


@cache
def short_weier_form3(a_invs: AInvs, p: int) -> AInvsShort3:
    a1, a2, a3, a4, a6 = a_invs
    b2, b4, b6, _ = b_invariants(a_invs, p)
    if a1 % p == 0 and a3 % p == 0:
        return AInvsShort3((a2 % p, a4 % p, a6 % p))
    else:
        return AInvsShort3((b2 % p, (8 * b4) % p, (16 * b6) % p))


@cache
def long_weier_form(a_invs: AInvs | AInvsShort2 | AInvsShort3) -> AInvs:
    match a_invs:
        case a, b:
            return AInvs((0, 0, 0, a, b))
        case a, b, c:
            return AInvs((0, a, 0, b, c))
        case a1, a2, a3, a4, a6:
            return AInvs((a1, a2, a3, a4, a6))
        case _:
            raise ValueError("Invalid weierstrass form")


@cache
def isomorphisms(E: AInvs, F: AInvs, p: int, just_one: bool = False) -> URST | list[URST] | None:
    if E == F:
        if just_one:
            return URST((1, 0, 0, 0))
        return [URST((1, 0, 0, 0))]

    try:
        j: int | None = j_invariant(E, p)
    except ValueError:
        j = None
    try:
        jf: int | None = j_invariant(F, p)
    except ValueError:
        jf = None
    if j != jf:
        if just_one:
            return None
        return []
    if j is None:
        j = -1

    from .sage_types import GF, FFPmodn, polygen

    K = cast(FFPmodn, GF(p))
    x = polygen(K, "x")

    a1E, a2E, a3E, _, _ = E
    a1F, a2F, a3F, _, _ = F
    c4E, c6E = c_invariants(E, p)
    c4F, c6F = c_invariants(F, p)

    if j == 0:
        m, um = 6, (c6E * pow(c6F, -1, p)) % p
    elif j == 1728:
        m, um = 4, (c4E * pow(c4F, -1, p)) % p
    else:
        m, um = 2, (c6E * c4F * pow(c6F * c4E, -1, p)) % p
    ulist = (x**m - um).roots(multiplicities=False)
    ans: list[URST] = []
    for u in ulist:
        s = (a1F * u - a1E) / 2
        r = (a2F * u**2 + a1E * s + s**2 - a2E) / 3
        t = (a3F * u**3 - a1E * r - a3E) / 2
        if just_one:
            return URST((u, r, s, t))
        ans.append(URST((u, r, s, t)))
    if just_one:
        return None
    ans.sort()
    return ans


@cache
def isomorphism(E: AInvs, F: AInvs, p: int) -> URST | None:
    urst = isomorphisms(E, F, p, True)
    assert not isinstance(urst, list)
    return urst


@cache
def dual_isomorphism(urst: URST, p: int) -> URST:
    u, r, s, t = urst
    return URST(
        (
            pow(u, -1, p),
            (-r * pow(u, -2, p)) % p,
            (-s * pow(u, -1, p)) % p,
            (((r * s - t) % p) * pow(u, -3, p)) % p,
        )
    )


@cache
def morph_point(
    urst: URST, p: int, x: int | tuple[int, int | None], y: int | None = None
) -> tuple[int, int | None]:
    if isinstance(x, tuple):
        x, y = x
    u, r, s, t = urst

    x -= r
    if isinstance(x, int):
        x %= p
    if y is not None:
        y -= s * x + t
        if isinstance(y, int):
            y %= p
        y *= pow(u, -3, p)
        if isinstance(y, int):
            y %= p
    x *= pow(u, -2, p)
    if isinstance(x, int):
        x %= p
    return x, y


def lift_x(a_invs: AInvs, x: int, ps: list[int]) -> set[Point]:
    from itertools import product

    from .sage_types import ECFF, GF, CRT_list, EllipticCurve, Integer

    ys_list: list[set[int]] = []
    ps_sage = [Integer(p) for p in ps]

    print(f"* Finding y-coordinates for {x = }")
    for p in ps_sage:
        E = cast(ECFF, EllipticCurve(GF(p), a_invs))
        ys = {Integer(P[1]) for P in E.lift_x(Integer(x), all=True)}
        print(f"  * {p = }: {len(ys)} y-coordinates found")
        for y in ys:
            print(f"    * {y = }")
        ys_list.append(ys)

    final_ys: set[int] = set()
    for y_list in product(*ys_list):
        print("* Trying CRT with y-coordinates:", y_list)
        if len(y_list) == len(ps_sage):
            y = int(CRT_list(list(y_list), ps_sage))
            print(f"  * Result: {y = }")
            final_ys.add(y)
        else:
            print("  * Skipping CRT, not enough y-coordinates")

    return {Point(x, y) for y in final_ys}
