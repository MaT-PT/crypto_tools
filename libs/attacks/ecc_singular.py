from itertools import product
from typing import cast

from ..ecc_utils import AInvs, isomorphism, long_weier_form, morph_point, short_weier_form3
from ..sage_types import FFPmodn, Integer, PRmodp, polygen
from ..types import ResultSet


def singular_attack(
    a_invs: AInvs, F: FFPmodn, gx0: int, gy0: int | None, px0: int, py0: int | None
) -> ResultSet:
    p = F.characteristic()
    a1, a2, a3, a4, a6 = a_invs
    if a1 % p == 0 and a3 % p == 0:
        print("* Curve is already in short Weierstrass form")
        a, b, c = a2, a4, a6
        gx, gy = gx0, gy0
        px, py = px0, py0
    else:
        a, b, c = short_weier_form3(a_invs, p)
        long_form = long_weier_form((a, b, c))
        urst = isomorphism(a_invs, long_form, p)
        gx, gy = morph_point(urst, p, gx0, gy0)
        px, py = morph_point(urst, p, px0, py0)
        print(f"* Short Weierstrass form: y^2 = x^3 + {a}*x^2 + {b}*x + {c}")

    x = cast(PRmodp, polygen(F, "x"))
    f = cast(PRmodp, x**3 + a * x**2 + b * x + c)

    if gy is None:
        try:
            gys: set[Integer] = set(f(gx).sqrt(all=True))
        except NotImplementedError:
            gys = set()
        if len(gys) == 0:
            raise ValueError("Could not find Gy, try specifying it manually")
        else:
            print("* Found multiple candidates for Gy:", gys)
    else:
        gys = {Integer(gy)}
    if py is None:
        try:
            pys: set[Integer] = set(f(px).sqrt(all=True))
        except NotImplementedError:
            pys = set()
        if len(pys) == 0:
            raise ValueError("Could not find Py, try specifying it manually")
        else:
            print("* Found multiple candidates for Py:", pys)
    else:
        pys = {Integer(py)}
    multiple_solutions = len(gys) > 1 or len(pys) > 1

    logs: set[int] = set()

    print("* Computing roots...")
    roots: list[tuple[Integer, int]] = f.roots()
    if len(roots) == 0:
        raise ValueError("Could not find any roots")
    root, mult = max(roots, key=lambda r_m: r_m[1])
    if mult < 2:
        print("* No multiple root:", roots)
        raise ValueError("Could not find multiple root")
    print(f"* Found root with multiplicity {mult}: {root}")
    if not mult in (2, 3):
        raise ValueError("Only double and triple roots are supported")

    gx_ = gx - root
    px_ = px - root

    if mult == 3:
        print("* Singular point is a cusp (triple root)")
        for gy_, py_ in product(gys, pys):
            n = (F(px_) / F(py_)) / (F(gx_) / F(gy_))
            logs.add(int(n))
        return ResultSet(logs)

    f_ = f.substitute(x=x + root)
    print("* Substituted polynomial:", f_)
    t = f_[2].sqrt()

    for gy_, py_ in product(gys, pys):
        if multiple_solutions:
            print(f"* Computing discrete log for Gy = {gy_}; Py = {py_}...")
        else:
            print(f"* Computing discrete log...")
        u = (gy_ + t * gx_) / (gy_ - t * gx_)
        v = (py_ + t * px_) / (py_ - t * px_)

        n = v.log(u)
        if multiple_solutions:
            print(f"  * n = {n}")
        logs.add(int(n))

    return ResultSet(logs)
