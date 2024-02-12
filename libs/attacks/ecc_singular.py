from itertools import product
from typing import cast

from ..sage_types import FFPmodn, Integer, Polynomial, PRmodp


def singular_attack(f: Polynomial, gx: int, gy: int | None, px: int, py: int | None) -> set[int]:
    P = cast(PRmodp, f.parent())

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
    root, mult = next(((r, int(m)) for r, m in roots if m > 1), (None, 0))
    if root is None:
        print("* No multiple root:", roots)
        raise ValueError("Could not find multiple root")
    print(f"* Found root with multiplicity {mult}: {root}")
    if not mult in (2, 3):
        raise ValueError("Only double and triple roots are supported")

    gx_ = gx - root
    px_ = px - root

    if mult == 3:
        print("* Singular point is a cusp (triple root)")
        F = cast(FFPmodn, P.base_ring())
        for gy_, py_ in product(gys, pys):
            n = (F(px_) / F(py_)) / (F(gx_) / F(gy_))
            logs.add(int(n))
        return logs

    x = P.gen()
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

    return logs
