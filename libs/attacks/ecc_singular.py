from itertools import product
from typing import cast

from ..sage_types import Integer, Polynomial, PRmodp


def singular_attack(f: Polynomial, gx: int, gy: int | None, px: int, py: int | None) -> set[int]:
    if gy is None:
        gys: set[Integer] = set(f(gx).sqrt(all=True))
        if len(gys) == 0:
            raise ValueError("Could not find Gy, try specifying it manually")
        else:
            print("* Found multiple candidates for Gy:", gys)
    else:
        gys = {Integer(gy)}
    if py is None:
        pys: set[Integer] = set(f(px).sqrt(all=True))
        if len(pys) == 0:
            raise ValueError("Could not find Py, try specifying it manually")
        else:
            print("* Found multiple candidates for Py:", pys)
    else:
        pys = {Integer(py)}

    print("* Computing roots...")
    roots: list[tuple[Integer, int]] = f.roots()
    root = next((r for r, m in roots if m == 2), None)
    if root is None:
        print("* No double root:", roots)
        raise ValueError("Could not find double root")
    print("* Found double root:", root)

    x = cast(PRmodp, f.parent()).gen()

    f_ = f.substitute(x=x + root)
    print("* Substituted polynomial:", f_)
    t = f_[2].sqrt()
    gx_ = gx - root
    px_ = px - root

    logs: set[int] = set()
    multiple_solutions = len(gys) > 1 or len(pys) > 1
    for gy_, py_ in product(gys, pys):
        if multiple_solutions:
            print(f"* Trying Gy = {gy_}; Py = {py_}")
        u = (gy_ + t * gx_) / (gy_ - t * gx_)
        v = (py_ + t * px_) / (py_ - t * px_)

        print(f"{'  ' if multiple_solutions else ''}* Computing discrete log...")
        n = v.log(u)
        logs.add(int(n))

    return logs
