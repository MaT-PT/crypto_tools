import math
from typing import cast

from ..sage_types import ECFF, GF, ECFFPoint, EllipticCurve
from ..types import SupportsLog


def embedding_degree(E: ECFF, max_k: int) -> int:
    """Compute the embedding degree `k` of the curve `E` (return -1 if `k > max_k`)"""
    n = E.order()
    q = E.base_field().order()
    k = 1
    while (q**k - 1) % n != 0:
        k += 1
        if k > max_k:
            return -1
    return k


def mov_attack(G: ECFFPoint, P: ECFFPoint) -> int:
    """Try solving the discrete logarithm problem using the MOV attack"""
    E = cast(ECFF, G.curve())
    print("* Computing embedding degree k of E...")
    k = embedding_degree(E, 6)
    print("* k =", k)
    if k < 0:
        raise ValueError(f"E is not supersingular")

    a, b = E.a4(), E.a6()
    q = E.base_field().order()
    Ek = cast(ECFF, EllipticCurve(GF(q**k), (a, b)))
    # print("* Ek:", Ek)

    print("* Computing order of G...")
    n = G.order()
    print("* Order: n =", n)

    print("* Generating point B with order n...")
    while True:
        R = cast(ECFFPoint, Ek.random_point())
        print("  * R =", R)
        m = R.order()
        print("  * m =", m)
        d = math.gcd(m, n)
        print("  * d =", d)
        B = cast(ECFFPoint, R * (m // d))
        print("  * B =", B)

        if B.order() == n:
            break
        print("* Mismatching orders, retrying...")

    Gk = cast(ECFFPoint, Ek(G))
    Pk = cast(ECFFPoint, Ek(P))
    # print("* Gk =", Gk)
    # print("* Pk =", Pk)

    print("* Computing Weil pairings...")
    u: SupportsLog = Gk.weil_pairing(B, n)
    v: SupportsLog = Pk.weil_pairing(B, n)
    # print("* u =", u)
    # print("* v =", v)

    print("* Computing discrete log...")
    n_p = v.log(u)

    if n_p * G != P:
        raise ValueError(f"n * G != P (n = {n_p})")
    return int(n_p)
