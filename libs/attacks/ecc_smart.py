from typing import cast

from ..sage_types import ECFF, ECPF, ZZ, ECFFPoint, ECFPoint, EllipticCurve, FFPmodn, Qp


def hensel_lift(E: ECPF, P: ECFFPoint) -> ECFPoint | None:
    """Lift point `P` to the p-adic numbers on curve `E` using Hensel's lemma"""
    F = cast(FFPmodn, cast(ECFF, P.curve()).base_ring())
    p_x, p_y = map(ZZ, P.xy())
    for pt in E.lift_x(p_x, all=True):
        y = F(pt.xy()[1])
        if p_y == y:
            return pt

    return None


def smart_attack(G: ECFFPoint, P: ECFFPoint) -> int:
    """Try solving the discrete logarithm problem using Smart's attack"""
    E = cast(ECFF, G.curve())
    Fp = cast(FFPmodn, E.base_ring())
    p = Fp.order()
    print("* Ring order: p = #Fp =", p)
    print("* Computing curve order...")
    curve_order = E.order()
    print("* Order: #E(FP) =", curve_order)
    if curve_order != p:
        raise ValueError("Curve is not anomalous (Smart attack requires #E(Fp) = p)")

    Eqp = cast(
        ECPF,
        EllipticCurve(Qp(p), [int(a) + p * ZZ.random_element(1, p) for a in E.a_invariants()]),
    )

    print("* Hensel lifting G...")
    G_lift = hensel_lift(Eqp, G)
    if G_lift is None:
        raise ValueError("Hensel lifting failed for G")
    print("* Hensel lifting P...")
    P_lift = hensel_lift(Eqp, P)
    if P_lift is None:
        raise ValueError("Hensel lifting failed for P")

    print("* Computing n...")
    Gqp = cast(ECFPoint, p * G_lift)
    Pqp = cast(ECFPoint, p * P_lift)
    Gqp_x, Gqp_y = Gqp.xy()
    Pqp_x, Pqp_y = Pqp.xy()
    n = int(Fp((Pqp_x / Pqp_y) / (Gqp_x / Gqp_y)))

    if n * G != P:
        raise ValueError(f"n * G != P ({n = })")
    return n
