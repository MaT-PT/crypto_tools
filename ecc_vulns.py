#!/usr/bin/env python3

from argparse import ArgumentParser, Namespace
from typing import cast

from libs.argparse_utils import PointAction, my_int
from libs.ecc_utils import Point, calc_curve_params, curve_contains_point


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="A collection of elliptic curve cryptography vulnerabilities.\n"
        "Try to find the discrete logarithm of a point P on the curve y^2 = x^3 + ax + b (mod p) "
        "given the generator point G (that is, find n in P = n * G).",
        allow_abbrev=False,
    )

    grp_curve = parser.add_argument_group("Elliptic curve parameters")
    grp_curve.add_argument("-a", type=my_int, help="Curve parameter a (optional)", metavar="a")
    grp_curve.add_argument("-b", type=my_int, help="Curve parameter b (optional)", metavar="b")
    grp_curve.add_argument("-p", type=my_int, help="Prime modulus", metavar="p", required=True)

    grp_g = parser.add_argument_group(
        "Generator point G", description="(supply either -gx/-gy or -G)"
    )
    grp_g.add_argument("-gx", type=my_int, help="G x coordinate", metavar="Gx", action=PointAction)
    grp_g.add_argument("-gy", type=my_int, help="G y coordinate", metavar="Gy", action=PointAction)
    grp_g.add_argument("-G", type=Point, help="G as a pair: x,y", metavar="G", action=PointAction)

    grp_p = parser.add_argument_group(
        "Target point P", description="(supply either -px/-py or -P)"
    )
    grp_p.add_argument("-px", type=my_int, help="P x coordinate", metavar="Px", action=PointAction)
    grp_p.add_argument("-py", type=my_int, help="P y coordinate", metavar="Py", action=PointAction)
    grp_p.add_argument("-P", type=Point, help="P as a pair: x,y", metavar="P", action=PointAction)

    args = parser.parse_args()

    if args.G is not None:
        args.gx, args.gy = args.G.x, args.G.y
    if args.P is not None:
        args.px, args.py = args.P.x, args.P.y
    if args.gx is None or args.gy is None:
        parser.error("the following arguments are required: -gx/-gy or -G")
    if args.px is None or args.py is None:
        parser.error("the following arguments are required: -px/-py or -P")
    if args.G is None:
        args.G = Point(args.gx, args.gy)
    if args.P is None:
        args.P = Point(args.px, args.py)
    if args.a is None and args.b is None:
        try:
            args.a, args.b = calc_curve_params(args.p, args.P, args.G)
            print("Calculated curve parameters:")
            print(f"* a = {args.a}")
            print(f"* b = {args.b}")
        except (ValueError, AssertionError) as e:
            parser.error("could not calculate curve parameters: " + str(e))
    elif args.a is None or args.b is None:
        parser.error("supply either both -a and -b, or none of them")

    if not curve_contains_point(args.a, args.b, args.p, args.G):
        parser.error("G is not on the curve")
    if not curve_contains_point(args.a, args.b, args.p, args.P):
        parser.error("P is not on the curve")

    return args


def do_attacks(args: Namespace) -> int | None:
    print("* Importing libs...")
    from libs.attacks import mov_attack, smart_attack
    from libs.sage_types import ECFF, GF, ECFFPoint, EllipticCurve

    E = cast(ECFF, EllipticCurve(GF(args.p), (args.a, args.b)))
    G = cast(ECFFPoint, E(tuple(args.G)))
    P = cast(ECFFPoint, E(tuple(args.P)))
    print("E:", E)
    print("G:", G)
    print("P:", P)

    print("Trying MOV attack...")
    try:
        n = mov_attack(G, P)
        print("* MOV attack succeded!")
        return n
    except ValueError as e:
        print("* MOV attack failed:", e)

    print()
    print("Trying Smart attack...")
    try:
        n = smart_attack(G, P)
        print("* Smart attack succeded!")
        return n
    except ValueError as e:
        print("* Smart attack failed:", e)

    return None


def main() -> None:
    args = parse_args()

    print(f"Curve: y^2 = x^3 + {args.a}x + {args.b} (mod {args.p})")
    print(f"Generator point G: {args.G}")
    print(f"Target point P: {args.P}")

    n = do_attacks(args)
    if n is None:
        print("* No attack succeeded :(")
        return

    print("* Discrete logarithm: P = n * G")
    print(f"{n = }")


if __name__ == "__main__":
    main()
