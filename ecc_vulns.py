#!/usr/bin/env python3

from argparse import ArgumentParser, ArgumentTypeError, Namespace
from typing import cast

from libs.crypto_utils import decrypt_aes_hash, hexstr_to_bytes
from libs.ecc_utils import Point, calc_curve_params, parse_int


def my_int(value: str) -> int:
    try:
        return parse_int(value)
    except ValueError as e:
        raise ArgumentTypeError(str(e))


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="A collection of elliptic curve cryptography vulnerabilities.\n"
        "Try to find the discrete logarithm of a point P on the curve y^2 = x^3 + ax + b (mod p) "
        "given the generator point G (that is, find n in P = n * G)."
    )

    grp_curve = parser.add_argument_group(
        "Elliptic curve parameters", "Curve has equation y^2 = x^3 + ax + b (mod p)"
    )
    grp_curve.add_argument("-a", type=my_int, help="Curve parameter a (optional)", metavar="a")
    grp_curve.add_argument("-b", type=my_int, help="Curve parameter b (optional)", metavar="b")
    grp_curve.add_argument("-p", type=my_int, help="Prime modulus", metavar="p", required=True)

    grp_g = parser.add_argument_group(
        "Generator point G", "Supply either -G, or -gx (and optionally -gy)"
    )
    grp_gx = grp_g.add_mutually_exclusive_group(required=True)
    grp_gx.add_argument("-G", type=Point, help="G as a pair: x,y", metavar="G")
    grp_gx.add_argument("-gx", type=my_int, help="G x coordinate", metavar="Gx")
    grp_g.add_argument("-gy", type=my_int, help="G y coordinate (optional)", metavar="Gy")

    grp_p = parser.add_argument_group(
        "Target point P (Alice's public key)", "Supply either -P, or -px (and optionally -py)"
    )
    grp_px = grp_p.add_mutually_exclusive_group(required=True)
    grp_px.add_argument("-P", type=Point, help="P as a pair: x,y", metavar="P")
    grp_px.add_argument("-px", type=my_int, help="P x coordinate", metavar="Px")
    grp_p.add_argument("-py", type=my_int, help="P y coordinate (optional)", metavar="Py")

    grp_ph = parser.add_argument_group("Pohlig-Hellman attack")
    grp_ph.add_argument("--max-bits", "-m", type=int, default=48, help="Maximum factor bit length")

    grp_d = parser.add_argument_group("Decryption", description="Decrypt AES with Diffie-Hellman")
    grp_d.add_argument("--decrypt", "-d", type=hexstr_to_bytes, help="Ciphertext to decrypt")
    grp_d.add_argument("--iv", "-i", type=hexstr_to_bytes, help="Initialization vector (IV)")
    grp_b = parser.add_argument_group(
        "Extra point B (Bob's public key) - Optional, only used in Diffie-Hellman decryption",
        "Supply either -B, or -bx (and optionally -by)",
    )
    grp_bx = grp_b.add_mutually_exclusive_group()
    grp_bx.add_argument("-B", type=Point, help="B as a pair: x,y", metavar="B")
    grp_bx.add_argument("-bx", type=my_int, help="B x coordinate", metavar="Bx")
    grp_b.add_argument("-by", type=my_int, help="B y coordinate (optional)", metavar="By")

    parser.epilog = (
        "If a and b are known, Gy and Py can be omitted (and vice versa).\n"
        "Points that are fully specified will be checked to be on the curve."
    )

    args = parser.parse_args()

    if args.G is not None:
        args.gx, args.gy = args.G
    if args.P is not None:
        args.px, args.py = args.P
    if args.B is not None:
        args.bx, args.by = args.B

    if (args.gy is None or args.py is None) and (args.a is None or args.b is None):
        parser.error(
            "the following arguments are required: (-a and -b) or ((-G or -gy) and (-P or -py))"
        )

    if args.G is None and args.gx is not None and args.gy is not None:
        args.G = Point(args.gx, args.gy)
    if args.P is None and args.px is not None and args.py is not None:
        args.P = Point(args.px, args.py)
    if args.B is None and args.bx is not None and args.by is not None:
        args.B = Point(args.bx, args.by)

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

    if args.decrypt is not None:
        if args.iv is None:
            parser.error("decryption requires an IV (--iv)")
        if args.bx is None:
            parser.error("decryption requires a public key B (-B, or -bx (and optionally -by))")

    if isinstance(args.G, Point) and not args.G.on_curve(args.a, args.b, args.p):
        parser.error("G is not on the curve")
    if isinstance(args.P, Point) and not args.P.on_curve(args.a, args.b, args.p):
        parser.error("P is not on the curve")
    if isinstance(args.B, Point) and not args.B.on_curve(args.a, args.b, args.p):
        parser.error("B is not on the curve")

    return args


def decrypt_diffie_hellman(args: Namespace, n: int) -> bytes:
    from libs.sage_types import ECFF, ECFFPoint, Integer

    E = cast(ECFF, args.sage["E"])

    if args.by is None:
        B = cast(ECFFPoint, E.lift_x(Integer(args.bx)))
    else:
        B = cast(ECFFPoint, E(args.B))

    S = B * n
    shared_secret = int(S[0])
    print("* Shared secret:", shared_secret)

    return decrypt_aes_hash(args.decrypt, shared_secret, args.iv)


def do_attacks(args: Namespace) -> int | None:
    print("* Importing libs...")
    from libs.attacks import mov_attack, pohlig_hellman_attack, smart_attack
    from libs.sage_types import ECFF, GF, ECFFPoint, EllipticCurve, Integer

    E = cast(ECFF, EllipticCurve(GF(args.p), (args.a, args.b)))
    if args.gy is None:
        G = cast(ECFFPoint, E.lift_x(Integer(args.gx)))
        args.gy = int(G[1])
        args.G = Point(args.gx, args.gy)
    else:
        G = cast(ECFFPoint, E(args.G))
    if args.py is None:
        P = cast(ECFFPoint, E.lift_x(Integer(args.px)))
        args.py = int(P[1])
        args.P = Point(args.px, args.py)
    else:
        P = cast(ECFFPoint, E(args.P))

    print("E:", E)
    print("G:", G)
    print("P:", P)
    args.sage = {"E": E, "G": G, "P": P}

    print()
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

    print()
    print("Trying Pohlig-Hellman attack...")
    try:
        n = pohlig_hellman_attack(G, P, args.max_bits)
        print("* Pohlig-Hellman attack succeded!")
        return n
    except ValueError as e:
        print("* Pohlig-Hellman attack failed:", e)

    return None


def main() -> None:
    args = parse_args()

    print(f"Curve: y^2 = x^3 + {args.a}x + {args.b} (mod {args.p})")
    if args.G is None:
        print("Generator point G: Gx =", args.gx)
    else:
        print("Generator point G:", args.G)
    if args.P is None:
        print("Target point P: Px =", args.px)
    else:
        print(f"Target point P: {args.P}")

    n = do_attacks(args)
    if n is None:
        print("No attack succeeded :(")
        return

    print("Discrete logarithm: P = n * G")
    print(f"{n = }")

    if args.decrypt is not None:
        decrypted = decrypt_diffie_hellman(args, n)
        print("Decrypted message:", decrypted.decode())


if __name__ == "__main__":
    main()
