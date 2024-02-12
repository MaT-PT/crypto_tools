#!/usr/bin/env python3

from argparse import ArgumentParser, ArgumentTypeError, Namespace
from typing import cast

from libs.crypto_utils import check_hash_type, decrypt_aes_hash, hexstr_to_bytes, long_to_bytes
from libs.ecc_utils import Point, calc_curve_params, parse_int


def my_int(value: str) -> int:
    try:
        return parse_int(value)
    except ValueError as e:
        raise ArgumentTypeError(str(e))


def pos_int(value: str) -> int:
    n = my_int(value)
    if n < 0:
        raise ArgumentTypeError("should not be a negative integer")
    return n


def hash_(value: str) -> str:
    try:
        return check_hash_type(value)
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

    grp_ph = parser.add_argument_group(
        "Pohlig-Hellman attack",
        "Supplying --max-n-bits will enable trying Pollard's Lambda "
        "algorithm if partial P-H attack didn't succeed",
    )
    grp_ph.add_argument("--max-bits", "-m", type=pos_int, default=48, help="Max factor bit length")
    grp_ph.add_argument("--max-n-bits", "-M", type=pos_int, default=0, help="Max bit length for n")
    grp_ph.add_argument("--min-n-bits", "-L", type=pos_int, default=1, help="Min bit length for n")

    grp_d = parser.add_argument_group(
        "Decryption", description="Decrypt plain secret or AES, with or without Diffie-Hellman"
    )
    grp_dx = grp_d.add_mutually_exclusive_group()
    grp_dx.add_argument(
        "--decrypt", "-d", action="store_true", help="Decrypt plain secret directly (as a long)"
    )
    grp_dx.add_argument(
        "--decrypt-aes",
        "-D",
        type=hexstr_to_bytes,
        help="AES-encrypted ciphertext",
        metavar="ENC_BYTES",
    )
    grp_d.add_argument(
        "--iv", "-i", type=hexstr_to_bytes, help="Initialization vector (IV) for AES"
    )
    grp_d.add_argument(
        "--hash", "-H", type=hash_, default="SHA1", help="Hash function for AES (default: SHA1)"
    )
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

    if args.decrypt_aes is not None and args.iv is None:
        parser.error("AES decryption requires an IV (--iv)")

    if args.max_n_bits != 0:
        if args.min_n_bits <= 0:
            parser.error("--min-n-bits/-L must be > 0")
        if args.min_n_bits > args.max_n_bits:
            parser.error("--min-n-bits/-L must be less than or equal to --max-n-bits/-M")

    if isinstance(args.G, Point) and not args.G.on_curve(args.a, args.b, args.p):
        parser.error("G is not on the curve")
    if isinstance(args.P, Point) and not args.P.on_curve(args.a, args.b, args.p):
        parser.error("P is not on the curve")
    if args.decrypt_aes is not None:
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

    print("B:", B)

    S = B * n
    shared_secret = int(S[0])
    print("* Shared secret:", shared_secret)

    return decrypt_aes_hash(args.decrypt_aes, shared_secret, args.iv, args.hash)


def do_attacks(args: Namespace) -> int | set[int] | None:
    print("* Importing libs...")
    from libs.attacks import mov_attack, pohlig_hellman_attack, singular_attack, smart_attack
    from libs.sage_types import ECFF, GF, ECFFPoint, EllipticCurve, FFPmodn, Integer

    p = int(args.p)
    a = int(args.a)
    b = int(args.b)
    gx, gy = int(args.gx), int(args.gy) if args.gy is not None else None
    px, py = int(args.px), int(args.py) if args.py is not None else None
    res: int | set[int]

    print("* Computing curve discriminant...")
    F = cast(FFPmodn, GF(p))
    x = F["x"].gen()
    f = x**3 + a * x + b
    d = int(f.discriminant())
    print("* Discriminant:", d)

    if d == 0:
        print("The curve is singular!")
        print()
        print("Trying singular attack...")
        try:
            res = singular_attack(f, gx, gy, px, py)
            print("* Singular attack succeded!")
            return res
        except ValueError as e:
            print("* Singular attack failed:", e)
            return None

    print("This is a valid elliptic curve (non-singular)")
    print()
    E = cast(ECFF, EllipticCurve(F, (a, b)))
    if gy is None:
        G = cast(ECFFPoint, E.lift_x(Integer(gx)))
        args.gy = gy = int(G[1])
        args.G = Point(gx, gy)
    else:
        G = cast(ECFFPoint, E(args.G))
    if py is None:
        P = cast(ECFFPoint, E.lift_x(Integer(px)))
        args.py = py = int(P[1])
        args.P = Point(px, py)
    else:
        P = cast(ECFFPoint, E(args.P))

    print("E:", E)
    print("G:", G)
    print("P:", P)
    args.sage = {"E": E, "G": G, "P": P}

    print()
    print("Trying MOV attack...")
    try:
        res = mov_attack(G, P)
        print("* MOV attack succeded!")
        return res
    except ValueError as e:
        print("* MOV attack failed:", e)

    print()
    print("Trying Smart attack...")
    try:
        res = smart_attack(G, P)
        print("* Smart attack succeded!")
        return res
    except ValueError as e:
        print("* Smart attack failed:", e)

    print()
    print("Trying Pohlig-Hellman attack...")
    try:
        res = pohlig_hellman_attack(G, P, args.max_bits, args.max_n_bits, args.min_n_bits)
        print("* Pohlig-Hellman attack succeded!")
        return res
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

    res = do_attacks(args)
    if res is None:
        print("No attack succeeded :(")
        return

    print()
    print("Discrete logarithm: P = n * G")

    if isinstance(res, set):
        if len(res) == 0:
            print("Attack returned no possible values :(")
            return
        if len(res) > 1:
            print("Multiple possible values found for n:")
    else:
        res = {res}

    for n in res:
        print()
        print(f"{n = }")
        if args.decrypt or args.decrypt_aes is not None:
            if args.decrypt:
                print("* Decrypting secret directly...")
                decrypted = long_to_bytes(n)
            elif args.bx is None:
                print(f"* Decrypting AES (hash: {args.hash})...")
                decrypted = decrypt_aes_hash(args.decrypt_aes, n, args.iv, args.hash)
            else:
                print(f"* Decrypting AES with Diffie-Hellman (hash function: {args.hash})...")
                decrypted = decrypt_diffie_hellman(args, n)

            try:
                print("Decrypted message:", decrypted.decode())
            except UnicodeDecodeError:
                print("Warning: decrypted message is not a valid UTF-8 string")
                print("* Raw bytes:", decrypted)
                print("* Hex:", decrypted.hex())


if __name__ == "__main__":
    main()
