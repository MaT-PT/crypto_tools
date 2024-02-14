from argparse import ArgumentParser, ArgumentTypeError
from argparse import BooleanOptionalAction as BOA
from argparse import Namespace

from .crypto_utils import check_hash_type, hexstr_to_bytes
from .ecc_utils import Point, calc_curve_params, parse_int


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
        "Try to find the discrete logarithm of a point P on an elliptic curve "
        "given the generator point G (that is, find n such that P = n * G)."
    )

    grp_curve = parser.add_argument_group(
        "Elliptic curve parameters",
        "Curve has equation y^2 + a1*x*y + a3*y = x^3 + a2*x^2 + a4*x + a6 (mod p) "
        "(or y^2 = x^3 + a*x + b (mod p))",
    )
    grp_curve.add_argument("-p", type=my_int, help="Prime modulus", metavar="p", required=True)
    grp_curve.add_argument("-a1", type=my_int, help="Param a1 (optional)", metavar="a1")
    grp_curve.add_argument("-a2", type=my_int, help="Param a2 (optional)", metavar="a2")
    grp_curve.add_argument("-a3", type=my_int, help="Param a3 (optional)", metavar="a3")
    grp_curve.add_argument("-a4", "-a", type=my_int, help="Param a4 (a) (optional)", metavar="a4")
    grp_curve.add_argument("-a6", "-b", type=my_int, help="Param a6 (b) (optional)", metavar="a6")

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

    grp_a = parser.add_argument_group(
        "Attacks", "Enabled attacks will be run on their own; disabled attacks will be skipped"
    )
    grp_a.add_argument("--mov", action=BOA, help="Enable/disable MOV attack")
    grp_a.add_argument("--smart", action=BOA, help="Enable/disable Smart attack")
    grp_a.add_argument("--ph", action=BOA, help="Enable/disable Pohlig-Hellman attack")
    grp_a.add_argument("--singular", action=BOA, help="Enable/disable singular curve attack")

    parser.epilog = (
        "If curve parameters are known, Gy and Py can be omitted (and vice versa).\n"
        "Points that are fully specified will be checked to be on the curve."
    )

    args = parser.parse_args()

    if args.G is not None:
        args.gx, args.gy = args.G
    if args.P is not None:
        args.px, args.py = args.P
    if args.B is not None:
        args.bx, args.by = args.B

    has_curve_param = any(a is not None for a in (args.a1, args.a2, args.a3, args.a4, args.a6))

    if (args.gy is None or args.py is None) and not has_curve_param:
        parser.error(
            "either give curve params (-a1, -a2, -a3, -a4/-a, -a6/-b), or fully specify G and P"
        )

    if args.G is None and args.gx is not None and args.gy is not None:
        args.G = Point(args.gx, args.gy)
    if args.P is None and args.px is not None and args.py is not None:
        args.P = Point(args.px, args.py)
    if args.B is None and args.bx is not None and args.by is not None:
        args.B = Point(args.bx, args.by)

    if not has_curve_param:
        try:
            args.a4, args.a6 = calc_curve_params(args.p, args.P, args.G)
            print("Calculated curve parameters:")
            print(f"* a = {args.a4}")
            print(f"* b = {args.a6}")
        except (ValueError, AssertionError) as e:
            parser.error(f"could not calculate curve parameters: {e}")

    a1 = args.a1 = args.a1 or 0
    a2 = args.a2 = args.a2 or 0
    a3 = args.a3 = args.a3 or 0
    a4 = args.a4 = args.a = args.a4 or 0
    a6 = args.a6 = args.b = args.a6 or 0

    if args.decrypt_aes is not None and args.iv is None:
        parser.error("AES decryption requires an IV (--iv)")

    if args.max_n_bits != 0:
        if args.min_n_bits <= 0:
            parser.error("--min-n-bits/-L must be > 0")
        if args.min_n_bits > args.max_n_bits:
            parser.error("--min-n-bits/-L must be less than or equal to --max-n-bits/-M")

    a_invs = (a1, a2, a3, a4, a6)
    if isinstance(args.G, Point) and not args.G.on_curve(a_invs, args.p):
        parser.error("G is not on the curve")
    if isinstance(args.P, Point) and not args.P.on_curve(a_invs, args.p):
        parser.error("P is not on the curve")
    if args.decrypt_aes is not None:
        if isinstance(args.B, Point) and not args.B.on_curve(a_invs, args.p):
            parser.error("B is not on the curve")

    args.a_invs = a_invs

    return args
