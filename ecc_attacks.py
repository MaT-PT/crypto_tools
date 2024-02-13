#!/usr/bin/env python3

from argparse import Namespace
from typing import cast

from libs.argparse_utils import parse_args
from libs.crypto_utils import decrypt_aes_hash, long_to_bytes
from libs.ecc_utils import Point, discriminant


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
    a_invs = (int(args.a1), int(args.a2), int(args.a3), int(args.a4), int(args.a6))
    a1, a2, a3, a4, a6 = a_invs
    print(f"* Curve: y^2 + {a1}*x*y + {a3}*y = x^3 + {a2}*x^2 + {a4}*x + {a6}")
    print("* Importing libs...")
    from libs.attacks import mov_attack, pohlig_hellman_attack, singular_attack, smart_attack
    from libs.sage_types import ECFF, GF, ECFFPoint, EllipticCurve, FFPmodn, Integer

    p = int(args.p)
    try:
        F = cast(FFPmodn, GF(p))
    except ValueError as e:
        print(f"Error: {e}")
        return None
    gx, gy = int(args.gx), int(args.gy) if args.gy is not None else None
    px, py = int(args.px), int(args.py) if args.py is not None else None
    res: int | set[int]

    print("* Computing curve discriminant...")
    d = discriminant(a_invs, p)
    print("* Discriminant:", d)

    if d == 0:
        print("The curve is singular!")
        print()
        print("Trying singular attack...")
        try:
            res = singular_attack(a_invs, F, gx, gy, px, py)
            print("* Singular attack succeded!")
            return res
        except ValueError as e:
            print("* Singular attack failed:", e)
            return None
        except KeyboardInterrupt:
            print("* Singular attack was interrupted by user")
            return None

    print("This is a valid elliptic curve (non-singular)")
    print()
    try:
        E = cast(ECFF, EllipticCurve(F, a_invs))
    except ValueError as e:
        print(f"Error: {e}")
        return None

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
    except KeyboardInterrupt:
        print("* MOV attack was interrupted by user")

    print()
    print("Trying Smart attack...")
    try:
        res = smart_attack(G, P)
        print("* Smart attack succeded!")
        return res
    except ValueError as e:
        print("* Smart attack failed:", e)
    except KeyboardInterrupt:
        print("* Smart attack was interrupted by user")

    print()
    print("Trying Pohlig-Hellman attack...")
    try:
        res = pohlig_hellman_attack(G, P, args.max_bits, args.max_n_bits, args.min_n_bits)
        print("* Pohlig-Hellman attack succeded!")
        return res
    except ValueError as e:
        print("* Pohlig-Hellman attack failed:", e)
    except KeyboardInterrupt:
        print("* Pohlig-Hellman attack was interrupted by user")

    return None


def main() -> None:
    args = parse_args()

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
