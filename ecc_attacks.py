#!/usr/bin/env python3

from argparse import Namespace
from typing import Callable, ParamSpec, TypeVar, cast

from libs.argparse_utils import parse_args
from libs.crypto_utils import decrypt_aes_hash, long_to_bytes
from libs.ecc_utils import AInvs, Point, discriminant

_P = ParamSpec("_P")
_T = TypeVar("_T")


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


def run_attack(
    attack: Callable[_P, _T],
    name: str,
    run_all: bool,
    run_this: bool | None,
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> _T | None:
    print()
    if run_this is not False and (run_all or run_this):
        print(f"Trying {name} attack...")
        try:
            res = attack(*args, **kwargs)
            print(f"* {name} attack succeded!")
            return res
        except ValueError as e:
            print(f"* {name} attack failed:", e)
        except KeyboardInterrupt:
            print(f"* {name} attack was interrupted by user")
    else:
        print(f"(Skipping {name} attack)")
    return None


def do_attacks(args: Namespace) -> int | set[int] | None:
    run_all = all(not atk for atk in (args.mov, args.smart, args.ph, args.singular))
    a1, a2, a3, a4, a6 = int(args.a1), int(args.a2), int(args.a3), int(args.a4), int(args.a6)
    a_invs = AInvs((a1, a2, a3, a4, a6))
    p = int(args.p)
    print(f"* Curve: y^2 + {a1}*x*y + {a3}*y = x^3 + {a2}*x^2 + {a4}*x + {a6} (mod {p})")
    print("* Importing libs...")
    from libs.attacks import mov_attack, pohlig_hellman_attack, singular_attack, smart_attack
    from libs.sage_types import ECFF, GF, ECFFPoint, EllipticCurve, FFPmodn, Integer

    try:
        F = cast(FFPmodn, GF(p))
    except ValueError as e:
        print(f"Error: {e}")
        return None
    gx, gy = int(args.gx), int(args.gy) if args.gy is not None else None
    px, py = int(args.px), int(args.py) if args.py is not None else None

    print("* Computing curve discriminant...")
    d = discriminant(a_invs, p)
    print("* Discriminant:", d)

    if d == 0:
        print("The curve is singular!")
        return run_attack(
            singular_attack, "singular curve", run_all, args.singular, a_invs, F, gx, gy, px, py
        )

    print("This is a valid elliptic curve (non-singular)")
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

    print()
    print("E:", E)
    print("G:", G)
    print("P:", P)
    args.sage = {"E": E, "G": G, "P": P}

    res = run_attack(mov_attack, "MOV", run_all, args.mov, G, P)
    if res is not None:
        return res

    res = run_attack(smart_attack, "Smart", run_all, args.smart, G, P)
    if res is not None:
        return res

    res = run_attack(
        pohlig_hellman_attack,
        "Pohlig-Hellman",
        run_all,
        args.ph,
        G,
        P,
        args.max_bits,
        args.max_n_bits,
        args.min_n_bits,
    )
    if res is not None:
        return res

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
    print()
    if res is None:
        print("No attack succeeded :(")
        return

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
