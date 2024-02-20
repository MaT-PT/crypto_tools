#!/usr/bin/env python3

from itertools import product
from math import prod
from typing import Callable, ParamSpec, TypeVar, cast

from libs.argparse_utils import Arguments, parse_args
from libs.crypto_utils import decrypt_aes_hash, long_to_bytes
from libs.ecc_utils import Point, discriminant, lift_x
from libs.types import Result

_P = ParamSpec("_P")
_T = TypeVar("_T")


def decrypt_diffie_hellman(args: Arguments, n: int, ps: list[int]) -> set[bytes]:
    assert args.decrypt_aes is not None and args.iv is not None and args.bx is not None
    from libs.ecc_utils import lift_x
    from libs.sage_types import EC, ECFFPoint, EllipticCurve, Zmod

    N = prod(ps)
    E = cast(EC, EllipticCurve(Zmod(N), args.a_invs))

    if args.by is None:
        Bs = {cast(ECFFPoint, E(pt)) for pt in lift_x(args.a_invs, args.bx, ps)}
    else:
        Bs = {cast(ECFFPoint, E(args.B))}

    decrypted: set[bytes] = set()
    for B in Bs:
        print("B:", B)

        S = B * n
        shared_secret = int(S[0])
        print("* Shared secret:", shared_secret)

        decrypted.add(decrypt_aes_hash(args.decrypt_aes, shared_secret, args.iv, args.hash))

    return decrypted


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
            print(f"Result: {res}")
            return res
        except ValueError as e:
            print(f"* {name} attack failed:", e)
        except KeyboardInterrupt:
            print(f"* {name} attack was interrupted by user")
    else:
        print(f"(Skipping {name} attack)")
    return None


def run_attacks(args: Arguments, p: int, is_composite: bool = False) -> set[Result] | None:
    run_all = all(not atk for atk in (args.mov, args.smart, args.ph, args.singular))
    a1, a2, a3, a4, a6 = a_invs = args.a_invs
    print(f"* Curve: y^2 + {a1}*x*y + {a3}*y = x^3 + {a2}*x^2 + {a4}*x + {a6} (mod {p})")
    from libs.attacks import mov_attack, pohlig_hellman_attack, singular_attack, smart_attack
    from libs.ecc_utils import lift_x
    from libs.sage_types import ECFF, GF, ECFFPoint, EllipticCurve, FFPmodn

    try:
        F = cast(FFPmodn, GF(p))
    except ValueError as e:
        print(f"Error: {e}")
        return None
    gx, gy = args.gx, args.gy
    px, py = args.px, args.py

    print("* Computing curve discriminant...")
    d = discriminant(a_invs, p)
    print("* Discriminant:", d)

    if d == 0:
        print("The curve is singular!")
        res = run_attack(
            singular_attack,
            "singular curve",
            run_all,
            args.singular,
            a_invs,
            F,
            gx,
            gy,
            px,
            py,
            args.use_generic_log,
        )
        return res.result_set() if res else None

    print("This is a valid elliptic curve (non-singular)")
    try:
        E = cast(ECFF, EllipticCurve(F, a_invs))
    except ValueError as e:
        print(f"Error: {e}")
        return None
    print()
    print("E:", E)

    if gy is None:
        Gs = {cast(ECFFPoint, E(pt)) for pt in lift_x(args.a_invs, args.gx, [p])}
    else:
        Gs = {cast(ECFFPoint, E(args.G))}
    if py is None:
        Ps = {cast(ECFFPoint, E(pt)) for pt in lift_x(args.a_invs, args.px, [p])}
    else:
        Ps = {cast(ECFFPoint, E(args.P))}

    if len(Gs) == 2 and len(Ps) == 2:
        G1, G2 = Gs
        if G1 == -G2:
            print()
            print("Possible points are opposites: skipping one of the possible Ps")
            Ps.pop()

    results: set[Result] = set()

    for G, P in product(Gs, Ps):
        print()
        print("* G:", G.xy())
        print("* P:", P.xy())

        res = run_attack(mov_attack, "MOV", run_all, args.mov, G, P)
        if res is not None:
            results |= res.result_set()
            continue

        res = run_attack(smart_attack, "Smart", run_all, args.smart, G, P)
        if res is not None:
            results |= res.result_set()
            continue

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
            allow_partial=is_composite,
        )
        if res is not None:
            results |= res.result_set()
            continue

    return results or None


def composite_attack(args: Arguments, ps: list[int]) -> set[int] | None:
    from libs.sage_types import EC, CRT_list, ECFFPoint, EllipticCurve, Zmod

    results: list[set[Result]] = []
    for p in ps:
        res = run_attacks(args, p, is_composite=True)
        print()
        if not res:
            print("No attack succeeded :(")
            return None
        results.append(res)

    print("Results:")
    for p, r in zip(ps, results):
        print(f"* p = {p}: {r}")
    print()

    N = prod(ps)
    E = cast(EC, EllipticCurve(Zmod(N), args.a_invs))
    if args.gy is None:
        Gs = {cast(ECFFPoint, E(pt)) for pt in lift_x(args.a_invs, args.gx, ps)}
    else:
        Gs = {cast(ECFFPoint, E(args.G))}
    if args.py is None:
        Ps = {cast(ECFFPoint, E(pt)) for pt in lift_x(args.a_invs, args.px, ps)}
    else:
        Ps = {cast(ECFFPoint, E(args.P))}

    valid_ns: set[int] = set()
    parts: tuple[Result, ...]
    for parts in product(*results):
        print("* Trying combination:", parts)
        n = int(CRT_list([part.n for part in parts], [part.order for part in parts]))
        print(f"* n = {n}")
        for G, P in product(Gs, Ps):
            print(f"  * Checking for G = {G}; P = {P}...")
            if n * G == P:
                print("Found valid n!")
                valid_ns.add(n)
                if args.gy is None:
                    args.gy = int(G[1])
                    args.G = Point(args.gx, args.gy)
                if args.py is None:
                    args.py = int(P[1])
                    args.P = Point(args.px, args.py)

    return valid_ns if valid_ns else None


def check_curve_type(args: Arguments, ps: list[int]) -> set[int] | None:
    if len(ps) == 1:
        res = run_attacks(args, ps[0])
        return {r.n for r in res} if res else None
    return composite_attack(args, ps)

def import_sagemath() -> None:
    import importlib

    import sage.version

    print(f"* Importing SageMath version {sage.version.version}...")
    importlib.import_module("libs.sage_types")
    print("* SageMath imported successfully")


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

    print()
    import_sagemath()
    print()

    res = check_curve_type(args, args.p)
    print()
    if res is None:
        print("No attack succeeded :(")
        return

    print("Discrete logarithm: P = n * G")

    if len(res) == 0:
        print("Attack returned no possible values :(")
        return
    if len(res) > 1:
        print("Multiple possible values found for n:")

    for n in res:
        print()
        print(f"{n = }")
        if args.decrypt or args.decrypt_aes is not None:
            if args.decrypt:
                print("* Decrypting secret directly...")
                decrypted = {long_to_bytes(n)}
            elif args.bx is None:
                print(f"* Decrypting AES (hash: {args.hash})...")
                assert args.decrypt_aes is not None and args.iv is not None
                decrypted = {decrypt_aes_hash(args.decrypt_aes, n, args.iv, args.hash)}
            else:
                print(f"* Decrypting AES with Diffie-Hellman (hash function: {args.hash})...")
                decrypted = decrypt_diffie_hellman(args, n, args.p)

            for dec in decrypted:
                try:
                    print("Decrypted message:", dec.decode())
                except UnicodeDecodeError:
                    print("Warning: decrypted message is not a valid UTF-8 string")
                    print("* Raw bytes:", dec)
                    print("* Hex:", dec.hex())


if __name__ == "__main__":
    main()
