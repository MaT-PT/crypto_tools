from typing import cast

from ..sage_types import ECFF, CRT_list, ECFFPoint, Integer


def pohlig_hellman_attack(G: ECFFPoint, P: ECFFPoint, size_limit: int = 56) -> int:
    """Try solving the discrete logarithm problem using the Pohlig-Hellman algorithm.
    Try with factors of increasing size until the log is found
    (CRT can give the right result even if not all factors are computed).
    Stop when the size of the factors exceeds `size_limit` bits
    (computation time increases with the square root of the factor's size)."""
    print("* Computing curve order...")
    n = Integer(cast(ECFF, G.curve()).order())
    print("* Order:", n)

    factors = n.factor()
    factors.sort()
    print("* Factors:", factors)

    mods: list[Integer] = []
    logs: list[Integer] = []

    for p, e in factors:
        nbits = p.nbits()
        if nbits > size_limit:
            print(f"* Factor {p} is too large, skipping ({nbits} bits, limit is {size_limit})")
            continue

        print(f"* Trying factor: {p}^{e}...")
        fact = p**e
        mods.append(fact)
        n_fact = n // fact
        Gp = cast(ECFFPoint, G * n_fact)
        Pp = cast(ECFFPoint, P * n_fact)

        print("  * Computing discrete log...")
        n_p = Gp.discrete_log(Pp)
        print(f"  * n_p = {n_p}")
        logs.append(n_p)

        print("  * Solving CRT...")
        crt = CRT_list(logs, mods)
        print(f"  * CRT = {crt}")
        if crt * G == P:
            print("  * Found n!")
            return int(crt)

    raise ValueError(
        f"Found no solution for ECDLP, try increasing the bit size limit (--max-bits)"
    )
