from math import prod
from typing import cast

from ..sage_types import ECFF, CRT_list, ECFFPoint, Integer, discrete_log_lambda


def pohlig_hellman_attack(
    G: ECFFPoint, P: ECFFPoint, size_limit: int = 48, max_n_bits: int = 0, min_n_bits: int = 1
) -> int:
    """Try solving the discrete logarithm problem using the Pohlig-Hellman algorithm.
    Try with factors of increasing size until the log is found
    (CRT can give the right result even if not all factors are computed).
    Stop when the size of the factors exceeds `size_limit` bits
    (computation time increases with the square root of the factor's size)."""
    print("* Computing curve order...")
    n = Integer(cast(ECFF, G.curve()).order())
    print("* Order:", n)

    print("* Factoring order...")
    factors = n.factor()
    factors.sort()
    print("* Factors:", factors)

    mods: list[Integer] = []
    logs: list[Integer] = []
    crt = 0

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

    if max_n_bits > 0:
        print("* Could not find log directly, trying with Pollard's Lambda algorithm...")
        mod = prod(mods)
        print("  * Partial mod:", mod)
        GP_ = P - G * crt
        G_ = G * mod
        lower_bound = (1 << (min_n_bits - 1)) // mod or 1
        upper_bound = (1 << max_n_bits) // mod + 1
        print(f"  * Lower bound: {lower_bound}")
        print(f"  * Upper bound: {upper_bound}")
        log = discrete_log_lambda(GP_, G_, (lower_bound, upper_bound), operation="+")
        print("* Pollard's Lambda found log:", log)
        n_p = (log * mod + crt) % n

        if n_p * G != P:
            raise ValueError(f"n * G != P (n = {n_p})")
        return int(n_p)
    else:
        raise ValueError(
            "Found no solution for ECDLP, try increasing the factor bit size limit "
            "(--max-bits) or giving a max bit size for n, if known (--max-n-bits)"
        )
