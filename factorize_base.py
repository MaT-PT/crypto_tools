#!/usr/bin/env python3


from collections import Counter


def factorize_base(N: int, max_base: int = 64) -> tuple[int, int]:
    """Try to factorize `N` using a base where it has a high ratio of 0s in its digits,
    with polynomial factorization. Will try bases from 2 to `max_base`."""
    print("Importing libs...")

    from libs.sage_types import PRID, ZZ, Factorization, Integer, Polynomial

    n = Integer(N)
    P: PRID = ZZ["x"]
    x: Polynomial = P.gen()

    for base in range(2, max_base + 1):
        digits: list[int] = n.digits(base)
        digits_counter = Counter(digits)
        ratio = digits_counter[0] / digits_counter.total()
        print(f"Base {base}: {ratio:.2%} of 0s ({digits_counter})")

        if ratio >= 0.8:
            print(f"Base {base} is a good candidate!")
            poly: Polynomial = sum(e * x**i for i, e in enumerate(digits))
            print(f"* Polynomial: {poly}")
            print("Factorizing...")
            factors: Factorization = poly.factor()
            print(f"* Factors: {factors}")
            fact_counter: Counter[Polynomial] = Counter(dict(factors))
            nb_factors = fact_counter.total()
            actual_factors = list(fact_counter.elements())

            if nb_factors < 2:
                print("* Failed to factorize N: not enough factors")
                continue
            if nb_factors > 2:
                print("* More than 2 factors!")
                for f, _ in actual_factors:
                    print(f"  - {f} = {f(base)}")
                p = actual_factors[0][0](base)
                q = n // p
            else:
                f_p, f_q = actual_factors
                print(f"* f_p: {f_p}, f_q: {f_q}")
                p = f_p(base)
                q = f_q(base)
            if p * q == n:
                print("* Success!")
                return int(p), int(q)
            else:
                print("* Failed to factorize N: p * q != N")

    raise ValueError("Failed to factorize N")


def main(argv: list[str]) -> None:
    if len(argv) <= 1:
        print(f"Usage: {argv[0]} <N>")
        return

    N = int(argv[1])
    max_base = 64
    if len(argv) > 2:
        max_base = int(argv[2])
    print(f"Trying to factorize {N = } with base up to {max_base}...")
    p, q = factorize_base(N, max_base)
    print(f"{p = }")
    print(f"{q = }")


if __name__ == "__main__":
    from sys import argv

    main(argv)
