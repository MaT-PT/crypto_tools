# crypto_tools

A collection of cryptographic attacks and tools for CTFs and other purposes.

This is a work in progress, and its purpose is to complement other tools such as [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool).

## Tools

### RSA / Prime Factorization

- [`factorize_base.py`](factorize_base.py): Tries to factorize a number using a base where it has a high ratio of 0's, by writing it as a polynomial which can be easily factorized (inspired by [this writeup](https://ctftime.org/writeup/22977)).
  The script checks bases from 2 to 64 (by default) to find a good candidate.

### Elliptic Curve Cryptography

- [`ecc_vulns.py`](ecc_vulns.py): Tries various attacks on elliptic curves to break the discrete logarithm problem. Automatically calculates the curve parameters $a$ and $b$ from the given points if not provided.

  Implemented attacks:

  - [`ecc_mov.py`](libs/attacks/ecc_mov.py): Implements the MOV attack that works on supersingular elliptic curves (whose embedding degree is small), by pairing the curve group with a finite field where the <abbr title="Discrete Logarithm Problem">DLP</abbr> is easier to solve.

  - [`ecc_smart.py`](libs/attacks/ecc_smart.py): Implements Smart's attack that works on anomalous elliptic curves ($\#E(F_p) = p$).

  - [`ecc_pohlig_hellman.py`](libs/attacks/ecc_pohlig_hellman.py): Implements the Pohlig-Hellman algorithm to solve the <abbr title="Elliptic Curve Discrete Logarithm Problem">ECDLP</abbr> on curves of relatively smooth order, by reducing the problem to smaller subgroups. It solves the <abbr title="Discrete Logarithm Problem">DLP</abbr> iteratively for each prime factor of the curve order and stops once their <abbr title="Chinese Remainder Theorem">CRT</abbr> is the right solution, or if all remaining factors are too large (configurable via `--max-bits`).
