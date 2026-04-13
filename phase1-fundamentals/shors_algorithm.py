"""
Shor's Algorithm — Classical Educational Simulation
=====================================================
A classical Python simulation of Shor's Algorithm for factoring integers.

IMPORTANT FRAMING:
This is a *classical simulation* — we are running Shor's steps on a normal
CPU. The key educational goal is to see *why* the period-finding step is
the bottleneck classically, and why quantum computers solve it exponentially
faster using superposition + Quantum Fourier Transform (QFT).

A real quantum computer would replace find_period() with a quantum circuit
that evaluates ALL values of r simultaneously via superposition, then uses
QFT to extract the period in O(log n) time instead of O(n) time.

Algorithm overview (Shor, 1994):
  1. Choose random a where 1 < a < n and gcd(a, n) = 1
  2. Find the period r: smallest r > 0 where a^r ≡ 1 (mod n)
  3. If r is even and a^(r/2) ≢ -1 (mod n):
     → factors are gcd(a^(r/2) ± 1, n)

Source: Adapted from University of Illinois Physics 498CMP course materials.
See also: Shor, P.W. (1994). Algorithms for quantum computation.
          Proceedings 35th Annual Symposium on Foundations of Computer Science.

Usage:
    python shors_algorithm.py

Test cases: 15, 21, 35, 77, 91 (small enough for classical period-finding)
"""

import math
import random
import time


def find_period(a: int, n: int) -> int | None:
    """
    Find the period r of the function f(x) = a^x mod n.

    The period r is the smallest positive integer where:
        a^r ≡ 1 (mod n)

    This is the classically SLOW step. On a classical computer we loop
    through candidate values of r one at a time — O(n) in the worst case.

    On a quantum computer, ALL values of r are evaluated simultaneously via
    superposition, and the QFT extracts the period in O(log² n) time.
    That exponential speedup is what breaks RSA.

    Args:
        a: The random base chosen in Shor's algorithm.
        n: The number being factored.

    Returns:
        The period r, or None if not found within n iterations.
    """
    # Start with r=1 and compute a^r mod n iteratively
    # We use modular exponentiation: multiply by a and reduce mod n each step
    # This avoids computing huge intermediate numbers
    value = a % n  # a^1 mod n
    for r in range(1, n):
        if value == 1:
            # Found it: a^r ≡ 1 (mod n)
            return r
        value = (value * a) % n  # a^(r+1) mod n = (a^r mod n) × a mod n

    return None  # should not happen for valid inputs, but be safe


def extract_factors(a: int, r: int, n: int) -> tuple[int, int] | None:
    """
    Use the period r to extract prime factors of n.

    Mathematical basis:
        If a^r ≡ 1 (mod n), then (a^(r/2) - 1)(a^(r/2) + 1) ≡ 0 (mod n)
        This means n divides their product, so gcd(a^(r/2) ± 1, n) likely
        gives us the non-trivial factors p and q.

    This step fails (returns None) when:
        - r is odd (can't halve it for integer math)
        - a^(r/2) ≡ -1 (mod n) — makes gcd trivial

    Args:
        a: The base used in period finding.
        r: The period found by find_period().
        n: The number being factored.

    Returns:
        Tuple (p, q) where p × q = n, or None if this (a, r) combo fails.
    """
    # Shor's algorithm only works when r is even
    if r % 2 != 0:
        return None

    half_r = r // 2
    x = pow(a, half_r, n)  # a^(r/2) mod n — efficient modular exponentiation

    # Degenerate case: a^(r/2) ≡ -1 (mod n) means gcd(x+1, n) = n (trivial)
    if x == n - 1:
        return None

    # The two candidate factors
    p = math.gcd(x - 1, n)
    q = math.gcd(x + 1, n)

    # Verify we got non-trivial factors (not 1 or n itself)
    if p in (1, n) or q in (1, n):
        return None

    return p, q


def shors_algorithm(n: int, max_attempts: int = 50) -> tuple[int, int] | None:
    """
    Orchestrate Shor's Algorithm to factor n.

    Tries multiple random bases a until period-finding and factor extraction
    both succeed. In practice, each attempt succeeds with ~50% probability,
    so ~2-3 attempts are typically needed.

    Args:
        n: The composite number to factor (must not be prime or a prime power).
        max_attempts: Maximum number of random base attempts.

    Returns:
        Tuple (p, q) where p × q = n, or None if all attempts fail.
    """
    # Quick sanity checks before the expensive period-finding step
    if n < 4:
        return None
    if n % 2 == 0:
        return 2, n // 2  # trivially even

    for attempt in range(1, max_attempts + 1):
        # Step 1: Pick a random base a coprime to n
        # If gcd(a, n) > 1, we accidentally found a factor already (lucky!)
        a = random.randint(2, n - 1)
        g = math.gcd(a, n)
        if g != 1:
            # gcd gave us a factor directly — no quantum needed
            return g, n // g

        # Step 2: Find the period r (classically slow; quantumly fast)
        r = find_period(a, n)
        if r is None:
            continue  # period not found, try another base

        # Step 3: Extract factors from the period
        result = extract_factors(a, r, n)
        if result is not None:
            p, q = result
            if p * q == n:  # verify the factorization is correct
                return p, q

        # Attempt failed — pick a new random base and retry
        # On a real quantum computer, each attempt is nearly instant

    return None  # all attempts failed


def run_demo():
    """
    Run the Shor's Algorithm demo on a set of test numbers.

    Prints: the number, the factors found, time taken, and explanation
    of where the quantum speedup would apply.
    """
    # Small composites that are tractable for classical period-finding
    test_numbers = [15, 21, 35, 77, 91]

    print("=" * 72)
    print("SHOR'S ALGORITHM — Classical Educational Simulation")
    print("=" * 72)
    print()
    print("This simulation runs Shor's steps on a classical CPU.")
    print("The BOTTLENECK (find_period) would be quantum-accelerated in real use.")
    print()
    print(f"{'n':>6} | {'Factors':>12} | {'Time':>10} | {'Verified':>8}")
    print("-" * 48)

    for n in test_numbers:
        start = time.perf_counter()
        result = shors_algorithm(n)
        elapsed = time.perf_counter() - start

        if result:
            p, q = result
            verified = "YES" if p * q == n else "NO"
            print(f"{n:>6} | {p:>5} × {q:<5} | {elapsed*1000:>8.3f} ms | {verified:>8}")
        else:
            print(f"{n:>6} | {'FAILED':>12} | {elapsed*1000:>8.3f} ms | {'N/A':>8}")

    print()
    print("=" * 72)
    print("THE QUANTUM ADVANTAGE — Why find_period() Is The Key")
    print("=" * 72)
    print()
    print("Classical find_period(a, n):  loops r = 1, 2, 3 … until a^r mod n = 1")
    print("  → Worst case: O(n) iterations")
    print("  → For n = RSA-2048: ~2^2048 operations = heat death of universe")
    print()
    print("Quantum find_period(a, n):    creates superposition of ALL r values")
    print("  → Quantum circuit evaluates f(r) = a^r mod n for ALL r simultaneously")
    print("  → Quantum Fourier Transform (QFT) extracts period from interference pattern")
    print("  → Time complexity: O(log² n) — polynomial, not exponential")
    print()
    print("The same algorithm, but find_period() runs in seconds instead of")
    print("millions of years. That is Shor's Algorithm.")
    print()
    print("CURRENT HARDWARE REALITY:")
    print("  Largest number factored via Shor's on real quantum hardware: ~21")
    print("  RSA-2048 requires: ~4096 logical qubits (millions of physical qubits)")
    print("  Estimated timeline: 15-20+ years for cryptographically relevant attack")
    print()
    print("THREAT TODAY — Harvest Now, Decrypt Later (HNDL):")
    print("  Adversaries capture TLS traffic TODAY.")
    print("  When quantum computers arrive, they decrypt the archived ciphertext.")
    print("  Data with 10-20 year sensitivity needs post-quantum protection NOW.")


if __name__ == "__main__":
    random.seed(42)  # reproducible results for learning/demo purposes
    run_demo()
