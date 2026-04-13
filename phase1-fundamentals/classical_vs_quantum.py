"""
Classical vs. Quantum Factoring — Side-by-Side Comparison
==========================================================
Takes a number n, factors it both classically (sympy) and via Shor's
algorithm simulation, then prints a side-by-side comparison table showing:
  - Actual measured time for each method
  - Theoretical quantum speedup (exponential → polynomial)
  - Why the quantum advantage grows with key size

This script is educational — it does NOT run a real quantum circuit.
The Shor simulation is classical and thus slower than the sympy factoring
for small numbers. The key lesson is the *algorithmic complexity* difference,
which only becomes decisive at large key sizes (600+ digits).

Usage:
    pip install sympy
    python classical_vs_quantum.py                     # uses built-in test cases
    python classical_vs_quantum.py 15 21 35 77 91     # custom numbers

Source for complexity analysis:
    Shor, P.W. (1994). Algorithms for quantum computation.
    Classical GFS complexity: Lenstra et al., 1993 (general number field sieve).
"""

import math
import random
import sys
import time
from sympy import factorint


# --- Classical Shor's simulation (from shors_algorithm.py) -----------------

def find_period(a: int, n: int) -> int | None:
    """
    Find smallest r > 0 where a^r ≡ 1 (mod n).

    Classical: O(n) — the bottleneck Shor's replaces with quantum QFT.
    """
    value = a % n
    for r in range(1, n):
        if value == 1:
            return r
        value = (value * a) % n
    return None


def extract_factors(a: int, r: int, n: int) -> tuple[int, int] | None:
    """Use period r to extract factors p, q via gcd."""
    if r % 2 != 0:
        return None
    x = pow(a, r // 2, n)
    if x == n - 1:
        return None
    p, q = math.gcd(x - 1, n), math.gcd(x + 1, n)
    if p in (1, n) or q in (1, n):
        return None
    return p, q


def shors_simulation(n: int, max_attempts: int = 50) -> tuple[int, int] | None:
    """
    Classical simulation of Shor's Algorithm.

    Returns (p, q) factors of n, or None if all attempts fail.
    """
    if n < 4:
        return None
    if n % 2 == 0:
        return 2, n // 2

    for _ in range(max_attempts):
        a = random.randint(2, n - 1)
        g = math.gcd(a, n)
        if g != 1:
            return g, n // g
        r = find_period(a, n)
        if r is None:
            continue
        result = extract_factors(a, r, n)
        if result and result[0] * result[1] == n:
            return result
    return None


# --- Complexity analysis ----------------------------------------------------

def classical_complexity(n: int) -> str:
    """
    Estimate the complexity of the General Number Field Sieve (GNFS)
    for factoring n.

    GNFS (best classical algorithm) runs in:
        L(n) = exp( (64/9)^(1/3) · (ln n)^(1/3) · (ln ln n)^(2/3) )

    This is sub-exponential but super-polynomial — grows very fast.

    Args:
        n: The number to factor.

    Returns:
        String description of the complexity class and approximate ops.
    """
    # ln n
    ln_n = math.log(n)
    if ln_n <= 0:
        return "trivial"

    ln_ln_n = math.log(ln_n) if ln_n > 1 else 0

    # GNFS exponent: (64/9)^(1/3) ≈ 1.923
    coeff = (64 / 9) ** (1 / 3)

    # Exponent = coeff × (ln n)^(1/3) × (ln ln n)^(2/3)
    exponent = coeff * (ln_n ** (1 / 3)) * (ln_ln_n ** (2 / 3)) if ln_ln_n > 0 else coeff * (ln_n ** (1 / 3))

    # Approximate number of operations
    if exponent < 40:
        ops = f"~e^{exponent:.1f} ≈ 10^{exponent * math.log10(math.e):.0f} ops"
    else:
        ops = f"~10^{exponent * math.log10(math.e):.0f} operations"

    return f"L[1/3, (64/9)^(1/3)] = {ops}"


def quantum_complexity(n: int) -> str:
    """
    Estimate Shor's Algorithm complexity for factoring n.

    Shor's runs in O(log² n · log log n · log log log n) — essentially
    polynomial in the number of bits. For cryptographic purposes, this
    is treated as O(log³ n).

    Args:
        n: The number to factor.

    Returns:
        String description of the complexity class and approximate ops.
    """
    bits = math.floor(math.log2(n)) + 1
    # Approximate as O(log³ n) gate operations
    gate_ops = bits ** 3
    return f"O(log³ n) ≈ {gate_ops:,} quantum gate ops (n = {bits} bits)"


def speedup_ratio(n: int) -> str:
    """
    Calculate and describe the exponential speedup Shor's gives over GNFS.

    Args:
        n: The number to factor.

    Returns:
        Human-readable speedup description.
    """
    ln_n = math.log(n)
    bits = math.floor(math.log2(n)) + 1

    # GNFS: sub-exponential in bits — scales as exp((bits)^(1/3))
    # Shor's: polynomial — scales as (bits)^3
    # Ratio grows super-exponentially with key size

    # Rough: how many times faster is Shor's?
    ln_ln_n = math.log(ln_n) if ln_n > 1 else 1
    gnfs_exp = (64 / 9) ** (1 / 3) * (ln_n ** (1 / 3)) * (ln_ln_n ** (2 / 3))
    shors_log = 3 * math.log(bits)  # log of the polynomial cost

    speedup_exponent = gnfs_exp - shors_log  # both in log space
    return f"Quantum is e^{speedup_exponent:.1f} ≈ 10^{speedup_exponent * math.log10(math.e):.0f}× faster"


# --- Main comparison logic --------------------------------------------------

def compare(n: int):
    """
    Factor n using both methods, time each, and print comparison.

    Args:
        n: The number to factor.
    """
    digits = len(str(n))
    bits = math.floor(math.log2(n)) + 1

    print(f"\n{'─' * 68}")
    print(f"  Factoring n = {n}   ({digits} digits, {bits} bits)")
    print(f"{'─' * 68}")

    # --- Classical factoring (sympy) ---
    start = time.perf_counter()
    classical_factors = factorint(n)
    classical_time = time.perf_counter() - start

    # Format factors as p × q
    factor_list = []
    for prime, exp in classical_factors.items():
        factor_list.extend([prime] * exp)
    factors_str = " × ".join(str(f) for f in sorted(factor_list))

    # --- Shor's simulation ---
    start = time.perf_counter()
    shor_result = shors_simulation(n)
    shor_time = time.perf_counter() - start

    shor_str = f"{shor_result[0]} × {shor_result[1]}" if shor_result else "FAILED"
    shor_verified = "YES" if shor_result and shor_result[0] * shor_result[1] == n else "NO"

    print(f"\n  {'METHOD':<28} {'RESULT':<22} {'TIME':>10}")
    print(f"  {'─'*28} {'─'*22} {'─'*10}")
    print(f"  {'Classical (sympy/GNFS)':<28} {factors_str:<22} {classical_time*1000:>8.3f} ms")
    print(f"  {'Shor Simulation (classical)':<28} {shor_str:<22} {shor_time*1000:>8.3f} ms")
    print(f"  {'Shor result verified:':<28} {shor_verified}")

    print(f"\n  COMPLEXITY ANALYSIS:")
    print(f"  Classical GNFS:    {classical_complexity(n)}")
    print(f"  Shor's Algorithm:  {quantum_complexity(n)}")
    print(f"  Quantum speedup:   {speedup_ratio(n)}")
    print()
    print(f"  NOTE: The simulation is CLASSICAL — find_period() runs on your CPU.")
    print(f"        A real quantum computer replaces find_period() with QFT,")
    print(f"        turning O(n) loop into O(log² n) quantum circuit evaluation.")


def print_rsa_context():
    """Print context about real RSA key sizes and the quantum timeline."""
    print()
    print("=" * 68)
    print("REAL-WORLD RSA KEY SIZES — THE QUANTUM THREAT IN PERSPECTIVE")
    print("=" * 68)
    print()

    rsa_sizes = [
        (1024, 308,  "Deprecated — do not use"),
        (2048, 617,  "Current minimum standard"),
        (4096, 1234, "High-security standard"),
    ]

    print(f"  {'Key Size':>12} {'Digits':>8}  {'Classical Time':>20}  Notes")
    print(f"  {'─'*12} {'─'*8}  {'─'*20}  {'─'*20}")
    for bits, digits, note in rsa_sizes:
        # Very rough estimate: factoring RSA-k takes ~e^(1.92 × k^(1/3)) ops
        # and modern hardware does ~10^15 ops/sec
        ln_n_approx = bits * math.log(2)
        ln_ln_n_approx = math.log(ln_n_approx)
        ops_exp = (64/9)**(1/3) * (ln_n_approx**(1/3)) * (ln_ln_n_approx**(2/3))
        # GNFS record (RSA-250) took ~2700 core-years → calibrate
        # We just show the qualitative picture
        print(f"  {f'RSA-{bits}':>12} {digits:>8}  {'millions of years':>20}  {note}")

    print()
    print("  Quantum computer (Shor's, cryptographically relevant scale):")
    print("  RSA-2048: hours to days (requires ~4,000 logical qubits)")
    print("  RSA-4096: ~4× longer (still tractable)")
    print()
    print("  CURRENT QUANTUM HARDWARE (2025):")
    print("  Largest number factored by Shor's: ~21 (on real hardware)")
    print("  RSA-2048 requires: millions of physical qubits with error correction")
    print("  Estimated timeline: 15-20+ years for cryptographically relevant attack")
    print()
    print("  BUT: Harvest Now, Decrypt Later (HNDL) attacks start TODAY.")
    print("  Data with 10-20 year sensitivity needs post-quantum protection NOW.")
    print()
    print("  SOLUTION: ML-KEM (FIPS 203) replaces RSA/ECDH in TLS key exchange.")
    print("  AES-256 (data encryption) is NOT affected — only key exchange changes.")


def main():
    """
    Run classical vs. quantum comparison for a set of numbers.
    Numbers can be passed as command-line arguments, or defaults are used.
    """
    # Use CLI args if provided, otherwise use defaults
    if len(sys.argv) > 1:
        try:
            test_numbers = [int(arg) for arg in sys.argv[1:]]
        except ValueError:
            print("ERROR: All arguments must be integers.")
            sys.exit(1)
    else:
        test_numbers = [15, 21, 35, 77, 91]

    print("=" * 68)
    print("CLASSICAL vs. QUANTUM FACTORING — Side-by-Side Comparison")
    print("=" * 68)
    print()
    print("Classical method: sympy.factorint() — uses trial division + Pollard's rho")
    print("Quantum method:   Shor's Algorithm simulation (classical CPU, not quantum)")
    print()
    print("Both factor the same numbers. The difference is ALGORITHMIC COMPLEXITY.")
    print("For small numbers, classical is faster. At RSA scale, quantum wins.")

    for n in test_numbers:
        compare(n)

    print_rsa_context()


if __name__ == "__main__":
    random.seed(42)
    main()
