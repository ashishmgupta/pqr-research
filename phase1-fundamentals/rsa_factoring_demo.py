"""
RSA Factoring Difficulty Demo
==============================
Demonstrates why RSA security depends on the computational difficulty of
factoring large numbers — and why this is vulnerable to quantum computers.

This script generates RSA-like moduli (n = p × q) of increasing size,
then times how long sympy takes to factor them back. The exponential growth
in time illustrates exactly why a 600-digit RSA key is "safe" classically
but falls to Shor's Algorithm on a quantum computer.

Usage:
    pip install sympy matplotlib
    python rsa_factoring_demo.py

Output:
    - Console table with factoring times
    - factoring_results.csv for use by factoring_chart.py
"""

import csv
import time
import random
from sympy import nextprime, factorint

# Number of decimal digits to test for each RSA modulus n = p × q
# We generate p and q each of roughly half this digit count
# so their product n has approximately this many digits
DIGIT_SIZES = [4, 6, 8, 10, 12, 14, 16, 18, 20, 25, 30]

# How many times to repeat each test for a stable average
TRIALS = 3

# Output CSV file (read by factoring_chart.py)
OUTPUT_CSV = "factoring_results.csv"


def generate_rsa_modulus(target_digits: int) -> tuple[int, int, int]:
    """
    Generate a pair of primes p, q such that n = p × q has approximately
    target_digits decimal digits.

    In real RSA, p and q are each roughly half the key size in bits.
    Here we work in decimal digits for intuitive understanding.

    Args:
        target_digits: Desired digit count for the product n.

    Returns:
        Tuple of (p, q, n) where n = p × q.
    """
    # Each prime should be roughly half the target digit count
    half_digits = target_digits // 2
    lower_bound = 10 ** (half_digits - 1)  # smallest number with half_digits digits
    upper_bound = 10 ** half_digits - 1    # largest number with half_digits digits

    # Pick a random starting point and find the next prime
    # This mimics how real RSA key generation works (random large primes)
    seed = random.randint(lower_bound, upper_bound)
    p = nextprime(seed)
    q = nextprime(p + random.randint(1, lower_bound))  # ensure p ≠ q

    n = p * q
    return p, q, n


def time_factoring(n: int, trials: int = TRIALS) -> tuple[float, dict]:
    """
    Time how long sympy takes to factor n, averaged over multiple trials.

    sympy.factorint() uses trial division, Pollard's rho, and other
    classical algorithms — the same class of methods as state-of-the-art
    classical computers. It does NOT use quantum methods.

    Args:
        n: The number to factor.
        trials: Number of timing trials to average.

    Returns:
        Tuple of (average_seconds, factor_dict).
    """
    elapsed_times = []
    factors = {}

    for _ in range(trials):
        start = time.perf_counter()
        factors = factorint(n)  # returns {prime: exponent, ...}
        end = time.perf_counter()
        elapsed_times.append(end - start)

    avg_time = sum(elapsed_times) / len(elapsed_times)
    return avg_time, factors


def format_time(seconds: float) -> str:
    """
    Format a duration in seconds into a human-readable string.

    Args:
        seconds: Duration in seconds.

    Returns:
        String like "1.23 ms", "4.56 s", "7.89 min", etc.
    """
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.2f} μs"
    elif seconds < 1.0:
        return f"{seconds * 1_000:.2f} ms"
    elif seconds < 60:
        return f"{seconds:.3f} s"
    elif seconds < 3600:
        return f"{seconds / 60:.2f} min"
    else:
        return f"{seconds / 3600:.2f} hr"


def main():
    """
    Run the RSA factoring difficulty demonstration.

    For each digit size, generates an RSA-like modulus, factors it, and
    records the time. Prints a formatted table and saves results to CSV.
    """
    print("=" * 72)
    print("RSA FACTORING DIFFICULTY DEMO")
    print("Simulates the computational work needed to break RSA encryption")
    print("=" * 72)
    print()
    print(f"{'Digits':>8} | {'n (truncated)':>22} | {'Factors':>24} | {'Avg Time':>12}")
    print("-" * 72)

    results = []

    for digits in DIGIT_SIZES:
        p, q, n = generate_rsa_modulus(digits)
        actual_digits = len(str(n))

        # Skip if sympy would take too long (configurable cutoff)
        # For this demo, we stop at 30 digits to keep runtime reasonable.
        # Real RSA = 600-1200 digits — factoring would take millions of years.
        avg_time, factors = time_factoring(n, trials=TRIALS)

        # Display the number truncated if very long
        n_str = str(n)
        n_display = n_str[:10] + "…" if len(n_str) > 10 else n_str

        # Show factor summary (p × q format)
        factor_keys = list(factors.keys())
        if len(factor_keys) == 2:
            factor_display = f"{factor_keys[0]} × {factor_keys[1]}"
        else:
            factor_display = str(factors)
        factor_display = factor_display[:24]  # truncate for table width

        print(f"{actual_digits:>8} | {n_display:>22} | {factor_display:>24} | {format_time(avg_time):>12}")

        results.append({
            "target_digits": digits,
            "actual_digits": actual_digits,
            "n": n,
            "p": p,
            "q": q,
            "avg_seconds": avg_time,
        })

    # Save results to CSV for charting
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["target_digits", "actual_digits", "n", "p", "q", "avg_seconds"])
        writer.writeheader()
        writer.writerows(results)

    print("-" * 72)
    print()
    print(f"Results saved to: {OUTPUT_CSV}")
    print()
    print("KEY INSIGHT:")
    print("  Notice how factoring time grows exponentially with digit count.")
    print("  A real RSA-2048 key has ~617 decimal digits.")
    print("  Classical computers: millions of years to factor.")
    print("  Quantum computer (Shor's Algorithm): hours to days.")
    print()
    print("Run factoring_chart.py to visualize the exponential growth curve.")


if __name__ == "__main__":
    random.seed(42)  # reproducible results for learning/demo purposes
    main()
