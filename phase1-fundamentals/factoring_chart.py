"""
RSA Factoring Time — Visualization
====================================
Reads the CSV output from rsa_factoring_demo.py and generates a matplotlib
chart showing how factoring time grows exponentially with digit count.

This visualization makes the RSA quantum vulnerability concrete:
the curve that looks "safe" for 30-digit numbers extrapolates to
millions of years at 600 digits (classically), but Shor's Algorithm
collapses that to hours on a quantum computer.

Usage:
    python rsa_factoring_demo.py   # generates factoring_results.csv first
    python factoring_chart.py      # reads CSV, produces chart

Output:
    factoring_chart.png — saved in the current directory
"""

import csv
import math
import sys
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    import numpy as np
except ImportError:
    print("ERROR: matplotlib and numpy are required.")
    print("Install with:  pip install matplotlib numpy")
    sys.exit(1)

INPUT_CSV = "factoring_results.csv"
OUTPUT_PNG = "factoring_chart.png"


def load_results(csv_path: str) -> tuple[list[int], list[float]]:
    """
    Load digit counts and factoring times from the CSV produced by
    rsa_factoring_demo.py.

    Args:
        csv_path: Path to the CSV file.

    Returns:
        Tuple of (list of digit counts, list of times in seconds).

    Raises:
        FileNotFoundError: If the CSV doesn't exist yet.
    """
    if not Path(csv_path).exists():
        raise FileNotFoundError(
            f"'{csv_path}' not found.\n"
            "Run rsa_factoring_demo.py first to generate the data."
        )

    digits = []
    times = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            digits.append(int(row["actual_digits"]))
            times.append(float(row["avg_seconds"]))

    return digits, times


def fit_exponential(x: list[int], y: list[float]) -> tuple[float, float]:
    """
    Fit an exponential curve y = e^(a*x + b) to the data using log-linear
    regression. This confirms the exponential growth we expect from the
    theory of factoring complexity.

    Args:
        x: X values (digit counts).
        y: Y values (factoring times in seconds).

    Returns:
        Tuple (a, b) — coefficients for ln(y) = a*x + b.
    """
    # Replace any zero times with a tiny value to avoid log(0)
    y_safe = [max(t, 1e-9) for t in y]
    log_y = [math.log(t) for t in y_safe]

    # Simple linear regression on (x, log(y)) — i.e. exponential fit
    n = len(x)
    mean_x = sum(x) / n
    mean_log_y = sum(log_y) / n
    cov_xy = sum((x[i] - mean_x) * (log_y[i] - mean_log_y) for i in range(n))
    var_x = sum((xi - mean_x) ** 2 for xi in x)
    a = cov_xy / var_x
    b = mean_log_y - a * mean_x
    return a, b


def build_chart(digits: list[int], times: list[float]):
    """
    Generate and save the factoring time chart.

    Chart design:
      - Measured data points: blue dots
      - Exponential fit curve: dashed blue line (extrapolated)
      - Real RSA-2048 annotation: vertical red line at 617 digits
      - Quantum speedup annotation: horizontal arrow showing collapse
      - Log scale on y-axis so the exponential appears as a straight line

    Args:
        digits: X values — digit counts of the RSA modulus n.
        times: Y values — factoring times in seconds.
    """
    fig, ax = plt.subplots(figsize=(12, 7))

    # --- Measured data ---
    ax.scatter(digits, times, color="#2563EB", s=80, zorder=5, label="Measured (sympy)")

    # --- Exponential fit extrapolated to 40 digits ---
    a, b = fit_exponential(digits, times)
    x_fit = list(range(min(digits), 42))
    y_fit = [math.exp(a * xi + b) for xi in x_fit]
    ax.plot(x_fit, y_fit, "--", color="#2563EB", linewidth=1.5,
            label=f"Exponential fit (e^{a:.3f}·digits)")

    # --- Y axis: log scale so exponential appears as a line ---
    ax.set_yscale("log")

    # Add reference horizontal lines for human-intuitive time anchors
    time_references = {
        1e-3: ("1 ms", "#94A3B8"),
        1.0: ("1 second", "#94A3B8"),
        60.0: ("1 minute", "#94A3B8"),
        3600.0: ("1 hour", "#94A3B8"),
        86400.0: ("1 day", "#F59E0B"),
        3.156e7: ("1 year", "#EF4444"),
        3.156e13: ("1 million years", "#7C3AED"),
    }
    for y_val, (label, color) in time_references.items():
        ax.axhline(y=y_val, color=color, linewidth=0.8, linestyle=":", alpha=0.7)
        ax.text(max(digits) + 0.5, y_val, label, va="center",
                fontsize=8, color=color, alpha=0.9)

    # --- RSA-2048 annotation ---
    # RSA-2048 has a 617-digit decimal modulus
    # We draw this even though it's far off the x-axis, to anchor intuition
    ax.axvline(x=617, color="#EF4444", linewidth=1.5, linestyle="--", alpha=0.6)
    ax.text(617, ax.get_ylim()[0] if ax.get_ylim()[0] > 0 else 1e-9,
            "  RSA-2048\n  (617 digits)", fontsize=8, color="#EF4444",
            va="bottom", ha="left")

    # --- Annotation box explaining the quantum threat ---
    annotation_text = (
        "Real RSA keys = 617–1233 digits\n"
        "Classical: millions of years to factor\n"
        "Quantum (Shor's): hours to days\n"
        "\nHarvest Now, Decrypt Later:\n"
        "Adversaries capture TLS traffic today,\n"
        "decrypt when quantum computers arrive."
    )
    ax.annotate(
        annotation_text,
        xy=(0.97, 0.97),
        xycoords="axes fraction",
        ha="right", va="top",
        fontsize=8.5,
        bbox=dict(boxstyle="round,pad=0.5", facecolor="#FEF3C7", edgecolor="#F59E0B", alpha=0.9),
    )

    # --- Labels and formatting ---
    ax.set_xlabel("Number of Decimal Digits in RSA Modulus (n = p × q)", fontsize=11)
    ax.set_ylabel("Time to Factor (seconds, log scale)", fontsize=11)
    ax.set_title(
        "RSA Factoring Difficulty: Exponential Growth vs. Digit Count\n"
        "Classical computers — this is what Shor's Algorithm eliminates",
        fontsize=13, fontweight="bold"
    )
    ax.legend(loc="upper left", fontsize=9)
    ax.grid(True, which="both", alpha=0.3)

    # Format x-axis as integers
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    plt.tight_layout()
    plt.savefig(OUTPUT_PNG, dpi=150, bbox_inches="tight")
    print(f"Chart saved to: {OUTPUT_PNG}")
    plt.show()


def main():
    """
    Load factoring results and render the chart.
    """
    print("Loading factoring results from:", INPUT_CSV)
    try:
        digits, times = load_results(INPUT_CSV)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print(f"Loaded {len(digits)} data points. Building chart...")
    build_chart(digits, times)

    print()
    print("KEY INSIGHT:")
    print("  The log-scale y-axis makes the exponential curve appear as a straight line.")
    print("  Each additional digit multiplies the factoring time by a constant factor.")
    print("  That's what 'exponential difficulty' means — and what Shor's Algorithm breaks.")


if __name__ == "__main__":
    main()
