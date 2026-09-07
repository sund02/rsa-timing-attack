#!/usr/bin/env python3
"""Plot the bench CSVs. Usage:
      python3 scripts/plot.py hamming.csv
      python3 scripts/plot.py reduction.csv
Requires matplotlib (pip install matplotlib). Saves a PNG next to the CSV.
"""
import csv, sys, os

def load(path):
    with open(path) as f:
        r = csv.DictReader(f)
        rows = list(r)
        return r.fieldnames, rows

def main():
    if len(sys.argv) < 2:
        print("usage: plot.py <hamming.csv|reduction.csv>"); return
    path = sys.argv[1]
    cols, rows = load(path)
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(7, 4.3))

    if "popcount" in cols:  # hamming experiment
        x  = [int(r["popcount"])    for r in rows]
        yn = [float(r["naive_us"])  for r in rows]
        yl = [float(r["ladder_us"]) for r in rows]
        ax.plot(x, yn, "o-", label="naive square-and-multiply (vulnerable)")
        ax.plot(x, yl, "s-", label="Montgomery ladder (hardened)")
        ax.set_xlabel("Hamming weight of private exponent d")
        ax.set_ylabel("decryption time (microseconds)")
        ax.set_title("RSA decryption time leaks the secret exponent's Hamming weight")
        ax.legend()
    else:                   # reduction experiment
        x = [int(r["extra_reductions"]) for r in rows]
        y = [float(r["mont_us"])        for r in rows]
        ax.scatter(x, y, alpha=0.7)
        ax.set_xlabel("Montgomery extra reductions (input-dependent)")
        ax.set_ylabel("decryption time (microseconds)")
        ax.set_title("Time tracks input-dependent extra reductions (Brumley-Boneh signal)")

    ax.grid(True, alpha=0.3)
    out = os.path.splitext(path)[0] + ".png"
    fig.tight_layout(); fig.savefig(out, dpi=130)
    print("wrote", out)

if __name__ == "__main__":
    main()
