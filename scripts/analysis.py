"""Shared helpers for the result-analysis scripts.

All statistics are recomputed from the raw sample CSV. The quantile method is
the project rule: linear interpolation between order statistics at position
``q * (n - 1)``, rounded half away from zero — the same method the Rust harness
uses in ``src/bench.rs`` (``quantile``).

Nothing here invents numbers: a missing sample group is an error, never a
silent zero.
"""
import csv
import math
from collections import defaultdict

SCHEMES = ["ed25519", "ml-dsa-44", "ml-dsa-65", "slh-dsa-sha2-128s"]
LENGTHS = ["32", "166", "1024"]
LABELS = {
    "ed25519": "Ed25519",
    "ml-dsa-44": "ML-DSA-44",
    "ml-dsa-65": "ML-DSA-65",
    "slh-dsa-sha2-128s": "SLH-DSA-SHA2-128s",
}


def load_raw(path):
    """Return {(scheme, op, mode, len, class): [elapsed_ns, ...]}."""
    groups = defaultdict(list)
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            key = (
                row["scheme"],
                row["operation"],
                row["mode"],
                row["message_len"],
                row["input_class"],
            )
            groups[key].append(int(row["elapsed_ns"]))
    if not groups:
        raise ValueError("no raw samples in %s" % path)
    return groups


def load_summaries(path):
    """Return {(scheme, op, mode, len, class): row dict}."""
    rows = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            key = (
                row["scheme"],
                row["operation"],
                row["mode"],
                row["message_len"],
                row["input_class"],
            )
            rows[key] = row
    if not rows:
        raise ValueError("no summary rows in %s" % path)
    return rows


def quantile(sorted_xs, q):
    n = len(sorted_xs)
    if n == 0:
        raise ValueError("quantile of an empty sample set")
    if n == 1:
        return float(sorted_xs[0])
    pos = q * (n - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    frac = pos - lo
    return sorted_xs[lo] * (1.0 - frac) + sorted_xs[hi] * frac


def round_half_away(x):
    return int(math.floor(x + 0.5))


def stats(samples):
    xs = sorted(samples)
    return {
        "n": len(xs),
        "median": round_half_away(quantile(xs, 0.5)),
        "q1": round_half_away(quantile(xs, 0.25)),
        "q3": round_half_away(quantile(xs, 0.75)),
        "p95": round_half_away(quantile(xs, 0.95)),
    }


def fmt_ns(ns):
    if ns >= 1_000_000_000:
        return "%.2f s" % (ns / 1e9)
    if ns >= 1_000_000:
        return "%.1f ms" % (ns / 1e6)
    if ns >= 1_000:
        return "%.1f µs" % (ns / 1e3)
    return "%d ns" % ns
