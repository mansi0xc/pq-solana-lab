#!/usr/bin/env python3
"""Generate the three research plots from raw benchmark data and transport JSON.

Usage: python3 scripts/plot_results.py <raw_csv> <transport_json> <out_dir>

Plots derive from raw rows (median computed here), so they trace back to the
recorded samples rather than to pre-aggregated summaries.
"""
import csv
import json
import os
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RAW, TRANSPORT, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(OUT, exist_ok=True)


def median(xs):
    xs = sorted(xs)
    n = len(xs)
    if n == 0:
        return 0.0
    if n % 2:
        return xs[n // 2]
    return (xs[n // 2 - 1] + xs[n // 2]) / 2


def load_raw(path):
    groups = defaultdict(list)
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            key = (r["scheme"], r["operation"], r["mode"], r["message_len"], r["input_class"])
            groups[key].append(int(r["elapsed_ns"]))
    return groups


def plot_verification_latency(groups, out):
    schemes = ["ed25519", "ml-dsa-44", "ml-dsa-65", "slh-dsa-sha2-128s"]
    lens = ["32", "166", "1024"]
    labels = {
        "ed25519": "Ed25519",
        "ml-dsa-44": "ML-DSA-44",
        "ml-dsa-65": "ML-DSA-65",
        "slh-dsa-sha2-128s": "SLH-DSA-SHA2-128s",
    }
    values = {}
    for s in schemes:
        vals = []
        for m in lens:
            key = (s, "verify", "prepared", m, "valid")
            vals.append(median(groups.get(key, [])) / 1e3)  # us
        values[s] = vals
    x = range(len(lens))
    width = 0.2
    fig, ax = plt.subplots(figsize=(7, 4))
    for i, s in enumerate(schemes):
        ax.bar([p + i * width for p in x], values[s], width, label=labels[s])
    ax.set_xticks([p + 1.5 * width for p in x])
    ax.set_xticklabels([f"{m} B" for m in lens])
    ax.set_ylabel("median verification latency (µs, log)")
    ax.set_yscale("log")
    ax.set_xlabel("message length")
    ax.set_title("Host ML-DSA/SLH-DSA vs Ed25519 verification (prepared, valid)")
    ax.legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "verification_latency.png"), dpi=150)
    plt.close(fig)


def plot_key_and_signature_sizes(out):
    schemes = ["ed25519", "ml-dsa-44", "ml-dsa-65", "slh-dsa-sha2-128s"]
    labels = ["Ed25519", "ML-DSA-44", "ML-DSA-65", "SLH-DSA-SHA2-128s"]
    pk = [32, 1312, 1952, 32]
    sig = [64, 2420, 3309, 7856]
    x = range(len(schemes))
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar([p - 0.2 for p in x], pk, 0.4, label="public key")
    ax.bar([p + 0.2 for p in x], sig, 0.4, label="signature")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylabel("bytes")
    ax.set_title("Public-key and signature sizes")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(out, "key_signature_bytes.png"), dpi=150)
    plt.close(fig)


def plot_transport_headroom(transport, out):
    rows = json.load(open(transport))
    schemes = ["ed25519", "ml-dsa-44", "ml-dsa-65", "slh-dsa-sha2-128s"]
    labels = ["Ed25519", "ML-DSA-44", "ML-DSA-65", "SLH-DSA-SHA2-128s"]
    formats = ["legacy", "v1"]
    # registered-placement headroom per format
    by_scheme = {}
    for r in rows:
        if r["key_placement"] == "registered":
            by_scheme.setdefault(r["scheme"], {})[r["format"]] = r["headroom"]
    fig, ax = plt.subplots(figsize=(7, 4))
    x = range(len(schemes))
    width = 0.35
    for i, fmt in enumerate(formats):
        vals = [by_scheme[s][fmt] for s in schemes]
        ax.bar([p + i * width for p in x], vals, width, label=f"{fmt} (limit {1232 if fmt=='legacy' else 4096})")
    ax.axhline(0, color="black", linewidth=0.8)
    ax.set_xticks([p + width / 2 for p in x])
    ax.set_xticklabels(labels)
    ax.set_ylabel("headroom (bytes, registered key)")
    ax.set_title("Transaction headroom for direct inclusion (registered key)")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "transport_headroom.png"), dpi=150)
    plt.close(fig)


def main():
    groups = load_raw(RAW)
    plot_verification_latency(groups, OUT)
    plot_key_and_signature_sizes(OUT)
    plot_transport_headroom(TRANSPORT, OUT)
    print("wrote plots to", OUT)


if __name__ == "__main__":
    main()
