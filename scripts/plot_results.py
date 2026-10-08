#!/usr/bin/env python3
"""Generate the research plots from committed result artifacts.

Usage: python3 scripts/plot_results.py <raw_csv> <summary_csv> <transport_json> <out_dir>

* Latency is recomputed from the raw sample CSV (medians), so it traces back to
  the recorded samples, not to a pre-aggregated summary.
* Key/signature sizes are read from the summary metadata for the same run, not
  from hard-coded arrays.
* A missing scheme/length/class group is an explicit error. Absent data is
  never plotted as a silent zero.
* Transport headroom is computed from the serialized transport JSON for the
  operational, registered-key rows.
"""
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analysis import LABELS, LENGTHS, SCHEMES, load_raw, load_summaries, stats  # noqa: E402

if len(sys.argv) != 5:
    sys.stderr.write(__doc__)
    sys.exit(2)
RAW, SUMMARY, TRANSPORT, OUT = sys.argv[1:5]
os.makedirs(OUT, exist_ok=True)


def median_of(groups, scheme, op, mode, length, cls):
    key = (scheme, op, mode, length, cls)
    if key not in groups:
        raise SystemExit(
            "missing raw samples for %s — refusing to plot a silent zero" % (key,)
        )
    return stats(groups[key])["median"]


def sizes_from_summaries(summaries):
    sizes = {}
    for scheme in SCHEMES:
        row = summaries.get((scheme, "keygen", "n/a", "0", "n/a"))
        if row is None:
            raise SystemExit("missing summary row for scheme %s" % scheme)
        sizes[scheme] = (int(row["public_key_bytes"]), int(row["signature_bytes"]))
    return sizes


def plot_verification_latency(groups, out):
    values = {}
    for scheme in SCHEMES:
        values[scheme] = [
            median_of(groups, scheme, "verify", "prepared", m, "valid") / 1e3
            for m in LENGTHS
        ]
    x = range(len(LENGTHS))
    width = 0.2
    fig, ax = plt.subplots(figsize=(7, 4))
    for i, scheme in enumerate(SCHEMES):
        ax.bar([p + i * width for p in x], values[scheme], width, label=LABELS[scheme])
    ax.set_xticks([p + 1.5 * width for p in x])
    ax.set_xticklabels(["%s B" % m for m in LENGTHS])
    ax.set_ylabel("median verification latency (µs, log)")
    ax.set_yscale("log")
    ax.set_xlabel("message length")
    ax.set_title("Host verification, prepared/valid (source: raw run `full`)")
    ax.legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "verification_latency.png"), dpi=150)
    plt.close(fig)


def plot_key_and_signature_sizes(sizes, out):
    pk = [sizes[s][0] for s in SCHEMES]
    sig = [sizes[s][1] for s in SCHEMES]
    x = range(len(SCHEMES))
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar([p - 0.2 for p in x], pk, 0.4, label="public key")
    ax.bar([p + 0.2 for p in x], sig, 0.4, label="signature")
    ax.set_xticks(list(x))
    ax.set_xticklabels([LABELS[s] for s in SCHEMES])
    ax.set_ylabel("bytes")
    ax.set_title("Public-key and signature sizes (source: summary metadata)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(out, "key_signature_bytes.png"), dpi=150)
    plt.close(fig)


def plot_transport_headroom(transport, out):
    rows = json.load(open(transport))
    # Registered-key, operational template: the realistic authorization shape.
    by_scheme = {}
    for r in rows:
        if r["key_placement"] == "registered" and r["template"] == "operational":
            by_scheme.setdefault(r["scheme"], {})[r["format"]] = r["headroom"]
    for scheme in SCHEMES:
        if scheme not in by_scheme:
            raise SystemExit("missing operational/registered transport row for %s" % scheme)
    formats = ["legacy", "v1"]
    limits = {"legacy": 1232, "v1": 4096}
    fig, ax = plt.subplots(figsize=(7, 4))
    x = range(len(SCHEMES))
    width = 0.35
    for i, fmt in enumerate(formats):
        vals = [by_scheme[s][fmt] for s in SCHEMES]
        ax.bar(
            [p + i * width for p in x],
            vals,
            width,
            label="%s (limit %d)" % (fmt, limits[fmt]),
        )
    ax.axhline(0, color="black", linewidth=0.8)
    ax.set_xticks([p + width / 2 for p in x])
    ax.set_xticklabels([LABELS[s] for s in SCHEMES])
    ax.set_ylabel("headroom (bytes)")
    ax.set_title("Direct inclusion headroom, registered key, operational template")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "transport_headroom.png"), dpi=150)
    plt.close(fig)


def main():
    groups = load_raw(RAW)
    summaries = load_summaries(SUMMARY)
    sizes = sizes_from_summaries(summaries)
    plot_verification_latency(groups, OUT)
    plot_key_and_signature_sizes(sizes, OUT)
    plot_transport_headroom(TRANSPORT, OUT)
    print("wrote plots to %s" % OUT)


if __name__ == "__main__":
    main()
