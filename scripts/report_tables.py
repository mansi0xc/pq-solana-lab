#!/usr/bin/env python3
"""Generate (or check) the numerical report tables from result artifacts.

Usage:
  python3 scripts/report_tables.py generate [options]
  python3 scripts/report_tables.py check    [options]

Options:
  --raw       results/raw/full-r1.csv
  --summary   results/summaries/full-r1.csv
  --transport results/transport.json
  --staged    results/transport-staged.json
  --repeats   full-r1,full-r2,full-r3    (independent runs for variability)
  --report    docs/report.md
  --out       results/tables

`generate` writes results/tables/*.csv and *.md and injects the tables into
docs/report.md between `<!-- BEGIN GENERATED: name -->` markers. `check`
recomputes everything and fails if the committed tables or the report are
stale — a fast detector for published numbers that no longer match the raw
evidence. Every table states its source run and configuration.
"""
import argparse
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analysis import (  # noqa: E402
    LABELS,
    SCHEMES,
    fmt_ns,
    load_raw,
    load_summaries,
    stats,
)

BLOCK_ORDER = [
    "host_primitives",
    "boundaries",
    "host_quartiles",
    "transport_direct",
    "transport_staged",
    "between_runs",
]


def _cell(raw, summaries, scheme, op, mode, length, cls):
    key = (scheme, op, mode, length, cls)
    if key not in raw:
        raise ValueError("missing valid raw samples for %s" % (key,))
    if summaries.get(key, {}).get("status", "ok") != "ok":
        raise ValueError("cannot publish non-ok case %s" % (key,))
    return stats(raw[key])


def render_host_primitives(raw, summaries, raw_path):
    lines = [
        "_Source: run `full-r1` (`configs/full.json`), mode `prepared`, input class "
        "`valid`, 166-byte messages; raw `%s`. Medians recomputed from raw samples._"
        % raw_path,
        "",
        "| Scheme | keygen | sign (166 B) | verify (166 B) | pubkey (B) | signature (B) |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    rows = []
    for scheme in SCHEMES:
        kg = _cell(raw, summaries, scheme, "keygen", "n/a", "0", "n/a")
        sg = _cell(raw, summaries, scheme, "sign", "prepared", "166", "valid")
        vf = _cell(raw, summaries, scheme, "verify", "prepared", "166", "valid")
        sizes = summaries[(scheme, "keygen", "n/a", "0", "n/a")]
        pk = int(sizes["public_key_bytes"])
        sig = int(sizes["signature_bytes"])

        def cell(s):
            note = "" if s["n"] >= 1000 else " (n=%d)" % s["n"]
            return fmt_ns(s["median"]) + note

        lines.append(
            "| %s | %s | %s | %s | %d | %d |"
            % (LABELS[scheme], cell(kg), cell(sg), cell(vf), pk, sig)
        )
        rows.append(
            {
                "scheme": scheme,
                "keygen_ns": kg["median"],
                "sign_166_ns": sg["median"],
                "verify_166_ns": vf["median"],
                "public_key_bytes": pk,
                "signature_bytes": sig,
            }
        )
    return "\n".join(lines), rows


BOUNDARY_SPECS = [
    ("verify", "prepared", "166", "valid", "verify prepared"),
    ("verify", "byte", "166", "valid", "verify byte"),
    ("verify_strict", "prepared", "166", "valid", "strict verify prepared"),
    ("verify_strict", "byte", "166", "valid", "strict verify byte"),
    ("authorize", "authorizer", "166", "valid", "authorize (accept)"),
    ("authorize", "authorizer", "166", "replay", "authorize (replay reject)"),
]


def render_boundaries(raw, summaries, raw_path):
    header = "| Scheme | " + " | ".join(s[4] for s in BOUNDARY_SPECS) + " |"
    sep = "| --- |" + " --- |" * len(BOUNDARY_SPECS)
    lines = [
        "_Source: run `full-r1` (`configs/full.json`), 166-byte messages; medians "
        "recomputed from `%s`. `authorize` includes registry lookup, intent "
        "decoding, environment/expiry policy, strict verification, and the atomic "
        "nonce/ledger update; the reject row is a replay workload._" % raw_path,
        "",
        header,
        sep,
    ]
    rows = []
    for scheme in SCHEMES:
        cells = []
        row = {"scheme": scheme}
        for op, mode, length, cls, label in BOUNDARY_SPECS:
            s = _cell(raw, summaries, scheme, op, mode, length, cls)
            cells.append(fmt_ns(s["median"]))
            row[label.replace(" ", "_").replace("(", "").replace(")", "")] = s["median"]
        lines.append("| %s | %s |" % (LABELS[scheme], " | ".join(cells)))
        rows.append(row)
    return "\n".join(lines), rows


def render_host_quartiles(raw, raw_path):
    lines = [
        "_Source: run `full-r1` (`configs/full.json`), mode `prepared`, input class "
        "`valid`, 166-byte messages; raw `%s`. Quartiles recomputed from raw samples "
        "(linear interpolation); p95 omitted below 200 samples._" % raw_path,
        "",
        "| Scheme | operation | n | median | Q1 | Q3 | p95 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    rows = []
    for scheme in SCHEMES:
        for op, mode, length, cls in [
            ("keygen", "n/a", "0", "n/a"),
            ("sign", "prepared", "166", "valid"),
            ("verify", "prepared", "166", "valid"),
        ]:
            key = (scheme, op, mode, length, cls)
            if key not in raw:
                raise ValueError("missing valid raw samples for %s" % (key,))
            s = stats(raw[key])
            p95 = fmt_ns(s["p95"]) if s["n"] >= 200 else "—"
            lines.append(
                "| %s | %s | %d | %s | %s | %s | %s |"
                % (
                    LABELS[scheme],
                    op,
                    s["n"],
                    fmt_ns(s["median"]),
                    fmt_ns(s["q1"]),
                    fmt_ns(s["q3"]),
                    p95,
                )
            )
            rows.append(
                {
                    "scheme": scheme,
                    "operation": op,
                    "n": s["n"],
                    "median_ns": s["median"],
                    "q1_ns": s["q1"],
                    "q3_ns": s["q3"],
                    "p95_ns": s["p95"] if s["n"] >= 200 else "",
                }
            )
    return "\n".join(lines), rows


def render_transport_direct(rows, transport_path):
    lines = [
        "_Source: `%s` — actually serialized `solana-sdk` 5.0.0 transactions; "
        "legacy/v0 use bincode, v1 uses the SDK `wincode` wire encoder. Evidence "
        "type: `serialized`. Limits: legacy/v0 = 1,232 B, v1 = 4,096 B._"
        % transport_path,
        "",
        "| Scheme | Template | Placement | legacy (B) | v0 (B) | v1 (B) | accounts | v1 config |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    by = {(r["scheme"], r["template"], r["key_placement"], r["format"]): r for r in rows}
    out = []
    for scheme in SCHEMES:
        for template in ["minimal", "operational"]:
            for placement in ["inline", "registered"]:
                get = lambda fmt: by[(scheme, template, placement, fmt)]  # noqa: E731
                legacy, v0, v1 = get("legacy"), get("v0"), get("v1")
                config = "empty" if v1["v1_config"] == "empty" else "explicit"
                lines.append(
                    "| %s | %s | %s | %d | %d | %d | %d | %s |"
                    % (
                        LABELS[scheme],
                        template,
                        placement,
                        legacy["total_bytes"],
                        v0["total_bytes"],
                        v1["total_bytes"],
                        legacy["account_count"],
                        config,
                    )
                )
                out.append(
                    {
                        "scheme": scheme,
                        "template": template,
                        "key_placement": placement,
                        "account_count": legacy["account_count"],
                        "legacy_bytes": legacy["total_bytes"],
                        "v0_bytes": v0["total_bytes"],
                        "v1_bytes": v1["total_bytes"],
                        "v1_config": v1["v1_config"],
                        "evidence_type": "serialized",
                    }
                )
    return "\n".join(lines), out


def render_transport_staged(rows, staged_path):
    lines = [
        "_Source: `%s` — a **model** (each transaction serialized, lifecycle not "
        "executed). Includes init/write/seal/authorize transaction bytes and "
        "session metadata + signature storage; excludes key registration, account "
        "rent, cleanup, and compute._" % staged_path,
        "",
        "| Scheme | Format | signature (B) | storage (B) | chunk (B) | chunks | transactions | total transport (B) |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    out = []
    for scheme in SCHEMES:
        for fmt in ["legacy", "v0", "v1"]:
            r = next((x for x in rows if x["scheme"] == scheme and x["format"] == fmt), None)
            if r is None:
                raise ValueError("missing staged row %s %s" % (scheme, fmt))
            lines.append(
                "| %s | %s | %d | %d | %d | %d | %d | %d |"
                % (
                    LABELS[scheme],
                    fmt,
                    r["signature_bytes"],
                    r["storage_bytes"],
                    r["chunk_bytes"],
                    r["chunk_count"],
                    r["total_transactions"],
                    r["total_transport_bytes"],
                )
            )
            out.append(
                {
                    "scheme": scheme,
                    "format": fmt,
                    "signature_bytes": r["signature_bytes"],
                    "storage_bytes": r["storage_bytes"],
                    "chunk_bytes": r["chunk_bytes"],
                    "chunk_count": r["chunk_count"],
                    "total_transactions": r["total_transactions"],
                    "total_transport_bytes": r["total_transport_bytes"],
                    "evidence_type": r["evidence_type"],
                }
            )
    return "\n".join(lines), out


REPEAT_SPECS = [
    ("keygen", "n/a", "0", "n/a", "keygen"),
    ("sign", "prepared", "166", "valid", "sign 166 B"),
    ("verify", "prepared", "166", "valid", "verify 166 B"),
    ("verify_strict", "prepared", "166", "valid", "strict verify"),
    ("authorize", "authorizer", "166", "valid", "authorize"),
]


def render_between_runs(run_ids, summary_paths):
    if not run_ids:
        raise ValueError("no repeat runs were given")
    summaries = []
    for run_id, path in zip(run_ids, summary_paths):
        if not os.path.exists(path):
            raise ValueError("missing repeat run %s (%s)" % (run_id, path))
        summaries.append(load_summaries(path))
    if len(run_ids) < 2:
        raise ValueError("between-run variability needs at least two runs")

    header = "| Scheme | operation | " + " | ".join(run_ids) + " | spread |"
    sep = "| --- | --- |" + " --- |" * len(run_ids) + " --- |"
    lines = [
        "_Source: independent runs %s (`configs/full.json`), prepared/valid, "
        "166-byte messages. Medians read from each run's summary; spread = "
        "(max − min) / min._" % ", ".join("`%s`" % r for r in run_ids),
        "",
        header,
        sep,
    ]
    rows = []
    for scheme in SCHEMES:
        for op, mode, length, cls, label in REPEAT_SPECS:
            key = (scheme, op, mode, length, cls)
            medians = []
            for sm in summaries:
                row = sm.get(key)
                if row is None or not row.get("median_ns"):
                    raise ValueError("missing median for %s in a repeat run" % (key,))
                medians.append(int(row["median_ns"]))
            spread = 0.0 if len(medians) < 2 else (max(medians) - min(medians)) * 100.0 / min(medians)
            lines.append(
                "| %s | %s | %s | %.1f%% |"
                % (
                    LABELS[scheme],
                    label,
                    " | ".join(fmt_ns(m) for m in medians),
                    spread,
                )
            )
            row = {"scheme": scheme, "operation": label, "spread_percent": round(spread, 2)}
            for run_id, m in zip(run_ids, medians):
                row["median_ns_%s" % run_id] = m
            rows.append(row)
    return "\n".join(lines), rows


def compute_blocks(args):
    raw = load_raw(args.raw)
    summaries = load_summaries(args.summary)
    transport = json.load(open(args.transport))
    staged = json.load(open(args.staged))

    hp_md, hp_rows = render_host_primitives(raw, summaries, args.raw)
    bd_md, bd_rows = render_boundaries(raw, summaries, args.raw)
    hq_md, hq_rows = render_host_quartiles(raw, args.raw)
    td_md, td_rows = render_transport_direct(transport, args.transport)
    ts_md, ts_rows = render_transport_staged(staged, args.staged)

    run_ids = [r for r in args.repeats.split(",") if r]
    repeat_paths = ["results/summaries/%s.csv" % r for r in run_ids]
    br_md, br_rows = render_between_runs(run_ids, repeat_paths)

    return {
        "host_primitives": (hp_md, hp_rows),
        "boundaries": (bd_md, bd_rows),
        "host_quartiles": (hq_md, hq_rows),
        "transport_direct": (td_md, td_rows),
        "transport_staged": (ts_md, ts_rows),
        "between_runs": (br_md, br_rows),
    }


def write_csv(path, rows):
    if not rows:
        raise ValueError("refusing to write empty table %s" % path)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def replace_block(text, name, body):
    begin = "<!-- BEGIN GENERATED: %s -->" % name
    end = "<!-- END GENERATED: %s -->" % name
    if begin not in text or end not in text:
        raise ValueError("report is missing markers for block %r" % name)
    i = text.index(begin) + len(begin)
    j = text.index(end)
    return text[:i] + "\n" + body + "\n" + text[j:]


def extract_block(text, name):
    begin = "<!-- BEGIN GENERATED: %s -->" % name
    end = "<!-- END GENERATED: %s -->" % name
    if begin not in text or end not in text:
        raise ValueError("report is missing markers for block %r" % name)
    i = text.index(begin) + len(begin)
    j = text.index(end)
    return text[i:j].strip("\n")


def do_generate(args, blocks):
    os.makedirs(args.out, exist_ok=True)
    text = open(args.report).read()
    for name, (md, rows) in blocks.items():
        with open(os.path.join(args.out, name + ".md"), "w") as f:
            f.write(md + "\n")
        write_csv(os.path.join(args.out, name + ".csv"), rows)
        text = replace_block(text, name, md)
    with open(args.report, "w") as f:
        f.write(text)
    print("generated %d tables into %s and updated %s" % (len(blocks), args.out, args.report))


def do_check(args, blocks):
    problems = []
    text = open(args.report).read()
    for name, (md, _rows) in blocks.items():
        path = os.path.join(args.out, name + ".md")
        committed = open(path).read().strip("\n") if os.path.exists(path) else "<missing>"
        if committed != md:
            problems.append("stale generated table: %s" % path)
        if extract_block(text, name).strip("\n") != md:
            problems.append("stale report block: %s" % name)
    if problems:
        sys.stderr.write("report is stale; rerun `report_tables.py generate`:\n")
        for p in problems:
            sys.stderr.write("  - %s\n" % p)
        return 1
    print("report tables are consistent with the raw/serialized evidence")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["generate", "check"])
    ap.add_argument("--raw", default="results/raw/full-r1.csv")
    ap.add_argument("--summary", default="results/summaries/full-r1.csv")
    ap.add_argument("--transport", default="results/transport.json")
    ap.add_argument("--staged", default="results/transport-staged.json")
    ap.add_argument("--repeats", default="full-r1,full-r2,full-r3")
    ap.add_argument("--report", default="docs/report.md")
    ap.add_argument("--out", default="results/tables")
    args = ap.parse_args()

    blocks = compute_blocks(args)
    if args.mode == "generate":
        do_generate(args, blocks)
        return 0
    return do_check(args, blocks)


if __name__ == "__main__":
    sys.exit(main())
