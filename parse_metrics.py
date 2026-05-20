"""
parse_metrics.py
-----------------
Reads metrics_results.csv (written by WhatsTrustTM.writeMetricsCSV)
and prints the sensitivity analysis table: mean +/- std-dev per
assumption combination across all seeds.

Run from the same folder as metrics_results.csv:
    python parse_metrics.py

Output goes to console AND is saved as metrics_summary.csv.
Paste the table directly into your paper (Issue 5a + 5c).
"""

import pandas as pd
import numpy as np
import os

CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metrics_results.csv")

if not os.path.exists(CSV_PATH):
    print("ERROR: metrics_results.csv not found.")
    print("Run run_all.bat first, then come back to this script.")
    exit(1)

df = pd.read_csv(CSV_PATH)
print(f"Loaded {len(df)} rows from metrics_results.csv.\n")

# Group by assumption combo
group_cols = ["FwdPhiProb", "LegitURLProb", "MalType", "NumUsers"]
metrics    = ["M1_PhishDeliveryPct", "M2_CarrierBlockPct",
              "M3_AvgFPLoss", "SuccessRatePct", "RunTimeSec"]

# Build mean +/- std table
rows = []
for keys, grp in df.groupby(group_cols):
    row = dict(zip(group_cols, keys))
    row["Trials"] = len(grp)
    for m in metrics:
        row[f"{m}_mean"] = grp[m].mean()
        row[f"{m}_std"]  = grp[m].std()
    rows.append(row)

summary = pd.DataFrame(rows)

# Pretty-print
print("=" * 100)
print("SENSITIVITY ANALYSIS — mean ± std-dev across seeds")
print("=" * 100)

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 200)

for m in metrics:
    summary[f"{m}"] = summary.apply(
        lambda r: f"{r[f'{m}_mean']:.4f} ± {r[f'{m}_std']:.4f}", axis=1
    )

display_cols = group_cols + ["Trials"] + metrics
print(summary[display_cols].to_string(index=False))

print("\n")
print("Key interpretation:")
print("  M1 (Phishing delivery %)  — lower is better. Should drop vs. plain WhatsTrust.")
print("  M2 (Carrier block %)      — higher is better. Should be near 100%.")
print("  M3 (Avg FP trust loss)    — lower is better. Should stay small (< 0.1).")
print("  SuccessRate %             — overall good-user success (same metric as paper).")
print("  If M1/M2/M3 are stable across FwdPhiProb rows → your assumption choice is justified.")

# Save
out_path = os.path.join(os.path.dirname(CSV_PATH), "metrics_summary.csv")
summary.to_csv(out_path, index=False)
print(f"\nFull summary saved to: {out_path}")
print("Done.")
