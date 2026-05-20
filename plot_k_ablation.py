"""
plot_k_ablation.py
-------------------
Reads metrics_results.csv and plots the K ablation trade-off curve
exactly as specified in the Dr's feedback (Issue 3 appendix):

  X-axis: K (severity constant)
  Y-axis left:  M1 phishing delivery rate (%)  — want LOW
  Y-axis right: M3 avg false-positive trust loss — want LOW

The sweet spot where phishing is low but FP cost is still acceptable
is your recommended K value. Label it in the paper.

Run: python plot_k_ablation.py
Output: k_ablation.png
"""

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import os

CSV = "metrics_results.csv"

if not os.path.exists(CSV):
    print(f"ERROR: {CSV} not found. Run run_all.bat first.")
    exit(1)

df = pd.read_csv(CSV)

# Keep only WhatsTrust rows that have a K column
if 'PenaltyK' not in df.columns:
    print("ERROR: PenaltyK column not found. Make sure you ran the updated run_all.bat.")
    exit(1)

# Average M1 and M3 across seeds/traces for each K
grouped = df.groupby('PenaltyK').agg(
    M1_mean=('M1_PhishDeliveryPct', 'mean'),
    M1_std =('M1_PhishDeliveryPct', 'std'),
    M3_mean=('M3_AvgFPLoss',        'mean'),
    M3_std =('M3_AvgFPLoss',        'std'),
    SR_mean=('SuccessRatePct',      'mean'),
).reset_index()

print(grouped.to_string(index=False))

fig, ax1 = plt.subplots(figsize=(8, 5))

color1 = '#e74c3c'
color2 = '#2980b9'

ax1.set_xlabel('Penalty Severity K', fontsize=13)
ax1.set_ylabel('M1: Phishing Delivery Rate (%)', color=color1, fontsize=12)
ax1.errorbar(grouped['PenaltyK'], grouped['M1_mean'],
             yerr=grouped['M1_std'], color=color1,
             marker='o', linewidth=2, markersize=8, label='Phishing delivery (M1)')
ax1.tick_params(axis='y', labelcolor=color1)
ax1.set_xticks(grouped['PenaltyK'])

ax2 = ax1.twinx()
ax2.set_ylabel('M3: Avg False-Positive Trust Loss', color=color2, fontsize=12)
ax2.errorbar(grouped['PenaltyK'], grouped['M3_mean'],
             yerr=grouped['M3_std'], color=color2,
             marker='s', linewidth=2, markersize=8, linestyle='--', label='FP trust loss (M3)')
ax2.tick_params(axis='y', labelcolor=color2)

# Annotate sweet spot
best_k = grouped.loc[grouped['M1_mean'].idxmin(), 'PenaltyK']
ax1.axvline(x=best_k, color='gray', linestyle=':', linewidth=1.5)
ax1.text(best_k + 0.1, grouped['M1_mean'].max() * 0.9,
         f'Recommended K={best_k}', fontsize=10, color='gray')

lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper right')

plt.title('Confidence-Weighted Penalty: K Trade-off Curve\n(M1 vs M3)', fontsize=13)
plt.tight_layout()
out = 'k_ablation.png'
plt.savefig(out, dpi=150)
print(f"\nSaved: {out}")
print("Use this figure in your paper under 'Penalty Sensitivity Analysis'.")
