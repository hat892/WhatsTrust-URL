"""
parse_results.py
-----------------
Reads all .eigen and .whatstrust output files and generates:
1. A comparison CSV table
2. Success rate charts (like the original WhatsTrust paper)

Run from: JavaApplication22\JavaApplication22\src
"""

import os
import re
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

# =============================================================
# STEP 1: PARSE OUTPUT FILES
# =============================================================

def parse_file(filepath):
    """Extract key statistics from a simulation output file."""
    stats = {}
    try:
        with open(filepath, 'r') as f:
            content = f.read()

        # Extract values using regex
        def get(pattern):
            m = re.search(pattern, content)
            return float(m.group(1)) if m else None

        stats['num_users']       = get(r'Number of Peers:\s+(\d+)')
        stats['num_trans']       = get(r'Number of Transactions:\s+(\d+)')
        stats['malicious_users'] = get(r'Purely Malicious Users:\s+(\d+)')
        stats['good_users']      = get(r'Good Behaving Users:\s+(\d+)')
        stats['good_successes']  = get(r'Good User Successes:\s+(\d+)')
        stats['good_transacts']  = get(r'Good User Transacts:\s+(\d+)')
        stats['strategy']        = re.search(r'Malicious strategy:\s+(\w+)', content)
        stats['strategy']        = stats['strategy'].group(1).lower() if stats['strategy'] else 'unknown'

        # Calculate success rate
        if stats['good_transacts'] and stats['good_transacts'] > 0:
            stats['success_rate'] = (stats['good_successes'] / stats['good_transacts']) * 100
        else:
            stats['success_rate'] = 0

        # Calculate malicious percentage
        if stats['num_users'] and stats['num_users'] > 0:
            stats['mal_percent'] = int((stats['malicious_users'] / stats['num_users']) * 100)
        else:
            stats['mal_percent'] = 0

    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
        return None

    return stats


# =============================================================
# STEP 2: COLLECT ALL RESULTS
# =============================================================

src_dir = os.path.dirname(os.path.abspath(__file__))
results = []

for filename in os.listdir(src_dir):
    if filename.endswith('.eigen') or filename.endswith('.whatstrust'):
        filepath = os.path.join(src_dir, filename)
        stats = parse_file(filepath)
        if stats:
            # Determine algorithm
            if filename.endswith('.eigen'):
                stats['algorithm'] = 'EigenTrust'
            else:
                stats['algorithm'] = 'WhatsTrust+URL'

            # Extract trace name
            stats['trace'] = filename.rsplit('.', 1)[0]
            results.append(stats)

if not results:
    print("No result files found! Make sure you're running from the src folder.")
    exit()

df = pd.DataFrame(results)
print(f"Loaded {len(df)} result files.")
print(df[['trace', 'algorithm', 'strategy', 'num_users', 'num_trans', 'mal_percent', 'success_rate']].head(10))

# Save full results to CSV
csv_path = os.path.join(src_dir, 'results_comparison.csv')
df.to_csv(csv_path, index=False)
print(f"\nFull results saved to: {csv_path}")

# =============================================================
# STEP 3: GENERATE CHARTS (like WhatsTrust paper)
# =============================================================

def plot_success_rate(df, strategy, save_path):
    """Plot success rate vs malicious percentage for each user count."""
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    fig.suptitle(f'Success Rate - {strategy.capitalize()} Strategy', fontsize=14)

    user_counts = [100, 200, 300]
    colors = {'EigenTrust': 'blue', 'WhatsTrust+URL': 'green'}
    markers = {'EigenTrust': 'o', 'WhatsTrust+URL': 's'}

    for idx, users in enumerate(user_counts):
        ax = axes[idx]
        subset = df[(df['strategy'] == strategy) & (df['num_users'] == users)]

        for algo in ['EigenTrust', 'WhatsTrust+URL']:
            algo_data = subset[subset['algorithm'] == algo]
            # Average over transaction counts and runs
            avg = algo_data.groupby('mal_percent')['success_rate'].mean().reset_index()
            avg = avg.sort_values('mal_percent')

            if not avg.empty:
                ax.plot(avg['mal_percent'], avg['success_rate'],
                       label=algo, color=colors[algo],
                       marker=markers[algo], linewidth=2, markersize=6)

        ax.set_title(f'{users} Users')
        ax.set_xlabel('Malicious Users (%)')
        ax.set_ylabel('Success Rate (%)')
        ax.set_ylim(0, 105)
        ax.legend()
        ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    print(f"Chart saved: {save_path}")
    plt.close()


# Generate charts for both strategies
plot_success_rate(df, 'naive',
    os.path.join(src_dir, 'results_naive.png'))
plot_success_rate(df, 'collective',
    os.path.join(src_dir, 'results_collective.png'))

# =============================================================
# STEP 4: SUMMARY TABLE
# =============================================================
print("\n=== SUMMARY: Average Success Rate ===")
summary = df.groupby(['algorithm', 'strategy', 'num_users', 'mal_percent'])['success_rate'].mean().reset_index()
summary = summary.round(2)
print(summary.to_string(index=False))

# Save summary
summary_path = os.path.join(src_dir, 'results_summary.csv')
summary.to_csv(summary_path, index=False)
print(f"\nSummary saved to: {summary_path}")
print("\nDone! Check results_naive.png and results_collective.png")
