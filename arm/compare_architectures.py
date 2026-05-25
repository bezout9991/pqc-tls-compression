#!/usr/bin/env python3
"""
compare_architectures.py
Compare les résultats entre x86_64 et ARM64.

Usage:
    python3 compare_architectures.py <x86_results_dir> <arm_results_dir> [--plots]

Compare les mêmes combinaisons (sig, kem, proto, scénario) entre les deux architectures.
"""

import os
import sys
import csv
import glob
import json
import argparse
from collections import defaultdict

import numpy as np


def load_durations_from_dir(results_dir):
    """Charge toutes les durées depuis un répertoire de résultats."""
    data = {}
    csv_pattern = os.path.join(results_dir, "client_*_*.csv")
    for csv_file in sorted(glob.glob(csv_pattern)):
        basename = os.path.basename(csv_file).replace('.csv', '')
        parts = basename.split('_')
        if len(parts) >= 4:
            sig_alg = parts[2]
            kem_alg = '_'.join(parts[3:])
        else:
            continue

        durations = []
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    d = float(row['duration_ms'])
                    durations.append(d)
                except (ValueError, KeyError):
                    continue

        if durations:
            key = (sig_alg, kem_alg)
            data[key] = durations

    # Charger les métadonnées
    meta = {}
    meta_files = glob.glob(os.path.join(results_dir, "metadata_*.txt"))
    for mf in meta_files:
        with open(mf, 'r') as f:
            for line in f:
                if '=' in line:
                    k, v = line.strip().split('=', 1)
                    meta[k] = v

    return data, meta


def compute_stats(values):
    if not values:
        return {'median': None, 'mean': None, 'p95': None, 'p99': None, 'count': 0}
    arr = np.array(values)
    return {
        'count': len(arr),
        'median': float(np.median(arr)),
        'mean': float(np.mean(arr)),
        'p95': float(np.percentile(arr, 95)),
        'p99': float(np.percentile(arr, 99)),
        'min': float(np.min(arr)),
        'max': float(np.max(arr)),
        'std': float(np.std(arr))
    }


def compare(x86_dir, arm_dir, output_dir=None, generate_plots=False):
    """Compare les résultats x86_64 vs ARM64."""

    x86_data, x86_meta = load_durations_from_dir(x86_dir)
    arm_data, arm_meta = load_durations_from_dir(arm_dir)

    if not x86_data:
        print(f"[ERROR] Aucune donnée x86_64 dans {x86_dir}")
        return
    if not arm_data:
        print(f"[ERROR] Aucune donnée ARM64 dans {arm_dir}")
        return

    x86_arch = x86_meta.get('docker_arch', x86_meta.get('host_arch', 'x86_64'))
    arm_arch = arm_meta.get('docker_arch', arm_meta.get('host_arch', 'arm64'))

    common_keys = set(x86_data.keys()) & set(arm_data.keys())
    only_x86 = set(x86_data.keys()) - set(arm_data.keys())
    only_arm = set(arm_data.keys()) - set(x86_data.keys())

    if only_x86:
        print(f"[WARN] Paires uniquement dans x86_64: {only_x86}")
    if only_arm:
        print(f"[WARN] Paires uniquement dans ARM64: {only_arm}")

    print(f"\n{'='*90}")
    print(f"  COMPARAISON {x86_arch} vs {arm_arch}")
    print(f"  {len(common_keys)} paires communes trouvées")
    print(f"{'='*90}")

    comparisons = []

    for key in sorted(common_keys):
        sig, kem = key
        x86_dur = x86_data[key]
        arm_dur = arm_data[key]

        x86_stats = compute_stats(x86_dur)
        arm_stats = compute_stats(arm_dur)

        # Ratio ARM/x86 (médiane)
        if x86_stats['median'] and arm_stats['median'] and x86_stats['median'] > 0:
            ratio_median = arm_stats['median'] / x86_stats['median']
            slowdown_pct = (ratio_median - 1) * 100
        else:
            ratio_median = None
            slowdown_pct = None

        print(f"\n  {sig} × {kem}")
        print(f"    {'':<12} {x86_arch:>12} {arm_arch:>12} {'Ratio ARM/x86':>14}")
        print(f"    {'Count':<12} {x86_stats['count']:>12} {arm_stats['count']:>12}")
        print(f"    {'Médiane':<12} {x86_stats['median']:>11.2f} ms {arm_stats['median']:>11.2f} ms {ratio_median:>13.2f}x ({slowdown_pct:+.1f}%)")
        print(f"    {'P95':<12} {x86_stats['p95']:>11.2f} ms {arm_stats['p95']:>11.2f} ms")
        print(f"    {'P99':<12} {x86_stats['p99']:>11.2f} ms {arm_stats['p99']:>11.2f} ms")
        print(f"    {'Min/Max':<12} {x86_stats['min']:.0f}/{x86_stats['max']:.0f} {arm_stats['min']:.0f}/{arm_stats['max']:.0f}")

        comparisons.append({
            'sig_alg': sig,
            'kem_alg': kem,
            'x86': x86_stats,
            'arm': arm_stats,
            'ratio_median': ratio_median,
            'slowdown_pct': slowdown_pct,
        })

    # ── Résumé global ──────────────────────────────────────────────────
    ratios = [c['ratio_median'] for c in comparisons if c['ratio_median'] is not None]
    if ratios:
        avg_ratio = np.mean(ratios)
        print(f"\n{'='*90}")
        print(f"  RÉSUMÉ GLOBAL")
        print(f"  Ratio ARM64/x86_64 moyen (médiane): {avg_ratio:.2f}x ({(avg_ratio-1)*100:+.1f}%)")
        print(f"  Min: {min(ratios):.2f}x  |  Max: {max(ratios):.2f}x")
        print(f"{'='*90}")

    # ── Sauvegarder CSV ────────────────────────────────────────────────
    out_dir = output_dir or os.path.commonpath([x86_dir, arm_dir])
    summary_csv = os.path.join(out_dir, "comparison_architectures.csv")
    with open(summary_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['sig_alg', 'kem_alg',
                         'x86_median_ms', 'x86_p95_ms', 'x86_p99_ms', 'x86_count',
                         'arm_median_ms', 'arm_p95_ms', 'arm_p99_ms', 'arm_count',
                         'ratio_arm_x86', 'slowdown_pct'])
        for c in comparisons:
            writer.writerow([
                c['sig_alg'], c['kem_alg'],
                f"{c['x86']['median']:.2f}", f"{c['x86']['p95']:.2f}",
                f"{c['x86']['p99']:.2f}", c['x86']['count'],
                f"{c['arm']['median']:.2f}", f"{c['arm']['p95']:.2f}",
                f"{c['arm']['p99']:.2f}", c['arm']['count'],
                f"{c['ratio_median']:.2f}" if c['ratio_median'] else "N/A",
                f"{c['slowdown_pct']:.1f}" if c['slowdown_pct'] is not None else "N/A"
            ])
    print(f"\n[CSV] {summary_csv}")

    # ── Plots ──────────────────────────────────────────────────────────
    if generate_plots:
        generate_plots_fn(out_dir, comparisons, x86_arch, arm_arch, x86_data, arm_data)

    return comparisons


def generate_plots_fn(out_dir, comparisons, x86_arch, arm_arch, x86_data, arm_data):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        print("[PLOTS] matplotlib non disponible.")
        return

    # 1. Bar chart: ratio ARM/x86 par paire
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))

    labels = [f"{c['sig_alg']}\n× {c['kem_alg']}" for c in comparisons]
    ratios = [c['ratio_median'] or 0 for c in comparisons]
    slowdowns = [c['slowdown_pct'] or 0 for c in comparisons]

    colors = ['#ff9999' if r > 1 else '#99ff99' for r in ratios]
    axes[0].barh(labels, ratios, color=colors, edgecolor='black')
    axes[0].axvline(x=1.0, color='black', linewidth=1.5, linestyle='--')
    axes[0].set_xlabel('Ratio ARM64 / x86_64 (médiane)')
    axes[0].set_title(f'Ratio de performance {arm_arch} vs {x86_arch}')
    for i, (r, s) in enumerate(zip(ratios, slowdowns)):
        axes[0].annotate(f'{r:.2f}x ({s:+.0f}%)', xy=(r, i), va='center',
                        fontsize=8, fontweight='bold')
    axes[0].grid(True, alpha=0.3, axis='x')

    # 2. Boxplot comparatif pour la première paire (la plus représentative)
    if comparisons:
        c = comparisons[0]
        sig, kem = c['sig_alg'], c['kem_alg']
        x86_dur = x86_data.get((sig, kem), [])
        arm_dur = arm_data.get((sig, kem), [])

        data = [x86_dur, arm_dur] if x86_dur and arm_dur else [[0], [0]]
        bp = axes[1].boxplot(data, labels=[x86_arch, arm_arch],
                            patch_artist=True, showfliers=False)
        bp['boxes'][0].set_facecolor('#6699cc')
        bp['boxes'][1].set_facecolor('#ff9966')
        axes[1].set_ylabel('Handshake Duration (ms)')
        axes[1].set_title(f'{sig} × {kem} — Distribution')
        axes[1].grid(True, alpha=0.3)

    plt.tight_layout()
    plot_file = os.path.join(out_dir, "plot_arch_comparison.pdf")
    plt.savefig(plot_file, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[PLOT] {plot_file}")


def main():
    parser = argparse.ArgumentParser(description='Comparaison architectures x86_64 vs ARM64')
    parser.add_argument('x86_dir', help='Répertoire résultats x86_64')
    parser.add_argument('arm_dir', help='Répertoire résultats ARM64')
    parser.add_argument('--output', '-o', default=None, help='Répertoire de sortie')
    parser.add_argument('--plots', action='store_true', help='Générer les graphiques')
    args = parser.parse_args()

    for d in [args.x86_dir, args.arm_dir]:
        if not os.path.isdir(d):
            print(f"[ERROR] Répertoire introuvable : {d}")
            sys.exit(1)

    compare(args.x86_dir, args.arm_dir, args.output, generate_plots=args.plots)


if __name__ == '__main__':
    main()
