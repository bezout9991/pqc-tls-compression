#!/usr/bin/env python3
"""
analyse_resumption_batch.py
Analyse des résultats Batch séparés : N full → N resumed
Inspiré de la littérature (rTLS, rustls-bench, arXiv:2603.11006)

Métriques :
  - n, min, max, mean, median (p50), p90, p95, p99, stdev
  - ratio full/resumed (speedup)
  - taux de succès
  - comparaison TLS vs QUIC

Usage:
  python3 analyse_resumption_batch.py <results_dir> [--plots] [--output <dir>]
"""

import os
import sys
import csv
import statistics
import math
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 10,
    'axes.titlesize': 11,
    'axes.labelsize': 10,
    'figure.dpi': 150,
    'savefig.dpi': 300,
    'axes.spines.top': False,
    'axes.spines.right': False,
})

RESULTS_DIR = sys.argv[1] if len(sys.argv) > 1 else "results"
PLOTS = "--plots" in sys.argv
OUTPUT_DIR = "results"

# Parse output dir
for i, arg in enumerate(sys.argv):
    if arg == "--output" and i + 1 < len(sys.argv):
        OUTPUT_DIR = sys.argv[i + 1]

os.makedirs(OUTPUT_DIR, exist_ok=True)


def parse_csv(filepath):
    """Parse un CSV resumption et retourne deux listes : full_times, resumed_times"""
    full_times = []
    resumed_times = []
    full_success = 0
    full_total = 0
    resumed_success = 0
    resumed_total = 0

    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            hs_type = row.get('handshake_type', '')
            duration = row.get('duration_ms', '')
            success = row.get('success', '1')

            if not duration:
                continue

            try:
                t = float(duration)
            except ValueError:
                continue

            if hs_type == 'full':
                full_total += 1
                if success == '1':
                    full_success += 1
                    full_times.append(t)
            elif hs_type == 'resumed':
                resumed_total += 1
                if success == '1':
                    resumed_success += 1
                    resumed_times.append(t)

    return {
        'full': full_times,
        'resumed': resumed_times,
        'full_success': full_success,
        'full_total': full_total,
        'resumed_success': resumed_success,
        'resumed_total': resumed_total,
    }


def compute_stats(times):
    """Calcule les statistiques descriptives (inspiré rTLS/rustls-bench)"""
    if not times:
        return None

    n = len(times)
    sorted_times = sorted(times)

    def percentile(p):
        """Interpolation linéaire (méthode numpy percentile)"""
        k = (n - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_times[int(k)]
        return sorted_times[f] * (c - k) + sorted_times[c] * (k - f)

    mean = statistics.mean(times)
    median = statistics.median(times)
    stdev = statistics.stdev(times) if n > 1 else 0.0

    return {
        'n': n,
        'min': sorted_times[0],
        'max': sorted_times[-1],
        'mean': mean,
        'median': median,
        'p50': percentile(50),
        'p90': percentile(90),
        'p95': percentile(95),
        'p99': percentile(99),
        'stdev': stdev,
        'p99_p50_ratio': percentile(99) / percentile(50) if percentile(50) > 0 else 0,
    }


def collect_data(results_dir):
    """Collecte tous les résultats batch dans un dictionnaire structuré"""
    data = {}

    for root, dirs, files in os.walk(results_dir):
        for f in files:
            if not f.startswith('resumption_') or not f.endswith('.csv'):
                continue

            filepath = os.path.join(root, f)

            # Extraire les métadonnées du nom de fichier
            # Format: resumption_{client_id}_{sig}_{kem}.csv
            parts = f.replace('.csv', '').split('_')
            if len(parts) < 4:
                continue
            sig_alg = parts[2]
            kem_alg = parts[3]

            # Extraire les métadonnées du répertoire parent
            # Format: {proto}_{profile}_l{loss}_d{delay}_{timestamp}
            dir_name = os.path.basename(root)
            dir_parts = dir_name.split('_')
            if len(dir_parts) < 5:
                continue

            proto = dir_parts[0]       # tls ou quic
            profile = dir_parts[1]     # none, simple, stable, unstable
            loss = dir_parts[2].replace('l', '') if len(dir_parts) > 2 else '0'
            delay = dir_parts[3].replace('d', '') if len(dir_parts) > 3 else '0'

            # Parser le CSV
            result = parse_csv(filepath)

            key = (proto, profile, loss, delay, sig_alg, kem_alg)
            if key not in data:
                data[key] = {
                    'full': [],
                    'resumed': [],
                    'full_success': 0,
                    'full_total': 0,
                    'resumed_success': 0,
                    'resumed_total': 0,
                }

            data[key]['full'].extend(result['full'])
            data[key]['resumed'].extend(result['resumed'])
            data[key]['full_success'] += result['full_success']
            data[key]['full_total'] += result['full_total']
            data[key]['resumed_success'] += result['resumed_success']
            data[key]['resumed_total'] += result['resumed_total']

    return data


def generate_summary_table(data):
    """Génère un tableau résumé CSV (inspiré rTLS Table 5, rustls-bench)"""
    rows = []

    for key in sorted(data.keys()):
        proto, profile, loss, delay, sig, kem = key
        d = data[key]

        full_stats = compute_stats(d['full'])
        resumed_stats = compute_stats(d['resumed'])

        # Taux de succès
        full_rate = (d['full_success'] / d['full_total'] * 100) if d['full_total'] > 0 else 0
        resumed_rate = (d['resumed_success'] / d['resumed_total'] * 100) if d['resumed_total'] > 0 else 0

        # Ratio full/resumed (speedup)
        if full_stats and resumed_stats and resumed_stats['median'] > 0:
            speedup = round(full_stats['median'] / resumed_stats['median'], 2)
        else:
            speedup = 0

        row = {
            'proto': proto,
            'profile': profile,
            'loss': loss,
            'delay': delay,
            'sig': sig,
            'kem': kem,
            # Full stats
            'full_n': full_stats['n'] if full_stats else 0,
            'full_min': round(full_stats['min'], 2) if full_stats else '',
            'full_mean': round(full_stats['mean'], 2) if full_stats else '',
            'full_median': round(full_stats['median'], 2) if full_stats else '',
            'full_p95': round(full_stats['p95'], 2) if full_stats else '',
            'full_p99': round(full_stats['p99'], 2) if full_stats else '',
            'full_stdev': round(full_stats['stdev'], 2) if full_stats else '',
            'full_success_rate': round(full_rate, 1),
            # Resumed stats
            'resumed_n': resumed_stats['n'] if resumed_stats else 0,
            'resumed_min': round(resumed_stats['min'], 2) if resumed_stats else '',
            'resumed_mean': round(resumed_stats['mean'], 2) if resumed_stats else '',
            'resumed_median': round(resumed_stats['median'], 2) if resumed_stats else '',
            'resumed_p95': round(resumed_stats['p95'], 2) if resumed_stats else '',
            'resumed_p99': round(resumed_stats['p99'], 2) if resumed_stats else '',
            'resumed_stdev': round(resumed_stats['stdev'], 2) if resumed_stats else '',
            'resumed_success_rate': round(resumed_rate, 1),
            # Speedup
            'speedup': speedup,
        }
        rows.append(row)

    return rows


def write_csv(rows, filepath):
    """Écrit le tableau résumé en CSV"""
    if not rows:
        print("Aucune donnée à écrire.")
        return

    fieldnames = [
        'proto', 'profile', 'loss', 'delay', 'sig', 'kem',
        'full_n', 'full_min', 'full_mean', 'full_median', 'full_p95', 'full_p99', 'full_stdev', 'full_success_rate',
        'resumed_n', 'resumed_min', 'resumed_mean', 'resumed_median', 'resumed_p95', 'resumed_p99', 'resumed_stdev', 'resumed_success_rate',
        'speedup',
    ]

    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"✅ Tableau résumé → {filepath}")


def print_latex_table(rows):
    """Affiche un tableau LaTeX pour l'article (inspiré rTLS Table 5)"""
    print("\n% Tableau LaTeX pour l'article")
    print("\\begin{table}[htbp]")
    print("\\centering")
    print("\\caption{TLS vs QUIC Session Resumption Performance}")
    print("\\label{tab:resumption}")
    print("\\begin{tabular}{llrrrrrr}")
    print("\\hline")
    print("Proto & Scenario & Full P50 & Full P99 & Resumed P50 & Resumed P99 & Speedup & Resumed\\% \\\\")
    print("\\hline")

    for row in rows:
        scenario = f"{row['delay']}ms/{row['loss']}\\%"
        proto = row['proto'].upper()
        full_p50 = row['full_median'] if row['full_median'] != '' else 'N/A'
        full_p99 = row['full_p99'] if row['full_p99'] != '' else 'N/A'
        res_p50 = row['resumed_median'] if row['resumed_median'] != '' else 'N/A'
        res_p99 = row['resumed_p99'] if row['resumed_p99'] != '' else 'N/A'
        speedup = row['speedup'] if row['speedup'] > 0 else 'N/A'
        res_rate = row['resumed_success_rate']

        print(f"{proto} & {scenario} & {full_p50} & {full_p99} & {res_p50} & {res_p99} & {speedup}x & {res_rate}\\% \\\\")

    print("\\hline")
    print("\\end{tabular}")
    print("\\end{table}")


def plot_comparison_tls_quic(data, output_dir, target_sig, target_kem, suffix=""):
    """Graphique comparatif TLS vs QUIC (inspiré rustls-bench)"""

    scenarios = [
        ('none', '0', '0', 'Ideal'),
        ('simple', '2', '35', '35ms/2%'),
        ('simple', '10', '200', '200ms/10%'),
        ('stable', '0', '0', 'GE Stable'),
    ]

    tls_full_med = []
    tls_resumed_med = []
    quic_full_med = []
    quic_resumed_med = []
    tls_resumed_rate = []
    quic_resumed_rate = []
    labels = []

    for profile, loss, delay, label in scenarios:
        labels.append(label)

        # TLS
        tls_key = ('tls', profile, loss, delay, target_sig, target_kem)
        if tls_key in data:
            d = data[tls_key]
            fs = compute_stats(d['full'])
            rs = compute_stats(d['resumed'])
            tls_full_med.append(fs['median'] if fs else 0)
            tls_resumed_med.append(rs['median'] if rs else 0)
            rate = (d['resumed_success'] / d['resumed_total'] * 100) if d['resumed_total'] > 0 else 0
            tls_resumed_rate.append(rate)
        else:
            tls_full_med.append(0)
            tls_resumed_med.append(0)
            tls_resumed_rate.append(0)

        # QUIC
        quic_key = ('quic', profile, loss, delay, target_sig, target_kem)
        if quic_key in data:
            d = data[quic_key]
            fs = compute_stats(d['full'])
            rs = compute_stats(d['resumed'])
            quic_full_med.append(fs['median'] if fs else 0)
            quic_resumed_med.append(rs['median'] if rs else 0)
            rate = (d['resumed_success'] / d['resumed_total'] * 100) if d['resumed_total'] > 0 else 0
            quic_resumed_rate.append(rate)
        else:
            quic_full_med.append(0)
            quic_resumed_med.append(0)
            quic_resumed_rate.append(0)

    # Figure 2 panels
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5))

    x = np.arange(len(labels))
    w = 0.2

    # Panel 1 : Full vs Resumed median
    ax1.bar(x - 1.5*w, tls_full_med, w, color='#4472C4', label='TLS Full', alpha=0.9)
    ax1.bar(x - 0.5*w, tls_resumed_med, w, color='#5B9BD5', label='TLS Resumed', alpha=0.9)
    ax1.bar(x + 0.5*w, quic_full_med, w, color='#ED7D31', label='QUIC Full', alpha=0.9)
    ax1.bar(x + 1.5*w, quic_resumed_med, w, color='#F4B183', label='QUIC Resumed', alpha=0.9)

    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontsize=9)
    ax1.set_ylabel('Median Duration (ms)')
    ax1.set_title('ML-DSA65 + ML-KEM768 — Full vs Resumed')
    ax1.legend(frameon=False, fontsize=8)
    ax1.set_yscale('log')
    ax1.yaxis.set_major_formatter(mticker.ScalarFormatter())
    ax1.ticklabel_format(style='plain', axis='y')

    # Panel 2 : Taux de succès resumed
    ax2.bar(x - 0.5*w, tls_resumed_rate, w, color='#4472C4', label='TLS', alpha=0.9)
    ax2.bar(x + 0.5*w, quic_resumed_rate, w, color='#ED7D31', label='QUIC', alpha=0.9)

    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, fontsize=9)
    ax2.set_ylabel('Resumed Success Rate (%)')
    ax2.set_title('Session Resumption Success Rate')
    ax2.set_ylim(0, 110)
    ax2.legend(frameon=False, fontsize=8)

    # Ajouter les valeurs sur les barres
    for i, (tls_r, quic_r) in enumerate(zip(tls_resumed_rate, quic_resumed_rate)):
        if tls_r > 0:
            ax2.text(i - 0.5*w, tls_r + 2, f'{tls_r:.0f}%', ha='center', fontsize=7, fontweight='bold')
        if quic_r > 0:
            ax2.text(i + 0.5*w, quic_r + 2, f'{quic_r:.0f}%', ha='center', fontsize=7, fontweight='bold')

    fig.suptitle('Post-Quantum TLS 1.3 vs QUIC — Session Resumption (Batch Séparés)',
                 fontsize=12, fontweight='bold', y=1.02)
    fig.tight_layout()

    for ext in ['pdf', 'svg', 'png']:
        fig.savefig(os.path.join(output_dir, f'comparison_resumption_batch{suffix}.{ext}'),
                    bbox_inches='tight', pad_inches=0.1)
    plt.close()
    print(f"✅ Plots → {output_dir}/comparison_resumption_batch{suffix}.pdf")


def plot_latency_distribution(data, output_dir, target_sig, target_kem, suffix=""):
    """Graphique de distribution de latence (inspiré rustls-bench, arXiv:2603.11006)"""

    scenarios = [
        ('none', '0', '0', 'Ideal (0ms/0%)'),
        ('simple', '2', '35', 'Local YDE (35ms/2%)'),
        ('simple', '10', '200', 'Degraded (200ms/10%)'),
        ('stable', '0', '0', 'GE Stable'),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    axes = axes.flatten()

    for idx, (profile, loss, delay, label) in enumerate(scenarios):
        ax = axes[idx]

        # TLS
        tls_key = ('tls', profile, loss, delay, target_sig, target_kem)
        if tls_key in data:
            d = data[tls_key]
            if d['full']:
                ax.hist(d['full'], bins=50, alpha=0.6, color='#4472C4', label='TLS Full', density=True)
            if d['resumed']:
                ax.hist(d['resumed'], bins=50, alpha=0.6, color='#5B9BD5', label='TLS Resumed', density=True)

        # QUIC
        quic_key = ('quic', profile, loss, delay, target_sig, target_kem)
        if quic_key in data:
            d = data[quic_key]
            if d['full']:
                ax.hist(d['full'], bins=50, alpha=0.6, color='#ED7D31', label='QUIC Full', density=True)
            if d['resumed']:
                ax.hist(d['resumed'], bins=50, alpha=0.6, color='#F4B183', label='QUIC Resumed', density=True)

        ax.set_title(label, fontsize=10)
        ax.set_xlabel('Duration (ms)')
        ax.set_ylabel('Density')
        ax.legend(fontsize=7, frameon=False)

    fig.suptitle('Latency Distribution — ML-DSA65 + ML-KEM768',
                 fontsize=12, fontweight='bold', y=1.01)
    fig.tight_layout()

    for ext in ['pdf', 'svg']:
        fig.savefig(os.path.join(output_dir, f'latency_distribution_batch{suffix}.{ext}'),
                    bbox_inches='tight', pad_inches=0.1)
    plt.close()
    print(f"✅ Distribution → {output_dir}/latency_distribution_batch{suffix}.pdf")


def plot_percentile_comparison(data, output_dir, target_sig, target_kem, suffix=""):
    """Graphique percentile comparison (inspiré arXiv:2603.11006 Table 5)"""

    scenarios = [
        ('none', '0', '0', 'Ideal'),
        ('simple', '2', '35', '35ms/2%'),
        ('simple', '10', '200', '200ms/10%'),
        ('stable', '0', '0', 'GE Stable'),
    ]

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))

    percentiles = [50, 90, 95, 99]
    x = np.arange(len(percentiles))
    w = 0.35

    # Panel 1: TLS
    ax1 = axes[0]
    tls_data = {'full': {}, 'resumed': {}}

    scenario_labels = [s[3] for s in scenarios]
    colors = ['#4472C4', '#70AD47', '#ED7D31', '#A5A5A5']

    for i, (profile, loss, delay, label) in enumerate(scenarios):
        tls_key = ('tls', profile, loss, delay, target_sig, target_kem)
        if tls_key in data:
            fs = compute_stats(data[tls_key]['full'])
            rs = compute_stats(data[tls_key]['resumed'])
            if fs:
                ax1.plot(percentiles, [fs[f'p{p}'] for p in percentiles], 'o-',
                        color=colors[i % len(colors)], label=f'TLS Full - {label}', alpha=0.8)
            if rs:
                ax1.plot(percentiles, [rs[f'p{p}'] for p in percentiles], 's--',
                        color=colors[i % len(colors)], label=f'TLS Resumed - {label}', alpha=0.5)

    ax1.set_xlabel('Percentile')
    ax1.set_ylabel('Duration (ms)')
    ax1.set_title('TLS 1.3 — Percentile Comparison')
    ax1.set_xticks(percentiles)
    ax1.legend(fontsize=7, frameon=False)

    # Panel 2: QUIC
    ax2 = axes[1]
    for i, (profile, loss, delay, label) in enumerate(scenarios):
        quic_key = ('quic', profile, loss, delay, target_sig, target_kem)
        if quic_key in data:
            fs = compute_stats(data[quic_key]['full'])
            rs = compute_stats(data[quic_key]['resumed'])
            if fs:
                ax2.plot(percentiles, [fs[f'p{p}'] for p in percentiles], 'o-',
                        color=colors[i % len(colors)], label=f'QUIC Full - {label}', alpha=0.8)
            if rs:
                ax2.plot(percentiles, [rs[f'p{p}'] for p in percentiles], 's--',
                        color=colors[i % len(colors)], label=f'QUIC Resumed - {label}', alpha=0.5)

    ax2.set_xlabel('Percentile')
    ax2.set_ylabel('Duration (ms)')
    ax2.set_title('QUIC — Percentile Comparison')
    ax2.set_xticks(percentiles)
    ax2.legend(fontsize=7, frameon=False)

    fig.suptitle(f'Percentile Analysis — {target_sig} + {target_kem}',
                  fontsize=12, fontweight='bold', y=1.02)
    fig.tight_layout()

    for ext in ['pdf', 'svg']:
        fig.savefig(os.path.join(output_dir, f'percentile_comparison_batch{suffix}.{ext}'),
                    bbox_inches='tight', pad_inches=0.1)
    plt.close()
    print(f"✅ Percentiles → {output_dir}/percentile_comparison_batch{suffix}.pdf")


def main():
    print(f"Analyse des résultats batch dans : {RESULTS_DIR}")
    print("=" * 80)

    # Collecter les données
    data = collect_data(RESULTS_DIR)

    if not data:
        print("Aucune donnée trouvée.")
        sys.exit(1)

    print(f"\n{len(data)} configurations trouvées.\n")

    # Générer le tableau résumé
    rows = generate_summary_table(data)

    # Écrire le CSV
    csv_path = os.path.join(OUTPUT_DIR, 'comparison_resumption_batch.csv')
    write_csv(rows, csv_path)

    # Afficher le tableau LaTeX
    print_latex_table(rows)

    # Afficher un résumé console
    print("\n" + "=" * 80)
    print("RÉSUMÉ DES RÉSULTATS")
    print("=" * 80)
    print(f"{'Proto':<6} {'Scenario':<18} {'Sig':<10} {'Full P50':>10} {'Res P50':>10} {'Speedup':>8} {'Res%':>8}")
    print("-" * 80)

    for row in rows:
        scenario = f"{row['delay']}ms/{row['loss']}%"
        full_p50 = f"{row['full_median']:.2f}" if row['full_median'] != '' else 'N/A'
        res_p50 = f"{row['resumed_median']:.2f}" if row['resumed_median'] != '' else 'N/A'
        speedup = f"{row['speedup']}x" if row['speedup'] > 0 else 'N/A'
        res_rate = f"{row['resumed_success_rate']:.0f}%"

        print(f"{row['proto'].upper():<6} {scenario:<18} {row['sig']:<10} {full_p50:>10} {res_p50:>10} {speedup:>8} {res_rate:>8}")

    # Générer les graphiques pour les deux paires
    pairs = [
        ('mldsa65', 'mlkem768'),
        ('mldsa87', 'hqc256')
    ]

    if PLOTS:
        print("\nGénération des graphiques pour les deux paires...")
        for sig, kem in pairs:
            suffix = f"_{sig}_{kem}"
            plot_comparison_tls_quic(data, OUTPUT_DIR, sig, kem, suffix)
            plot_latency_distribution(data, OUTPUT_DIR, sig, kem, suffix)
            plot_percentile_comparison(data, OUTPUT_DIR, sig, kem, suffix)

    print("\n✅ Analyse terminée.")


if __name__ == '__main__':
    main()
