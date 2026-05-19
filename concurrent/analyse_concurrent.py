#!/usr/bin/env python3
"""
analyse_concurrent.py
Analyse les résultats des tests de charge concurrente TLS/QUIC.

Usage:
    python3 analyse_concurrent.py <results_directory> [--plots]

Lit tous les fichiers client_N_*.csv dans le répertoire,
calcule les statistiques par client et globales,
et génère un rapport de synthèse.
"""

import os
import sys
import csv
import json
import glob
import argparse
import statistics
from collections import defaultdict

import numpy as np


def load_client_csv(filepath):
    """Charge un fichier CSV client et retourne (durations, successes)."""
    durations = []
    successes = []
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                d = float(row['duration_ms'])
                s = int(row['success'])
                durations.append(d)
                successes.append(s)
            except (ValueError, KeyError):
                continue
    return durations, successes


def compute_stats(values):
    """Calcule les statistiques descriptives d'une liste de valeurs."""
    if not values:
        return {'count': 0, 'median': None, 'mean': None, 'p95': None, 'p99': None,
                'min': None, 'max': None, 'std': None}
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


def analyse_directory(results_dir, generate_plots=False):
    """Analyse tous les résultats d'un répertoire de test concurrent."""
    
    # Trouver tous les fichiers CSV clients
    csv_pattern = os.path.join(results_dir, "client_*_*.csv")
    csv_files = sorted(glob.glob(csv_pattern))
    
    if not csv_files:
        print(f"[ERROR] Aucun fichier client_*.csv trouvé dans {results_dir}")
        return None

    # Regrouper par (sig_alg, kem_alg)
    groups = defaultdict(list)
    for f in csv_files:
        basename = os.path.basename(f)
        parts = basename.replace('.csv', '').split('_')
        # Format: client_{id}_{sig}_{kem}.csv
        if len(parts) >= 4:
            client_id = parts[1]
            sig_alg = parts[2]
            kem_alg = '_'.join(parts[3:])  # au cas où le KEM contient des _
            groups[(sig_alg, kem_alg)].append((client_id, f))

    # Charger les métadonnées
    meta = {}
    meta_files = glob.glob(os.path.join(results_dir, "metadata_*.txt"))
    for mf in meta_files:
        with open(mf, 'r') as f:
            for line in f:
                if '=' in line:
                    k, v = line.strip().split('=', 1)
                    meta[k] = v

    results = {}
    all_global_durations = []

    for (sig_alg, kem_alg), client_files in sorted(groups.items()):
        print(f"\n{'='*70}")
        print(f"  Signature: {sig_alg}  |  KEM: {kem_alg}")
        print(f"  Clients trouvés: {len(client_files)}")
        print(f"{'='*70}")

        per_client_stats = []
        all_durations = []
        total_success = 0
        total_attempts = 0

        for client_id, filepath in sorted(client_files, key=lambda x: int(x[0])):
            durations, successes = load_client_csv(filepath)
            stats = compute_stats(durations)
            stats['client_id'] = int(client_id)
            stats['success_count'] = sum(successes)
            stats['fail_count'] = len(successes) - sum(successes)
            stats['success_rate'] = sum(successes) / len(successes) * 100 if successes else 0
            per_client_stats.append(stats)
            all_durations.extend(durations)
            total_success += sum(successes)
            total_attempts += len(successes)

        # Statistiques globales (tous clients confondus)
        global_stats = compute_stats(all_durations)
        global_stats['total_clients'] = len(client_files)
        global_stats['total_handshakes'] = total_attempts
        global_stats['total_success'] = total_success
        global_stats['total_failures'] = total_attempts - total_success
        global_stats['success_rate'] = total_success / total_attempts * 100 if total_attempts else 0

        # Afficher le résumé
        print(f"\n  --- Résumé Global ---")
        print(f"  Total handshakes : {global_stats['total_handshakes']}")
        print(f"  Réussis          : {global_stats['total_success']} ({global_stats['success_rate']:.1f}%)")
        print(f"  Échoués          : {global_stats['total_failures']}")
        print(f"  Médiane          : {global_stats['median']:.2f} ms")
        print(f"  Moyenne          : {global_stats['mean']:.2f} ms")
        print(f"  P95              : {global_stats['p95']:.2f} ms")
        print(f"  P99              : {global_stats['p99']:.2f} ms")
        print(f"  Min / Max        : {global_stats['min']:.2f} / {global_stats['max']:.2f} ms")
        print(f"  Écart-type       : {global_stats['std']:.2f} ms")

        # Afficher les stats par client (top 5 + bottom 5)
        sorted_clients = sorted(per_client_stats, key=lambda x: x['median'] if x['median'] else float('inf'))
        print(f"\n  --- Top 5 clients les plus rapides (médiane) ---")
        for s in sorted_clients[:5]:
            print(f"  Client {s['client_id']:>4d}: médiane={s['median']:>8.2f} ms  "
                  f"p95={s['p95']:>8.2f} ms  succès={s['success_rate']:.0f}%")

        print(f"\n  --- Top 5 clients les plus lents (médiane) ---")
        for s in sorted_clients[-5:]:
            print(f"  Client {s['client_id']:>4d}: médiane={s['median']:>8.2f} ms  "
                  f"p95={s['p95']:>8.2f} ms  succès={s['success_rate']:.0f}%")

        key = f"{sig_alg}_{kem_alg}"
        results[key] = {
            'global': global_stats,
            'per_client': per_client_stats,
            'meta': meta
        }
        all_global_durations.extend(all_durations)

    # ── Sauvegarder le résumé en CSV ──────────────────────────────────────
    summary_csv = os.path.join(results_dir, "summary_concurrent.csv")
    with open(summary_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['sig_alg', 'kem_alg', 'num_clients', 'total_handshakes',
                         'success_rate', 'median_ms', 'mean_ms', 'p95_ms', 'p99_ms',
                         'min_ms', 'max_ms', 'std_ms', 'total_time_ms'])
        for key, data in results.items():
            g = data['global']
            m = data['meta']
            writer.writerow([
                key.split('_')[0], key.split('_', 1)[1] if '_' in key else key,
                g['total_clients'], g['total_handshakes'],
                f"{g['success_rate']:.1f}", f"{g['median']:.2f}",
                f"{g['mean']:.2f}", f"{g['p95']:.2f}", f"{g['p99']:.2f}",
                f"{g['min']:.2f}", f"{g['max']:.2f}", f"{g['std']:.2f}",
                m.get('total_time_ms', 'N/A')
            ])
    print(f"\n[RÉSUMÉ] Fichier CSV sauvegardé : {summary_csv}")

    # ── Sauvegarder les stats détaillées en JSON ───────────────────────────
    detail_json = os.path.join(results_dir, "detail_concurrent.json")
    # Convertir les stats numpy en types Python natifs
    serializable = {}
    for key, data in results.items():
        serializable[key] = {
            'global': {k: v for k, v in data['global'].items()},
            'per_client': [{k: v for k, v in c.items()} for c in data['per_client']],
            'meta': data['meta']
        }
    with open(detail_json, 'w') as f:
        json.dump(serializable, f, indent=2, default=str)
    print(f"[DÉTAIL] Fichier JSON sauvegardé : {detail_json}")

    # ── Générer les plots si demandé ──────────────────────────────────────
    if generate_plots:
        generate_plots_fn(results_dir, results)

    return results


def generate_plots_fn(results_dir, results):
    """Génère des graphiques pour les résultats concurrents."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        print("[PLOTS] matplotlib non disponible, plots ignorés.")
        return

    for key, data in results.items():
        sig_alg, kem_alg = key.split('_', 1) if '_' in key else (key, '')

        # Collecter toutes les durées par client
        client_data = {}
        for c in data['per_client']:
            # Recharger les durées depuis le CSV
            csv_file = os.path.join(results_dir, f"client_{c['client_id']}_{sig_alg}_{kem_alg}.csv")
            if os.path.exists(csv_file):
                durations, _ = load_client_csv(csv_file)
                client_data[c['client_id']] = durations

        if not client_data:
            continue

        # Violin plot par client
        fig, axes = plt.subplots(1, 2, figsize=(16, 6))

        # 1. Distribution par client (boxplot)
        client_ids = sorted(client_data.keys())
        data_to_plot = [client_data[cid] for cid in client_ids]
        axes[0].boxplot(data_to_plot, tick_labels=[str(c) for c in client_ids], showfliers=False)
        axes[0].set_xlabel('Client ID')
        axes[0].set_ylabel('Handshake Duration (ms)')
        axes[0].set_title(f'Distribution par client — {sig_alg} × {kem_alg}')
        axes[0].tick_params(axis='x', rotation=90)
        axes[0].grid(True, alpha=0.3)

        # 2. Distribution globale (histogramme)
        all_durations = []
        for d in data_to_plot:
            all_durations.extend(d)
        axes[1].hist(all_durations, bins=50, alpha=0.7, edgecolor='black')
        axes[1].axvline(np.median(all_durations), color='red', linestyle='--', label=f'Médiane: {np.median(all_durations):.1f} ms')
        axes[1].axvline(np.percentile(all_durations, 95), color='orange', linestyle='--', label=f'P95: {np.percentile(all_durations, 95):.1f} ms')
        axes[1].set_xlabel('Handshake Duration (ms)')
        axes[1].set_ylabel('Frequency')
        axes[1].set_title(f'Distribution globale — {sig_alg} × {kem_alg}')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)

        plt.tight_layout()
        plot_file = os.path.join(results_dir, f"plot_{sig_alg}_{kem_alg}.pdf")
        plt.savefig(plot_file, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"[PLOT] Sauvegardé : {plot_file}")

    # ── Comparaison multi-niveaux si plusieurs répertoires ─────────────────
    print("\n[PLOTS] Pour comparer plusieurs niveaux de concurrence, utilisez compare_concurrent.py")


def main():
    parser = argparse.ArgumentParser(description='Analyse des tests de charge concurrente TLS/QUIC')
    parser.add_argument('results_dir', help='Répertoire contenant les fichiers client_*.csv')
    parser.add_argument('--plots', action='store_true', help='Générer les graphiques')
    args = parser.parse_args()

    if not os.path.isdir(args.results_dir):
        print(f"[ERROR] Répertoire introuvable : {args.results_dir}")
        sys.exit(1)

    analyse_directory(args.results_dir, generate_plots=args.plots)


if __name__ == '__main__':
    main()
