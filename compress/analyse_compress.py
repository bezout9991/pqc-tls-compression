#!/usr/bin/env python3
"""
analyse_compress.py
Analyse les résultats compression certificat (avec vs sans).

Usage:
    python3 analyse_compress.py <results_directory> [--plots]

Pour chaque paire (sig, kem), compare:
  - Durée handshake (médiane, p95, p99)
  - Taille totale handshake (bytes) — depuis pcap
  - Nombre de paquets — depuis pcap
  - Retransmissions TCP — depuis pcap
"""

import os
import sys
import csv
import glob
import json
import subprocess
import argparse
import re
from collections import defaultdict

import numpy as np


def load_duration_csv(filepath):
    """Charge un CSV de durée et retourne (durations, successes)."""
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
    """Statistiques descriptives."""
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


def analyse_pcap_tls(pcap_file):
    """
    Analyse un pcap TLS avec tshark.
    Retourne:
      - total_bytes: somme des bytes TCP sur le port serveur
      - total_packets: nombre total de paquets
      - retransmissions: nombre de retransmissions TCP
      - bytes_per_conn: liste des bytes par connexion TCP
      - packets_per_conn: liste des paquets par connexion TCP
    """
    result = {
        'total_bytes': 0,
        'total_packets': 0,
        'retransmissions': 0,
        'bytes_per_conn': [],
        'packets_per_conn': [],
        'error': None
    }

    if not os.path.exists(pcap_file):
        result['error'] = f"Fichier introuvable: {pcap_file}"
        return result

    try:
        # Total bytes et packets (port 4433)
        cap_info = subprocess.run(
            ['capinfos', '-M', pcap_file],
            capture_output=True, text=True, timeout=30
        )
        for line in cap_info.stdout.splitlines():
            if 'File size' in line:
                pass
            if 'Number of packets' in line:
                m = re.search(r'(\d+)', line)
                if m:
                    result['total_packets'] = int(m.group(1))
            if 'Data size' in line:
                m = re.search(r'(\d+)\s*bytes', line)
                if m:
                    result['total_bytes'] = int(m.group(1))

        # Retransmissions TCP
        retrans = subprocess.run(
            ['tshark', '-r', pcap_file, '-Y', 'tcp.analysis.retransmission', '-T', 'fields', '-e', 'frame.number'],
            capture_output=True, text=True, timeout=30
        )
        result['retransmissions'] = len([l for l in retrans.stdout.splitlines() if l.strip()])

        # Bytes et packets par connexion TCP (stream)
        streams = subprocess.run(
            ['tshark', '-r', pcap_file, '-T', 'fields',
             '-e', 'tcp.stream', '-e', 'frame.len', '-e', 'ip.dst'],
            capture_output=True, text=True, timeout=30
        )

        conn_bytes = defaultdict(int)
        conn_packets = defaultdict(int)
        for line in streams.stdout.splitlines():
            parts = line.split('\t')
            if len(parts) >= 2 and parts[0].strip():
                stream_id = parts[0].strip()
                try:
                    pkt_len = int(parts[1].strip())
                    conn_bytes[stream_id] += pkt_len
                    conn_packets[stream_id] += 1
                except ValueError:
                    continue

        result['bytes_per_conn'] = list(conn_bytes.values())
        result['packets_per_conn'] = list(conn_packets.values())

    except FileNotFoundError:
        result['error'] = "tshark/capinfos non installé"
    except subprocess.TimeoutExpired:
        result['error'] = "Timeout analyse pcap"
    except Exception as e:
        result['error'] = str(e)

    return result


def analyse_pcap_quic(pcap_file):
    """
    Analyse un pcap QUIC (UDP).
    Retourne les mêmes métriques adaptées à QUIC.
    """
    result = {
        'total_bytes': 0,
        'total_packets': 0,
        'retransmissions': 0,
        'bytes_per_conn': [],
        'packets_per_conn': [],
        'error': None
    }

    if not os.path.exists(pcap_file):
        result['error'] = f"Fichier introuvable: {pcap_file}"
        return result

    try:
        cap_info = subprocess.run(
            ['capinfos', '-M', pcap_file],
            capture_output=True, text=True, timeout=30
        )
        for line in cap_info.stdout.splitlines():
            if 'Number of packets' in line:
                m = re.search(r'(\d+)', line)
                if m:
                    result['total_packets'] = int(m.group(1))
            if 'Data size' in line:
                m = re.search(r'(\d+)\s*bytes', line)
                if m:
                    result['total_bytes'] = int(m.group(1))

        # QUIC retransmissions (spurious retransmissions)
        quic_retrans = subprocess.run(
            ['tshark', '-r', pcap_file, '-Y', 'quic.retransmission or tcp.analysis.retransmission',
             '-T', 'fields', '-e', 'frame.number'],
            capture_output=True, text=True, timeout=30
        )
        result['retransmissions'] = len([l for l in quic_retrans.stdout.splitlines() if l.strip()])

        # Connexions QUIC par Connection ID
        conns = subprocess.run(
            ['tshark', '-r', pcap_file, '-T', 'fields',
             '-e', 'quic.scid', '-e', 'frame.len'],
            capture_output=True, text=True, timeout=30
        )
        conn_bytes = defaultdict(int)
        conn_packets = defaultdict(int)
        for line in conns.stdout.splitlines():
            parts = line.split('\t')
            if len(parts) >= 2 and parts[0].strip():
                cid = parts[0].strip()
                try:
                    pkt_len = int(parts[1].strip())
                    conn_bytes[cid] += pkt_len
                    conn_packets[cid] += 1
                except ValueError:
                    continue

        result['bytes_per_conn'] = list(conn_bytes.values())
        result['packets_per_conn'] = list(conn_packets.values())

    except FileNotFoundError:
        result['error'] = "tshark/capinfos non installé"
    except subprocess.TimeoutExpired:
        result['error'] = "Timeout analyse pcap"
    except Exception as e:
        result['error'] = str(e)

    return result


def analyse_directory(results_dir, generate_plots=False):
    """Analyse un répertoire de résultats compression."""

    # Support new subfolder structure (nocompress/ + compressed/) and old flat layout
    csv_files = []
    pcap_files = []

    # Preferred: new structure with subfolders
    for sub in ["nocompress", "compressed"]:
        subdir = os.path.join(results_dir, sub)
        if os.path.isdir(subdir):
            csv_files += glob.glob(os.path.join(subdir, "compress_*_*.csv"))
            pcap_files += glob.glob(os.path.join(subdir, "capture_*_*.pcap"))

    # Fallback: old flat structure (for backward compatibility)
    if not csv_files:
        csv_files = glob.glob(os.path.join(results_dir, "compress_*_*.csv"))
        pcap_files = glob.glob(os.path.join(results_dir, "capture_*_*.pcap"))

    if not csv_files:
        print(f"[ERROR] Aucun fichier compress_*.csv trouvé dans {results_dir}")
        return None

    # Charger métadonnées
    meta = {}
    meta_files = glob.glob(os.path.join(results_dir, "metadata_*.txt"))
    for mf in meta_files:
        with open(mf, 'r') as f:
            for line in f:
                if '=' in line:
                    k, v = line.strip().split('=', 1)
                    meta[k] = v

    # Regrouper par (sig, kem, mode)
    groups = defaultdict(lambda: {'nocompress': None, 'compressed': None})

    for csv_file in csv_files:
        basename = os.path.basename(csv_file).replace('.csv', '')
        parts = basename.split('_')
        # Format: compress_{client_id}_{sig}_{kem}_{mode}.csv
        if len(parts) >= 5:
            sig_alg = parts[2]
            kem_alg = '_'.join(parts[3:-1])
            mode = parts[-1]
            key = (sig_alg, kem_alg)
            groups[key][mode] = csv_file

    # Associer les pcap
    pcap_map = {}
    for pf in pcap_files:
        basename = os.path.basename(pf).replace('.pcap', '')
        parts = basename.split('_')
        if len(parts) >= 5:
            sig_alg = parts[2]
            kem_alg = '_'.join(parts[3:-1])
            mode = parts[-1]
            pcap_map[(sig_alg, kem_alg, mode)] = pf

    all_results = []
    protocol = meta.get('protocol', '?')

    for (sig, kem), modes in sorted(groups.items()):
        print(f"\n{'='*70}")
        print(f"  {sig} × {kem}")
        print(f"{'='*70}")

        row = {'sig_alg': sig, 'kem_alg': kem}

        for mode_label, mode_key in [('Sans compression', 'nocompress'), ('Avec compression', 'compressed')]:
            csv_file = modes.get(mode_key)
            if not csv_file:
                print(f"  {mode_label}: DONNÉES MANQUANTES")
                continue

            durations, successes = load_duration_csv(csv_file)
            stats = compute_stats(durations)
            success_rate = sum(successes) / len(successes) * 100 if successes else 0

            # Analyse pcap
            pcap_key = (sig, kem, mode_key)
            pcap_file = pcap_map.get(pcap_key)
            if pcap_file:
                if protocol == 'quic':
                    pcap_info = analyse_pcap_quic(pcap_file)
                else:
                    pcap_info = analyse_pcap_tls(pcap_file)
            else:
                pcap_info = {'error': 'Pas de pcap', 'total_bytes': 0, 'total_packets': 0,
                            'retransmissions': 0, 'bytes_per_conn': [], 'packets_per_conn': []}

            avg_bytes_per_conn = np.mean(pcap_info['bytes_per_conn']) if pcap_info['bytes_per_conn'] else 0
            avg_packets_per_conn = np.mean(pcap_info['packets_per_conn']) if pcap_info['packets_per_conn'] else 0

            print(f"\n  {mode_label}:")
            print(f"    Durée  — médiane: {stats['median']:.2f} ms  p95: {stats['p95']:.2f} ms  p99: {stats['p99']:.2f} ms")
            print(f"    Succès — {success_rate:.1f}% ({sum(successes)}/{len(successes)})")
            print(f"    Pcap   — {pcap_info['total_packets']} paquets, {pcap_info['total_bytes']} bytes totaux")
            print(f"    Connex — {avg_bytes_per_conn:.0f} bytes/conn, {avg_packets_per_conn:.0f} pkts/conn (moy)")
            print(f"    Retrans— {pcap_info['retransmissions']} retransmissions")
            if pcap_info.get('error'):
                print(f"    [WARN] {pcap_info['error']}")

            row[mode_key] = {
                'stats': stats,
                'success_rate': success_rate,
                'pcap': pcap_info,
                'avg_bytes_per_conn': avg_bytes_per_conn,
                'avg_packets_per_conn': avg_packets_per_conn,
            }

        # Calculer les gains
        if row.get('nocompress') and row.get('compressed'):
            nc = row['nocompress']
            c = row['compressed']

            def gain_pct(nc_val, c_val):
                if nc_val and c_val and nc_val > 0:
                    return (nc_val - c_val) / nc_val * 100
                return None

            print(f"\n  ── GAINS (compression vs sans) ──")
            g_median = gain_pct(nc['stats']['median'], c['stats']['median'])
            g_p95 = gain_pct(nc['stats']['p95'], c['stats']['p95'])
            g_bytes = gain_pct(nc['avg_bytes_per_conn'], c['avg_bytes_per_conn'])
            g_pkts = gain_pct(nc['avg_packets_per_conn'], c['avg_packets_per_conn'])
            g_retrans = gain_pct(nc['pcap']['retransmissions'], c['pcap']['retransmissions'])

            print(f"    Durée médiane : {g_median:+.1f}%")
            print(f"    Durée P95     : {g_p95:+.1f}%")
            print(f"    Bytes/conn    : {g_bytes:+.1f}%")
            print(f"    Paquets/conn  : {g_pkts:+.1f}%")
            print(f"    Retransmissions: {g_retrans:+.1f}%")

            row['gains'] = {
                'median_pct': g_median,
                'p95_pct': g_p95,
                'bytes_per_conn_pct': g_bytes,
                'packets_per_conn_pct': g_pkts,
                'retransmissions_pct': g_retrans,
            }

        all_results.append(row)

    # ── Sauvegarder résumé CSV ──────────────────────────────────────────
    summary_csv = os.path.join(results_dir, "summary_compress.csv")
    with open(summary_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'sig_alg', 'kem_alg',
            'nc_median_ms', 'nc_p95_ms', 'nc_p99_ms', 'nc_success_rate',
            'nc_bytes_per_conn', 'nc_packets_per_conn', 'nc_retrans',
            'c_median_ms', 'c_p95_ms', 'c_p99_ms', 'c_success_rate',
            'c_bytes_per_conn', 'c_packets_per_conn', 'c_retrans',
            'gain_median_pct', 'gain_bytes_pct', 'gain_packets_pct', 'gain_retrans_pct'
        ])
        for r in all_results:
            nc = r.get('nocompress', {})
            c = r.get('compressed', {})
            g = r.get('gains', {})
            writer.writerow([
                r['sig_alg'], r['kem_alg'],
                f"{nc.get('stats', {}).get('median', 'N/A')}", f"{nc.get('stats', {}).get('p95', 'N/A')}",
                f"{nc.get('stats', {}).get('p99', 'N/A')}", f"{nc.get('success_rate', 'N/A')}",
                f"{nc.get('avg_bytes_per_conn', 'N/A'):.0f}" if nc.get('avg_bytes_per_conn') else 'N/A',
                f"{nc.get('avg_packets_per_conn', 'N/A'):.0f}" if nc.get('avg_packets_per_conn') else 'N/A',
                nc.get('pcap', {}).get('retransmissions', 'N/A'),
                f"{c.get('stats', {}).get('median', 'N/A')}", f"{c.get('stats', {}).get('p95', 'N/A')}",
                f"{c.get('stats', {}).get('p99', 'N/A')}", f"{c.get('success_rate', 'N/A')}",
                f"{c.get('avg_bytes_per_conn', 'N/A'):.0f}" if c.get('avg_bytes_per_conn') else 'N/A',
                f"{c.get('avg_packets_per_conn', 'N/A'):.0f}" if c.get('avg_packets_per_conn') else 'N/A',
                c.get('pcap', {}).get('retransmissions', 'N/A'),
                f"{g.get('median_pct', 'N/A')}" if g.get('median_pct') is not None else 'N/A',
                f"{g.get('bytes_per_conn_pct', 'N/A')}" if g.get('bytes_per_conn_pct') is not None else 'N/A',
                f"{g.get('packets_per_conn_pct', 'N/A')}" if g.get('packets_per_conn_pct') is not None else 'N/A',
                f"{g.get('retransmissions_pct', 'N/A')}" if g.get('retransmissions_pct') is not None else 'N/A',
            ])
    print(f"\n[CSV] Résumé : {summary_csv}")

    # ── Plots ──────────────────────────────────────────────────────────
    if generate_plots:
        generate_plots_fn(results_dir, all_results, meta)

    return all_results


def generate_plots_fn(results_dir, all_results, meta):
    """Génère les graphiques compression vs sans."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        print("[PLOTS] matplotlib non disponible.")
        return

    for r in all_results:
        sig, kem = r['sig_alg'], r['kem_alg']
        nc = r.get('nocompress')
        c = r.get('compressed')
        if not nc or not c:
            continue

        # Recharger les durées
        nc_dur = []
        c_dur = []
        for mode_key, mode_data in [('nocompress', nc), ('compressed', c)]:
            csv_pattern = os.path.join(results_dir, f"compress_*_{sig}_{kem}_{mode_key}.csv")
            for cf in glob.glob(csv_pattern):
                dur, _ = load_duration_csv(cf)
                if mode_key == 'nocompress':
                    nc_dur = dur
                else:
                    c_dur = dur

        fig, axes = plt.subplots(2, 2, figsize=(14, 10))

        # 1. Boxplot durées
        data = [nc_dur, c_dur] if nc_dur and c_dur else [[0], [0]]
        bp = axes[0, 0].boxplot(data, labels=['Sans compression', 'Avec compression'],
                               patch_artist=True, showfliers=False)
        bp['boxes'][0].set_facecolor('#ffcccc')
        bp['boxes'][1].set_facecolor('#ccccff')
        axes[0, 0].set_ylabel('Handshake Duration (ms)')
        axes[0, 0].set_title(f'{sig} × {kem} — Durée handshake')
        axes[0, 0].grid(True, alpha=0.3)

        # 2. Bytes par connexion
        nc_bytes = nc.get('pcap', {}).get('bytes_per_conn', [])
        c_bytes = c.get('pcap', {}).get('bytes_per_conn', [])
        if nc_bytes and c_bytes:
            axes[0, 1].bar(['Sans compression', 'Avec compression'],
                          [np.mean(nc_bytes), np.mean(c_bytes)],
                          color=['#ffcccc', '#ccccff'], edgecolor='black')
            axes[0, 1].set_ylabel('Bytes par connexion (moy)')
            axes[0, 1].set_title('Taille handshake')
            axes[0, 1].grid(True, alpha=0.3, axis='y')

        # 3. Paquets par connexion
        nc_pkts = nc.get('pcap', {}).get('packets_per_conn', [])
        c_pkts = c.get('pcap', {}).get('packets_per_conn', [])
        if nc_pkts and c_pkts:
            axes[1, 0].bar(['Sans compression', 'Avec compression'],
                          [np.mean(nc_pkts), np.mean(c_pkts)],
                          color=['#ffcccc', '#ccccff'], edgecolor='black')
            axes[1, 0].set_ylabel('Paquets par connexion (moy)')
            axes[1, 0].set_title('Nombre de paquets')
            axes[1, 0].grid(True, alpha=0.3, axis='y')

        # 4. Retransmissions
        nc_retrans = nc.get('pcap', {}).get('retransmissions', 0)
        c_retrans = c.get('pcap', {}).get('retransmissions', 0)
        axes[1, 1].bar(['Sans compression', 'Avec compression'],
                      [nc_retrans, c_retrans],
                      color=['#ffcccc', '#ccccff'], edgecolor='black')
        axes[1, 1].set_ylabel('Retransmissions')
        axes[1, 1].set_title('Retransmissions TCP')
        axes[1, 1].grid(True, alpha=0.3, axis='y')

        plt.tight_layout()
        plot_file = os.path.join(results_dir, f"plot_compress_{sig}_{kem}.pdf")
        plt.savefig(plot_file, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"[PLOT] {plot_file}")

    # ── Résumé global ──────────────────────────────────────────────────
    if len(all_results) > 1:
        fig, ax = plt.subplots(figsize=(12, 6))
        labels = []
        gains_median = []
        gains_bytes = []
        for r in all_results:
            g = r.get('gains', {})
            if g:
                labels.append(f"{r['sig_alg']}\n× {r['kem_alg']}")
                gains_median.append(g.get('median_pct', 0) or 0)
                gains_bytes.append(g.get('bytes_per_conn_pct', 0) or 0)

        if labels:
            x = np.arange(len(labels))
            width = 0.35
            ax.bar(x - width/2, gains_median, width, label='Gain durée médiane', color='#6699cc', edgecolor='black')
            ax.bar(x + width/2, gains_bytes, width, label='Gain bytes/connexion', color='#99cc66', edgecolor='black')
            ax.axhline(y=0, color='black', linewidth=0.8)
            ax.set_ylabel('Gain (%)')
            ax.set_title(f'Impact compression certificat — {meta.get("protocol", "?").upper()} ({meta.get("network_profile", "?")})')
            ax.set_xticks(x)
            ax.set_xticklabels(labels)
            ax.legend()
            ax.grid(True, alpha=0.3, axis='y')

            plt.tight_layout()
            plot_file = os.path.join(results_dir, "plot_compress_summary.pdf")
            plt.savefig(plot_file, dpi=150, bbox_inches='tight')
            plt.close()
            print(f"[PLOT] {plot_file}")


def main():
    parser = argparse.ArgumentParser(description='Analyse compression certificat')
    parser.add_argument('results_dir', help='Répertoire contenant les fichiers compress_*.csv et capture_*.pcap')
    parser.add_argument('--plots', action='store_true', help='Générer les graphiques')
    parser.add_argument('--all', action='store_true', help='Analyser tous les runs dans le répertoire results/')
    args = parser.parse_args()

    if not os.path.isdir(args.results_dir):
        print(f"[ERROR] Répertoire introuvable : {args.results_dir}")
        sys.exit(1)

    if args.all:
        # Mode multi-runs : on cherche tous les sous-dossiers qui contiennent nocompress/ ou compressed/
        run_dirs = []
        for entry in sorted(os.listdir(args.results_dir)):
            full = os.path.join(args.results_dir, entry)
            if os.path.isdir(full) and (os.path.isdir(os.path.join(full, "nocompress")) or os.path.isdir(os.path.join(full, "compressed"))):
                run_dirs.append(full)

        if not run_dirs:
            print("[INFO] Aucun run avec structure nocompress/compressed trouvé.")
            sys.exit(0)

        print(f"[INFO] Analyse de {len(run_dirs)} run(s) trouvés...")
        for rd in run_dirs:
            print(f"\n=== {os.path.basename(rd)} ===")
            analyse_directory(rd, generate_plots=args.plots)
    else:
        analyse_directory(args.results_dir, generate_plots=args.plots)


if __name__ == '__main__':
    main()
