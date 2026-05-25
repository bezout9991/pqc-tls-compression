#!/usr/bin/env python3
"""Full vs Resumed — 4 scenarios (Ideal, 35ms, 200ms, GE stable)."""
import os, csv, sys, statistics
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({
    'font.family': 'serif', 'font.size': 10,
    'axes.titlesize': 11, 'axes.labelsize': 10,
    'figure.dpi': 150, 'savefig.dpi': 300,
    'axes.spines.top': False, 'axes.spines.right': False,
})

RESULTS_DIR = sys.argv[1] if len(sys.argv) > 1 else "results"

def analyze_csv(fp):
    full, resumed = [], []
    with open(fp) as f:
        for r in csv.DictReader(f):
            if r['success'] != '1' or not r['duration_ms']: continue
            t = float(r['duration_ms'])
            (full if r['handshake_type'] == 'full' else resumed).append(t)
    return full, resumed

def s(times):
    if not times: return None
    x = sorted(times); n = len(x)
    return {'n': n, 'med': statistics.median(times), 'avg': statistics.mean(times),
            'p95': x[int(n*0.95)], 'p99': x[int(n*0.99)] if n > 100 else x[-1]}

data = {}
for root, _, files in os.walk(RESULTS_DIR):
    for f in files:
        if not f.startswith('resumption_') or not f.endswith('.csv'): continue
        fp = os.path.join(root, f)
        p = f.replace('.csv','').split('_')
        sig, kem = p[2], p[3]
        dn = os.path.basename(root).split('_')
        if len(dn) < 5: continue
        proto = dn[0]; profile = dn[1]; loss = dn[2].replace('l',''); delay = dn[3].replace('d','')
        ft, rt = analyze_csv(fp)
        fs = s(ft)
        if not fs or fs['n'] == 0: continue
        key = (proto, delay, loss, profile, sig, kem)
        if key not in data: data[key] = {'full': [], 'resumed': []}
        data[key]['full'] += ft
        data[key]['resumed'] += rt

rows = []
for (proto, delay, loss, profile, sig, kem), d in sorted(data.items()):
    fs = s(d['full']); rs = s(d['resumed']) if d['resumed'] else None
    ratio = round(fs['med'] / rs['med'], 1) if rs and rs['med'] > 0 else 0
    rows.append((proto, delay, loss, profile, sig, kem, fs, rs, ratio))

# Filter mldsa65 x mlkem768
T = ('mldsa65', 'mlkem768')
flt = [(p,d,l,pr,s,k,fs,rs,r) for (p,d,l,pr,s,k,fs,rs,r) in rows if s == T[0] and k == T[1]]

# Figure: 2 panels
lbl = ['Ideal', '35 ms / 2%', '200 ms / 10%']
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

quic_r = [(d,pr,fs,rs,r) for (p,d,l,pr,s,k,fs,rs,r) in flt if p == 'quic' and pr != 'stable']
quic_r.sort(key=lambda x: int(x[0]))
x = np.arange(3); w = 0.35
fq = [fs['med'] for _,_,fs,_,_ in quic_r]
rq = [rs['med'] if rs else 0 for _,_,_,rs,_ in quic_r]
ax1.bar(x - w/2, fq, w, color='#4472C4', label='Full')
ax1.bar(x + w/2, rq, w, color='#ED7D31', label='Resumed')
for i, (fv, rv) in enumerate(zip(fq, rq)):
    ax1.text(i - w/2, fv + 8, f'{fv:.0f}', ha='center', fontsize=7, fontweight='bold')
    if rv > 0:
        ax1.text(i + w/2, rv + 8, f'{rv:.0f}', ha='center', fontsize=7, fontweight='bold')
ax1.set_xticks(x); ax1.set_xticklabels(lbl, fontsize=9)
ax1.set_ylabel('Duration (ms)'); ax1.set_title('QUIC — Full vs Resumed')
ax1.legend(frameon=False, fontsize=9)

tls_r = [(d,pr,fs,rs,r) for (p,d,l,pr,s,k,fs,rs,r) in flt if p == 'tls' and pr != 'stable']
tls_r.sort(key=lambda x: (0 if x[1]=='none' else 1 if x[1]=='simple' else 2, int(x[0])))
ft = [fs['med'] for _,_,fs,_,_ in tls_r]
ax2.bar(x - w/2, ft, w, color='#70AD47', label='TLS 1.3')
ax2.bar(x + w/2, fq, w, color='#4472C4', label='QUIC')
for i, (tv, qv) in enumerate(zip(ft, fq)):
    ax2.text(i - w/2, tv + 8, f'{tv:.0f}', ha='center', fontsize=7, fontweight='bold')
    ax2.text(i + w/2, qv + 8, f'{qv:.0f}', ha='center', fontsize=7, fontweight='bold')
ax2.set_xticks(x); ax2.set_xticklabels(lbl, fontsize=9)
ax2.set_ylabel('Duration (ms)'); ax2.set_title('TLS 1.3 vs QUIC — Full Handshake')
ax2.legend(frameon=False, fontsize=9)

fig.suptitle('ML-DSA 65 x ML-KEM 768 — Session Resumption', fontsize=13, fontweight='bold', y=1.02)
fig.tight_layout()
for ext in ['pdf', 'svg']:
    fig.savefig(os.path.join(RESULTS_DIR, f'comparison_resumption.{ext}'),
                bbox_inches='tight', pad_inches=0.1)
plt.close()

# CSV
csv_file = os.path.join(RESULTS_DIR, 'comparison_resumption.csv')
with open(csv_file, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=['proto','profile','delay','loss','sig','kem',
        'full_med','full_avg','full_p95','full_p99',
        'resumed_med','resumed_avg','resumed_p95','resumed_p99',
        'ratio','full_n','resumed_n'])
    w.writeheader()
    for p,d,l,pr,s,k,fs,rs,r in rows:
        if pr == 'stable': continue
        w.writerow({'proto':p,'profile':pr,'delay':d,'loss':l,'sig':s,'kem':k,
            'full_med':fs['med'],'full_avg':round(fs['avg'],2),'full_p95':fs['p95'],'full_p99':fs['p99'],
            'resumed_med':rs['med'] if rs else '','resumed_avg':round(rs['avg'],2) if rs else '',
            'resumed_p95':rs['p95'] if rs else '','resumed_p99':rs['p99'] if rs else '',
            'ratio':r,'full_n':fs['n'],'resumed_n':rs['n'] if rs else 0})

print(f"✅ {len(rows)} rows → {csv_file}")
print(f"✅ Plots → {RESULTS_DIR}/comparison_resumption.pdf")
