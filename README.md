# ML-DSA × ML-KEM — TLS/QUIC Concurrent Load Performance

> Study 1: Impact of concurrent clients on post-quantum TLS 1.3 and QUIC handshakes
> ~340,000 handshakes | 500 runs/client | 3 network scenarios calibrated from Yaoundé, Cameroon

---

## Overview

This study measures how **ML-DSA** (FIPS 204) combined with **ML-KEM** (FIPS 203) performs under **concurrent client load** in TLS 1.3 and QUIC. We test 10, 50, and 100 simultaneous clients to quantify the head-of-line blocking penalty in TLS versus QUIC's stream multiplexing.

**Key finding:** TLS handshake latency explodes under concurrency (up to **110× worse than QUIC** at 100 clients / 200ms RTT), while QUIC remains stable regardless of client count.

---

## Environment & Reproducibility

### Hardware
| Component | Specification |
|-----------|--------------|
| CPU | Intel Xeon E-2288G (8 cores @ 3.7 GHz, AVX2) |
| RAM | 64 GB DDR4 ECC |
| OS | Ubuntu 24.10 (Oracular) |
| Docker | 26.x with buildx |

### Software Stack
| Component | Version | Notes |
|-----------|---------|-------|
| liboqs | 0.12.0 | Post-quantum crypto library |
| OpenSSL | 3.4.0 | Fork with OQS provider support |
| oqs-provider | 0.8.0 | OpenSSL ↔ liboqs bridge |
| MsQuic | 2.4.x | Microsoft QUIC implementation (PQ fork) |
| Pumba | 0.10.x | Network impairment (tc netem wrapper) |

### Network Scenarios
| Scenario | RTT | Packet Loss | Source |
|----------|-----|-------------|--------|
| **Ideal** | 0 ms | 0% | Baseline (localhost Docker) |
| **Local YDE** | 35 ms | 2% | Measured at ENSP Yaoundé, Orange Cameroon (Apr 2026) |
| **Degraded** | 200 ms | 10% | Worst-case backbone link |

### Algorithm Pairs Tested
| Security Level | Signature | KEM |
|---------------|-----------|-----|
| NIST L1 | ML-DSA44 | ML-KEM512 |
| NIST L3 | ML-DSA65 | ML-KEM768 |
| NIST L5 | ML-DSA87 | ML-KEM1024 |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/TOLOKOUM/mldsa-mlkem-hqc-tls-quic-performance.git
cd mldsa-mlkem-hqc-tls-quic-performance

# 2. Build Docker image (~15 min)
cd 0-docker && docker build -t uma-tls-quic-pq-34 . && cd ..

# 3. Run a single test (10 clients, TLS, ideal)
./Launcherv3_concurrent.sh tls 10 none 0 0

# 4. Run full matrix (18 runs, ~2-3 hours)
./run_concurrent_matrix.sh --resume

# 5. Analyze results
python3 concurrent/compare_concurrent.py results/
```

---

## Project Structure

```
├── 0-docker/
│   ├── Dockerfile                          # Multi-stage build (liboqs + OpenSSL + MsQuic)
│   └── scripts/
│       ├── doCert.sh                       # Certificate generation (ML-DSA)
│       ├── perftestServerTlsQuic.sh        # Server (TLS or QUIC)
│       └── perftestClientConcurrent.sh     # Client (500 handshakes, CSV output)
├── concurrent/
│   ├── analyse_concurrent.py               # Per-run analysis (stats + plots)
│   └── compare_concurrent.py               # Cross-run comparison (CSV + plots)
├── Launcherv3_concurrent.sh                # Single-run launcher
├── run_concurrent_matrix.sh                # Full matrix launcher (18 runs)
├── results/                                # All test outputs
│   ├── comparison_concurrent.csv           # Aggregated results
│   └── comparison_*.pdf                    # Per-scenario plots
└── README.md
```

---

## How It Works

### Test Flow
1. **Certificate generation**: `doCert.sh` creates ML-DSA certificates for the chosen security level
2. **Server startup**: `perftestServerTlsQuic.sh` starts an OpenSSL TLS 1.3 or MsQuic server
3. **Network impairment**: `tc netem` applies RTT delay and packet loss on the server interface
4. **Concurrent clients**: N Docker containers launch simultaneously, each performing 500 handshakes
5. **Data collection**: Each client writes a CSV with `run_id, duration_ms, success` per handshake

### Metrics Collected
| Metric | Source | Description |
|--------|--------|-------------|
| `duration_ms` | Client CSV | Wall-clock time per handshake |
| `success` | Client CSV | 1 = completed, 0 = failed |
| `success_rate` | Aggregated | % of successful handshakes |
| `median, p95, p99` | Analysis | Latency percentiles |

### TLS Handshake (1-RTT)
```
Client                                  Server
  |-------- ClientHello (ML-KEM768) ------>|
  |<---- ServerHello + Certificate -------|  (ML-DSA65 signature)
  |-------- Finished --------------------->|
```

### QUIC Handshake (0-RTT after first)
```
Client                                  Server
  |-------- Initial (ML-KEM768) ---------->|
  |<---- Handshake + Certificate ---------|  (ML-DSA65 signature)
  |-------- Handshake Finished ----------->|
```

---

## Results Summary

### ML-DSA65 × ML-KEM768 (NIST L3)

| Clients | Scenario | TLS Median | QUIC Median | TLS/QUIC Ratio |
|---------|----------|-----------|-------------|----------------|
| 10 | Ideal (0ms/0%) | 8.9 ms | 5.3 ms | 1.7× |
| 10 | 35ms/2% | 460 ms | 81 ms | 5.7× |
| 10 | 200ms/10% | 4,753 ms | 419 ms | 11.3× |
| 50 | Ideal (0ms/0%) | 158 ms | 31 ms | 5.1× |
| 50 | 35ms/2% | 2,619 ms | 99 ms | 26.5× |
| 50 | 200ms/10% | 23,612 ms | 420 ms | 56.2× |
| 100 | Ideal (0ms/0%) | 516 ms | 41 ms | 12.6× |
| 100 | 35ms/2% | 5,528 ms | 123 ms | 44.9× |
| 100 | 200ms/10% | 47,685 ms | 432 ms | **110.4×** |

> All handshakes 100% successful. TLS suffers from TCP head-of-line blocking under concurrent load; QUIC multiplexes streams over UDP and remains stable.

---

## Reproducing Results

### Prerequisites
- Docker 24+ with `--cap-add=NET_ADMIN` support
- ~20 GB free disk space (Docker image + results)
- Linux kernel 5.4+ (for `tc netem`)

### Step-by-step

```bash
# 1. Build
cd 0-docker
docker build -t uma-tls-quic-pq-34 .
cd ..

# 2. Full matrix (18 runs, ~2-3 hours)
./run_concurrent_matrix.sh --resume

# 3. Analyze
python3 -m pip install numpy matplotlib
python3 concurrent/compare_concurrent.py results/
```

### Expected outputs
```
results/
├── tls_c10_none_l0_d0_YYYYMMDD_HHMMSS/    # 10 client CSVs
├── tls_c10_simple_l2_d35_YYYYMMDD_HHMMSS/
├── ... (18 directories total)
├── comparison_concurrent.csv               # Aggregated table
├── comparison_tls_none_l0_d0.pdf           # Per-scenario plots
└── ...
```

### Validation
To verify the setup works correctly:
```bash
# Quick smoke test (~1 minute)
./Launcherv3_concurrent.sh tls 10 none 0 0
# Expected: 10 clients × 500 handshakes, median ~8-10 ms, 100% success
```

---

## License

MIT — See LICENSE file.

## Citation

```bibtex
@misc{tolokoum2026mldsa-concurrent,
  title={Impact of Concurrent Load on Post-Quantum TLS 1.3 and QUIC Handshakes},
  author={Tolokoum, Bruno and others},
  year={2026},
  note={ENSP Yaoundé — University of Málaga}
}
```

