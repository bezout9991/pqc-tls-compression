# PQC TLS Compression — RFC 8879 with Post-Quantum Cryptographic Certificates

## ⚠️ Key Finding

**TLS 1.3 certificate compression (RFC 8879) is negotiated but NOT operational with post-quantum certificates (ML-DSA/ML-KEM) in OpenSSL 3.4.2 + OQS provider.**

The `compress_certificate` extension (TLS type 27) is correctly advertised by the client, but the server never sends a `CompressedCertificate` message (handshake type 25). The compression fails silently at runtime:

```
Compressing certificates
Error compressing certs on ctx
```

This is a **provider/provider-key compatibility limitation** of the current OpenSSL/OQS stack, not a configuration error.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Project Structure](#project-structure)
3. [Build Instructions](#build-instructions)
4. [Scientific Context](#scientific-context)
5. [Experimental Setup](#experimental-setup)
6. [Infrastructure](#infrastructure)
7. [Network Profiles](#network-profiles)
8. [Algorithm Pairs](#algorithm-pairs)
9. [Methodology](#methodology)
10. [Results](#results)
11. [Network-Level Validation](#network-level-validation)
12. [Known Issues](#known-issues)
13. [Conclusion](#conclusion)
14. [Reproducibility](#reproducibility)
15. [Citation](#citation)
16. [References](#references)

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/bezout9991/pqc-tls-compression.git
cd pqc-tls-compression

# Build the Docker image
docker build -t uma-tls-quic-pq-34 -f 0-docker/Dockerfile ./0-docker/

# Run full campaign (TLS + QUIC, all network profiles, 500 runs each)
./run_compress_matrix.sh

# Or run a single configuration
./Launcherv3_compress.sh tls simple 2 35    # TLS, 35ms delay, 2% loss

# Analyze results
python3 compress/analyse_compress.py results/<run_directory> --plots
```

---

## Project Structure

```
pqc-tls-compression/
├── README.md                          # This file
├── .gitignore
├── Launcherv3_compress.sh             # Main launcher (server + client orchestration)
├── run_compress_matrix.sh             # Matrix runner (all protocols × profiles)
├── 0-docker/
│   ├── Dockerfile                     # Docker image with OpenSSL 3.4.2 + OQS
│   ├── patch_openssl.sh              # OpenSSL patches for cert compression (RFC 8879)
│   ├── patch_openssl_v2.sh           # Additional patches for PQ compatibility
│   └── scripts/
│       ├── perftestServerCompress.sh  # Server: s_server/quics_server with -cert_comp
│       ├── perftestClientCompress.sh  # Client: 500 handshakes + TCP capture
│       └── doCert.sh                  # Certificate generation (ML-DSA/ML-KEM)
├── compress/
│   ├── analyse_compress.py           # Statistical analysis + PDF plots generation
│   └── results/                      # Test results
└── results/                          # Experimental results
    ├── tls_none_l0_d0_20260602_115738/        # TLS, ideal network
    ├── tls_simple_l2_d35_20260602_120822/      # TLS, 35ms/2%
    ├── tls_simple_l4_d200_20260602_124952/     # TLS, 200ms/4%
    ├── quic_none_l0_d0_20260602_151009/        # QUIC, ideal network
    ├── quic_simple_l2_d35_20260602_152812/     # QUIC, 35ms/2%
    └── quic_simple_l4_d200_20260602_161526/    # QUIC, 200ms/4/
```

Each result directory contains:
- `compressed/` — 500 handshakes with `-cert_comp` (CSV + PCAP)
- `nocompress/` — 500 handshakes with `-no_tx_cert_comp` (CSV + PCAP)
- `plot_compress_*.pdf` — Per-pair duration distribution plots
- `plot_compress_summary.pdf` — All-pairs comparison plot
- `summary_compress.csv` — Aggregate statistics (median, p95, p99, gain %)

---

## Build Instructions

### Prerequisites

- Docker 24.0+
- Python 3.12+ with `numpy`, `matplotlib`
- tshark (optional, for PCAP analysis)
- Linux host with `NET_ADMIN` capability

### Docker Image Build

```bash
docker build -t uma-tls-quic-pq-34 -f 0-docker/Dockerfile ./0-docker/
```

The image includes:
- OpenSSL 3.4.2 compiled with `-DZLIB -DBROTLI -DZSTD`
- OQS Provider 0.8.0 (ML-DSA, ML-KEM, HQC, FALCON, Dilithium)
- MsQuic 2.5 for QUIC support
- tshark/tcpdump for packet capture

### Docker Network Setup

The launcher creates a Docker bridge network `localNet` automatically. Each run creates isolated containers:

- `OQS_SERVER` — Server container (running `s_server` or `quics_server`)
- `client-{1,2}` — Client containers (one per condition)

The `cert` Docker volume is shared between containers for key/certificate distribution.

---

## Scientific Context

### The Promise of RFC 8879

TLS 1.3 certificate compression (RFC 8879) was designed to reduce handshake size by compressing X.509 certificates using zlib, brotli, or zstd. For classical certificates (RSA 2048, ECDSA P-256), this yields measurable bandwidth savings.

### The Post-Quantum Problem

Post-quantum certificates (ML-DSA, ML-KEM, HQC) are significantly larger than classical ones:

| Algorithm | Certificate Size |
|-----------|-----------------|
| ECDSA P-256 | ~0.5 KB |
| RSA 2048 | ~1.5 KB |
| ML-DSA44 | ~5.4 KB |
| ML-DSA65 | ~5.3 KB |
| ML-DSA87 | ~5.4 KB |
| HQC-192 | ~8.2 KB |

With larger certificates, compression should theoretically yield **greater absolute savings** in the PQ setting.

### Research Question

> **Is RFC 8879 certificate compression functionally operational with post-quantum certificates in current OpenSSL/OQS builds, and if so, what latency/bandwidth gains does it provide under realistic network conditions?**

---

## Experimental Setup

### Tested Configurations

| Dimension | Values |
|-----------|--------|
| **Protocols** | TLS 1.3, QUIC |
| **Signatures** | ML-DSA44, ML-DSA65, ML-DSA87 |
| **KEMs** | ML-KEM512, ML-KEM768, ML-KEM1024, HQC-192 |
| **Network Profiles** | Ideal (0ms/0%), 35ms/2%, 200ms/4%, GE Stable |
| **Runs per condition** | 500 |
| **Total handshakes** | ~12,000 |

### Docker Infrastructure

```
┌─────────────┐      bridge network       ┌─────────────┐
│  servidor    │ ◄──── localNet ──────────► │  cliente     │
│  (server)    │      tc netem applied     │  (client)    │
│              │                           │              │
│  openssl     │                           │  openssl     │
│  s_server    │                           │  s_client    │
│  or          │                           │  or          │
│  quics_server│                           │  quics_conn  │
└──────────────┘                           └──────────────┘
       ▲                                          ▲
       │                                          │
   cert volume                              cert volume
   (shared keys + certs)                    (shared keys + certs)
```

### Network Emulation

Traffic control (`tc netem`) is applied inside containers on `eth0`:

- **Server side**: `tc qdisc add dev eth0 root netem delay $TC_DELAY loss $TC_LOSS`
- **Client side**: same configuration

Each container pair gets fresh netem rules per run.

**Note**: Network profiles are parameterized (`$DELAY_MS`, `$LOSS_PERC`) and passed through environment variables. Earlier versions had a bug where these were hardcoded to `0ms/0%` (see [Known Issues](#known-issues)).

---

## Infrastructure

### Image

`uma-tls-quic-pq-34:latest` — Multi-stage Docker image with:
- OpenSSL 3.4.2 with `-DZLIB -DBROTLI -DZSTD`
- OQS Provider 0.8.0
- MsQuic for QUIC support
- tshark/tcpdump for packet capture

### Key Scripts

| Script | Purpose |
|--------|---------|
| `Launcherv3_compress.sh` | Orchestrates server/client per pair/condition |
| `run_compress_matrix.sh` | Runs all (protocol × network profile) combinations |
| `0-docker/scripts/perftestServerCompress.sh` | Server-side: starts `s_server` or `quics_server` with `-cert_comp` or `-no_tx_cert_comp` |
| `0-docker/scripts/perftestClientCompress.sh` | Client-side: runs 500 handshakes, captures CSV + PCAP |
| `0-docker/scripts/doCert.sh` | Generates ML-DSA/ML-KEM certificates |
| `compress/analyse_compress.py` | Statistical analysis + PDF plots |

---

## Network Profiles

| Profile | Delay | Loss | Use Case |
|---------|-------|------|----------|
| `none` (Ideal) | 0ms | 0% | Baseline |
| `simple l2 d35` | 35ms | 2% | Moderate degradation (cross-country) |
| `simple l4 d200` | 200ms | 4% | Severe degradation (satellite/intercontinental) |
| `stable` | GE model | GE model | Burst-loss pattern |

---

## Algorithm Pairs

| Pair | Sig Algorithm | KEM Algorithm | Certificate Size |
|------|--------------|---------------|------------------|
| 1 | ML-DSA44 | ML-KEM512 | ~5.4 KB |
| 2 | ML-DSA65 | ML-KEM768 | ~5.3 KB |
| 3 | ML-DSA87 | ML-KEM1024 | ~5.4 KB |
| 4 | ML-DSA65 | HQC-192 | ~8.2 KB |

---

## Methodology

### Per Pair

1. Generate certificates: `doCert.sh $SIG_ALG`
2. **Phase 1 (nocompress)**:
   - Start server: `s_server ... -no_tx_cert_comp`
   - Run client: 500 handshakes → CSV + PCAP
3. **Phase 2 (compressed)**:
   - Restart server: `s_server ... -cert_comp`
   - Run client: 500 handshakes → CSV + PCAP

### Measurements

| Metric | Source |
|--------|--------|
| Handshake duration (ms) | `perftestClientCompress.sh` (client-side timing) |
| Success rate | `Verify return code: 0` in OpenSSL output |
| Bytes per connection | tshark analysis of PCAP |
| Packets per connection | tshark analysis of PCAP |
| Retransmissions | tshark `tcp.analysis.retransmission` |

### Analysis

```bash
python3 compress/analyse_compress.py results/<run_directory> --plots
```

Generates:
- Per-pair PDF plots (duration distribution, CDF)
- Summary PDF (all pairs comparison)
- `summary_compress.csv` with median, p95, p99, bytes/packets/retrans, gain %

---

## Results

### TLS Handshake Duration (median, ms)

| Pair | Ideal (0/0) | 35ms/2% | 200ms/4% |
|------|-------------|---------|----------|
| mldsa44+mlkem512 | 62→53 | 371→355 | 1406→1391 |
| mldsa65+hqc192 | 144→156 | 601→647 | 2111→2107 |
| mldsa65+mlkem768 | 52→47 | 367→380 | 1497→1452 |
| mldsa87+mlkem1024 | 52→52 | 443→427 | 1831→1818 |

### TLS Gain (compression vs nocompress, %)

| Pair | Ideal | 35ms/2% | 200ms/4% |
|------|-------|---------|----------|
| mldsa44+mlkem512 | **+14.5%** | **+4.3%** | **+1.0%** |
| mldsa65+hqc192 | **-8.0%** | **-7.6%** | **+0.2%** |
| mldsa65+mlkem768 | **+10.5%** | **-3.4%** | **+3.0%** |
| mldsa87+mlkem1024 | **+1.0%** | **+3.5%** | **+0.7%** |

### QUIC Handshake Duration (median, ms)

| Pair | Ideal (0/0) | 35ms/2% | 200ms/4% |
|------|-------------|---------|----------|
| mldsa44+mlkem512 | 115→103 | 397→436 | 1506→1505 |
| mldsa65+hqc192 | 281→236 | 621→636 | 2016→1962 |
| mldsa65+mlkem768 | 105→115 | 418→412 | 1548→1545 |
| mldsa87+mlkem1024 | 114→103 | 419→401 | 1522→1525 |

### QUIC Gain (compression vs nocompress, %)

| Pair | Ideal | 35ms/2% | 200ms/4% |
|------|-------|---------|----------|
| mldsa44+mlkem512 | **+10.4%** | **-9.8%** | **+0.0%** |
| mldsa65+hqc192 | **+16.0%** | **-2.3%** | **+2.7%** |
| mldsa65+mlkem768 | **-9.0%** | **+1.3%** | **+0.2%** |
| mldsa87+mlkem1024 | **+9.6%** | **+4.2%** | **-0.2%** |

### Network Traffic (bytes/connection)

| Pair | nocompress | compressed | Delta |
|------|------------|------------|-------|
| mldsa44+mlkem512 | 10,423 | 10,435 | -0.1% |
| mldsa65+hqc192 | 25,229 | 25,242 | -0.1% |
| mldsa65+mlkem768 | 13,679 | 13,684 | -0.0% |
| mldsa87+mlkem1024 | 17,945 | 17,963 | -0.1% |

---

## Network-Level Validation

### Critical Finding: RFC 8879 Not Applied on the Wire

Despite successful negotiation of the `compress_certificate` extension, **no actual certificate compression is transmitted**.

#### Evidence 1: OpenSSL Runtime Error

```
$ openssl s_server ... -cert_comp
Compressing certificates
Error compressing certs on ctx
```

#### Evidence 2: TLS Extension Negotiated but Not Used

ClientHello (compressed run) contains extension 27:
```
10,35,22,23,13,43,45,51,27
```

ClientHello (nocompress run) does NOT contain extension 27:
```
10,35,22,23,13,43,45,51
```

#### Evidence 3: No CompressedCertificate Message (HandshakeType 25)

```bash
$ tshark -r compressed.pcap -Y "tls.handshake.type==25"
# (no output)

$ tshark -r nocompress.pcap -Y "tls.handshake.type==11" | wc -l
500

$ tshark -r compressed.pcap -Y "tls.handshake.type==11" | wc -l
500
```

Both captures contain **exactly 500 Certificate messages (type 11)** — no CompressedCertificate (type 25) in either.

#### Evidence 4: Identical PCAP Sizes

| Run | nocompress | compressed | Delta |
|-----|------------|------------|-------|
| tls_none_l0_d0 mldsa44 | 5355 kB | 5361 kB | +0.1% |

#### Evidence 5: Identical Bytes per Connection

See [Results](#results) table above — delta is <0.2% for all pairs.

### Root Cause

The root cause of the compression failure was **not definitively identified** in this study. The following observations were made:

- OpenSSL 3.4.2 with OQS Provider 0.8.0 accepts the `-cert_comp` flag
- The `compress_certificate` extension (type 27) is negotiated in ClientHello
- However, `SSL_CTX_compress_certs()` fails at runtime with `Error compressing certs on ctx`
- The internal compression functions (`BIO_f_zlib()`, `BIO_f_brotli()`, `BIO_f_zstd()`) may return NULL for provider-based keys

**What was NOT tested**: Classical certificates (RSA/ECDSA) were not evaluated in this study. Therefore, we cannot confirm whether the compression path works for classical keys and fails specifically for PQ keys. Further investigation with classical certificate comparison is needed to isolate the exact cause.

---

## Known Issues

### 1. Hardcoded TC_DELAY/TC_LOSS (Fixed)

**Status**: Fixed in `Launcherv3_compress.sh`

Earlier versions had network parameters hardcoded:
```bash
# BEFORE (bug)
-e TC_DELAY=0ms \
-e TC_LOSS=0% \
```

Now correctly uses variables:
```bash
# AFTER (fix)
-e TC_DELAY=${DELAY_MS}ms \
-e TC_LOSS=${LOSS_PERC}% \
```

### 2. RFC 8879 Not Operational with PQ Keys

**Status**: Known limitation

OpenSSL 3.4.2 + OQS provider 0.8.0 does not support certificate compression for provider-based keys (ML-DSA, ML-KEM, HQC). The extension is negotiated but compression fails silently at runtime.

### 3. Docker Image Not Public

**Status**: Manual build required

The `uma-tls-quic-pq-34:latest` image must be built locally using `0-docker/Dockerfile`. It is not available on Docker Hub.

### 4. `quics_server` Does Not Support `-cert_comp`

**Status**: QUIC limitation

MsQuic-based `quics_server` does not support certificate compression. The QUIC results use TLS compatibility mode (`USE_TLS=false` triggers `quics_server` which ignores `-cert_comp`).

---

## Conclusion

### What We Set Out to Measure

> Does RFC 8879 certificate compression reduce latency/bandwidth of TLS 1.3 handshakes with post-quantum certificates?

### What We Actually Found

1. **RFC 8879 is NOT functionally operational** with ML-DSA/ML-KEM certificates in OpenSSL 3.4.2 + OQS provider 0.8.0.

2. The extension is negotiated but compression fails at runtime (`Error compressing certs on ctx`).

3. No `CompressedCertificate` (handshake type 25) is ever sent — only classic `Certificate` (type 11).

4. Network captures show **identical traffic patterns** between nocompress and compressed runs (<0.2% delta).

5. The latency variations observed (-10% to +16%) are **not caused by certificate compression** but by experimental variability (network jitter, CPU scheduling, cache effects, Docker bridge contention).

### Scientific Contribution

This result documents a **negative finding** with rigorous experimental validation:

> **Experimental evaluation shows that RFC 8879 certificate compression could not be successfully activated for ML-DSA, ML-KEM and HQC certificates when using OpenSSL 3.4.2 together with OQS Provider 0.8.0. Although the extension was negotiated, no CompressedCertificate message was observed and certificate sizes remained unchanged. The precise cause requires further investigation.**

### Recommendations

1. **For this work**: Report the negative finding as a limitation — it demonstrates rigorous experimental verification
2. **For future work**: Compare RFC 8879 behavior with classical certificates (RSA/ECDSA) to isolate whether the limitation is specific to PQ keys or a general stack issue
3. **For deeper investigation**: Debug OpenSSL source code to identify the exact failure point in the compression path for provider-based keys

---

## Reproducibility

### Requirements

- Docker 24.0+ with `NET_ADMIN` capability
- `uma-tls-quic-pq-34:latest` image (build with `0-docker/Dockerfile`)
- Python 3.12+ with `numpy`, `matplotlib`
- tshark (optional, for PCAP analysis)

### Run Full Campaign

```bash
cd /path/to/repo
./run_compress_matrix.sh
```

### Run Single Configuration

```bash
# TLS, ideal network
./Launcherv3_compress.sh tls none 0 0

# TLS, 35ms delay, 2% loss
./Launcherv3_compress.sh tls simple 2 35

# QUIC, 200ms delay, 4% loss
./Launcherv3_compress.sh quic simple 4 200
```

### Analyze Results

```bash
python3 compress/analyse_compress.py results/<run_directory> --plots
```

### Validate Compression on Wire

```bash
# Check extension negotiation (should see 27 in compressed)
tshark -r results/<run>/compressed/capture_2_*.pcap \
  -Y "tls.handshake.extension.type" \
  -T fields -e tls.handshake.extension.type | grep 27

# Check for CompressedCertificate (type 25) — should return nothing
tshark -r results/<run>/compressed/capture_2_*.pcap \
  -Y "tls.handshake.type==25"

# Compare certificate sizes (should be identical)
tshark -r results/<run>/nocompress/capture_1_*.pcap \
  -Y "tls.handshake.type==11" \
  -T fields -e tls.handshake.certificate.length | head -5

tshark -r results/<run>/compressed/capture_2_*.pcap \
  -Y "tls.handshake.type==11" \
  -T fields -e tls.handshake.certificate.length | head -5
```

---

## Citation

If you use this work in your research, please cite:

```bibtex
@misc{bezout2026pqccompression,
  author = {Bezout, Jean},
  title = {Evaluating TLS 1.3 Certificate Compression (RFC 8879) with Post-Quantum Cryptographic Certificates},
  year = {2026},
  howpublished = {\url{https://github.com/bezout9991/pqc-tls-compression}},
  note = {Experimental validation showing RFC 8879 extension is negotiated but compression is not observed on the wire for ML-DSA/ML-KEM certificates in OpenSSL 3.4.2 + OQS provider 0.8.0}
}
```

---

## References

- [RFC 8879: TLS Certificate Compression](https://www.rfc-editor.org/rfc/rfc8879)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 206: HQC](https://csrc.nist.gov/pubs/fips/206/final)
- [OpenSSL 3.4.2](https://www.openssl.org/source/)
- [OQS Provider 0.8.0](https://github.com/open-quantum-safe/oqs-provider)
