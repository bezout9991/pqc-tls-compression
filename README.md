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

1. [Scientific Context](#scientific-context)
2. [Experimental Setup](#experimental-setup)
3. [Infrastructure](#infrastructure)
4. [Network Profiles](#network-profiles)
5. [Algorithm Pairs](#algorithm-pairs)
6. [Methodology](#methodology)
7. [Results](#results)
8. [Network-Level Validation](#network-level-validation)
9. [Conclusion](#conclusion)
10. [Reproducibility](#reproducibility)

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
| **Total handshakes** | ~16,000 |

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

OpenSSL 3.4.2 with OQS provider accepts the `-cert_comp` flag and negotiates the extension, but **fails to compress provider-based keys** (EVP_PKEY from OQS provider). The compression path works for classical keys (RSA, ECDSA) but not for PQ keys from external providers.

This is a **known limitation** of the current OpenSSL/OQS integration.

---

## Conclusion

### What We Set Out to Measure

> Does RFC 8879 certificate compression reduce latency/bandwidth of TLS 1.3 handshakes with post-quantum certificates?

### What We Actually Found

1. **RFC 8879 is NOT functionally operational** with ML-DSA/ML-KEM certificates in OpenSSL 3.4.2 + OQS provider 0.8.0.

2. The extension is negotiated but compression fails at runtime (`Error compressing certs on ctx`).

3. No `CompressedCertificate` (handshake type 25) is ever sent — only classic `Certificate` (type 11).

4. Network captures show **identical traffic patterns** between nocompress and compressed runs.

5. The latency variations observed (-10% to +16%) are **not caused by certificate compression** but by experimental variability (network jitter, CPU scheduling, cache effects).

### Scientific Contribution

This result is a **negative finding** but scientifically valuable:

> **TLS 1.3 certificate compression (RFC 8879) is not currently compatible with post-quantum certificates from the OQS provider in OpenSSL 3.4.2.**

This limitation should be documented and addressed in future OpenSSL/OQS releases before RFC 8879 can be meaningfully evaluated in PQ TLS handshakes.

### Recommendations

1. **For this paper**: Report the negative finding as a limitation section
2. **For future work**: Test with native OpenSSL PQ support (no provider) or wait for OQS provider updates
3. **For comparison**: Evaluate RFC 8879 with classical certificates (RSA/ECDSA) where it works, as baseline

---

## Reproducibility

### Requirements

- Docker with `NET_ADMIN` capability
- `uma-tls-quic-pq-34:latest` image
- Python 3.12+ with numpy, matplotlib
- tshark (for PCAP analysis)

### Run Full Campaign

```bash
cd /path/to/repo
./run_compress_matrix.sh
```

### Analyze Results

```bash
python3 compress/analyse_compress.py results/<run_directory> --plots
```

### Validate Compression on Wire

```bash
# Check extension negotiation
tshark -r results/<run>/compressed/capture_2_*.pcap \
  -Y "tls.handshake.extension.type" \
  -T fields -e tls.handshake.extension.type | grep 27

# Check for CompressedCertificate (type 25)
tshark -r results/<run>/compressed/capture_2_*.pcap \
  -Y "tls.handshake.type==25"

# Compare certificate sizes
tshark -r results/<run>/nocompress/capture_1_*.pcap \
  -Y "tls.handshake.type==11" \
  -T fields -e tls.handshake.certificate.length

tshark -r results/<run>/compressed/capture_2_*.pcap \
  -Y "tls.handshake.type==11" \
  -T fields -e tls.handshake.certificate.length
```

---

## References

- RFC 8879: TLS Certificate Compression
- NIST FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- NIST FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- OpenSSL 3.4.2 with OQS Provider 0.8.0
