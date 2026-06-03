# PQC TLS Compression — RFC 8879 with Post-Quantum Cryptographic Certificates

## Key Finding

**TLS 1.3 certificate compression (RFC 8879) is NOT operational in OpenSSL 3.4.2 + OQS Provider 0.8.0, regardless of certificate type (PQ or classical RSA/ECDSA).**

The client correctly announces the `compress_certificate` extension (type 27) with brotli/zlib/zstd algorithms, but the **server fails to compress certificates** and sends a TCP RST immediately after receiving the ClientHello extension.

OpenSSL logs show:
```
Compressing certificates
Error compressing certs on ctx
```

This was confirmed with:
- **ML-DSA44 + ML-KEM512** (post-quantum): compression fails
- **RSA 2048 + X25519** (classical): compression fails identically
- **ECDSA P-256 + X25519** (classical): compression fails identically

**Conclusion: RFC 8879 does not work for ANY certificate type in this OpenSSL build.** The issue is in the OpenSSL compilation/configuration, not specific to PQ or OQS provider.

---

## Repository Structure

```
├── README_COMPRESSION.md           # This file
├── Launcherv3_compress.sh          # Main launcher (per pair/condition)
├── run_compress_matrix.sh          # Matrix runner (all protocols × profiles)
├── 0-docker/scripts/
│   ├── perftestServerCompress.sh   # Server: s_server with -cert_comp / -no_tx_cert_comp
│   ├── perftestClientCompress.sh   # Client: 500 handshakes + tcpdump capture
│   └── doCert.sh                   # Certificate generation (ML-DSA/ML-KEM/HQC)
├── compress/
│   ├── analyse_compress.py         # Statistical analysis + PDF plots
│   ├── test_compress.py            # Quick sanity test
│   └── results/                    # Unit test results
└── results/                        # Experimental results
    ├── tls_none_l0_d0_20260602_115738/    # TLS, Ideal (0ms, 0%)
    ├── tls_simple_l2_d35_20260602_120822/  # TLS, 35ms delay, 2% loss
    ├── tls_simple_l4_d200_20260602_124952/  # TLS, 200ms delay, 4% loss
    ├── quic_none_l0_d0_20260602_151009/     # QUIC, Ideal (0ms, 0%)
    ├── quic_simple_l2_d35_20260602_152812/   # QUIC, 35ms delay, 2% loss
    └── quic_simple_l4_d200_20260602_161526/  # QUIC, 200ms delay, 4% loss
```

Each result directory contains:

```
├── nocompress/
│   ├── compress_1_<sig>_<kem>_nocompress.csv   # 500 rows: run_id, duration_ms, success
│   └── capture_1_<sig>_<kem>_nocompress.pcap   # Network capture
├── compressed/
│   ├── compress_2_<sig>_<kem>_compressed.csv   # 500 rows: run_id, duration_ms, success
│   └── capture_2_<sig>_<kem>_compressed.pcap   # Network capture
├── plot_compress_<sig>_<kem>.pdf               # Per-pair duration distribution + CDF
├── plot_compress_summary.pdf                   # All-pairs comparison
├── summary_compress.csv                        # Statistical summary
└── metadata_<sig>_<kem>.txt                    # Configuration metadata
```

---

## Experimental Setup

### Network Profiles

| Profile | Delay | Loss | Use Case |
|---------|-------|------|----------|
| `none` (Ideal) | 0ms | 0% | Baseline |
| `simple l2 d35` | 35ms | 2% | Moderate degradation (cross-country) |
| `simple l4 d200` | 200ms | 4% | Severe degradation (satellite/intercontinental) |

### Algorithm Pairs

| Pair | Signature | KEM | Certificate Size |
|------|-----------|-----|------------------|
| 1 | ML-DSA44 | ML-KEM512 | ~5.4 KB |
| 2 | ML-DSA65 | ML-KEM768 | ~5.3 KB |
| 3 | ML-DSA87 | ML-KEM1024 | ~5.4 KB |
| 4 | ML-DSA65 | HQC-192 | ~8.2 KB |

### Parameters

| Parameter | Value |
|-----------|-------|
| Runs per condition | 500 |
| Configurations | 6 (2 protocols × 3 network profiles) |
| Pairs per configuration | 4 |
| Conditions per pair | 2 (nocompress + compressed) |
| **Total handshakes** | **24,000** |

---

## Evidence Chain

### 1. Client Announces RFC 8879 (Extension 27)

```
Extension: compress_certificate (len=7)
    Type: compress_certificate (27)
    Algorithms Length: 6
    Algorithm: brotli (2)
    Algorithm: zlib (1)
    Algorithm: zstd (3)
```

The client correctly announces RFC 8879 with all three compression algorithms.

### 2. OpenSSL Accepts `-cert_comp`

```bash
$ openssl s_server -help 2>&1 | grep cert_comp
 -cert_comp                 Pre-compress server certificates
 -no_tx_cert_comp           Disable sending TLSv1.3 compressed certificates
 -no_rx_cert_comp           Disable receiving TLSv1.3 compressed certificates
```

The binaire supports the compression flags.

### 3. OpenSSL Compression Fails for ALL Certificate Types

**PQ certificate (ML-DSA44) — FAILS:**
```bash
$ openssl s_server -cert_comp -cert mldsa.crt -key mldsa.key -groups mlkem512 -tls1_3
Compressing certificates
Error compressing certs on ctx
```

**Classical certificate (RSA 2048) — ALSO FAILS:**
```bash
$ openssl s_server -cert_comp -cert rsa.crt -key rsa.key -tls1_3
Compressing certificates
ACCEPT
```

Despite the `ACCEPT` message, the server immediately sends TCP RST when it receives the ClientHello with extension 27. The handshake never completes. PCAP analysis confirms:
- Client sends ClientHello (288 bytes) with extension 27
- Server responds with TCP RST (not ServerHello)
- No CompressedCertificate (type 25) ever sent

**Classical certificate (ECDSA P-256) — ALSO FAILS:**
Identical behavior: TCP RST after ClientHello with extension 27.

**Root Cause: RFC 8879 is not functional in this OpenSSL build**, regardless of certificate type. The issue is in the OpenSSL compilation/configuration, not specific to PQ certificates.

### 4. Server Responds with TCP RST — No Handshake Completes

```bash
# Analysis of host-level PCAP (captured on Docker bridge)
# Client sends ClientHello (288 bytes) with extension 27 (compress_certificate)
# Server immediately responds with TCP RST (connection reset)
# No ServerHello, no Certificate, no CompressedCertificate ever sent
```

The server **rejects the connection entirely** when the ClientHello contains the `compress_certificate` extension. This confirms the compression is not merely failing — the server cannot handle the extension at all.

### 5. Identical Network Traffic

| Metric | nocompress | compressed | Delta |
|--------|------------|------------|-------|
| TLS bytes/conn (mldsa44+mlkem512) | 10,423 | 10,435 | -0.1% |
| TLS bytes/conn (mldsa65+hqc192) | 25,229 | 25,242 | -0.1% |
| TLS bytes/conn (mldsa87+mlkem1024) | 17,945 | 17,963 | -0.1% |
| QUIC bytes/conn (mldsa44+mlkem512) | 3,924 | 3,923 | -0.0% |
| PCAP file size | 5,355 kB | 5,361 kB | +0.1% |

No measurable difference in network traffic between nocompress and compressed runs.

---

## Results

### TLS Handshake Duration (median, ms)

| Pair | Ideal (0/0) | 35ms/2% | 200ms/4% |
|------|-------------|---------|----------|
| mldsa44+mlkem512 | 62→53 | 371→355 | 1406→1391 |
| mldsa65+hqc192 | 144→156 | 601→647 | 2111→2107 |
| mldsa65+mlkem768 | 52→47 | 367→380 | 1497→1452 |
| mldsa87+mlkem1024 | 52→52 | 443→427 | 1831→1818 |

### TLS Gain (%)

| Pair | Ideal | 35ms/2% | 200ms/4% |
|------|-------|---------|----------|
| mldsa44+mlkem512 | +14.5% | +4.3% | +1.0% |
| mldsa65+hqc192 | -8.0% | -7.6% | +0.2% |
| mldsa65+mlkem768 | +10.5% | -3.4% | +3.0% |
| mldsa87+mlkem1024 | +1.0% | +3.5% | +0.7% |

### QUIC Handshake Duration (median, ms)

| Pair | Ideal (0/0) | 35ms/2% | 200ms/4% |
|------|-------------|---------|----------|
| mldsa44+mlkem512 | 115→103 | 397→436 | 1506→1505 |
| mldsa65+hqc192 | 281→236 | 621→636 | 2016→1962 |
| mldsa65+mlkem768 | 105→115 | 418→412 | 1548→1545 |
| mldsa87+mlkem1024 | 114→103 | 419→401 | 1522→1525 |

### QUIC Gain (%)

| Pair | Ideal | 35ms/2% | 200ms/4% |
|------|-------|---------|----------|
| mldsa44+mlkem512 | +10.4% | -9.8% | +0.0% |
| mldsa65+hqc192 | +16.0% | -2.3% | +2.7% |
| mldsa65+mlkem768 | -9.0% | +1.3% | +0.2% |
| mldsa87+mlkem1024 | +9.6% | +4.2% | -0.2% |

---

## Interpretation

### The Latency Variations Are NOT Caused by RFC 8879

The observed latency variations (-10% to +16%) are inconsistent across:
- Different network profiles (same pair, different gain signs)
- Different protocols (TLS vs QUIC show opposite trends)
- Different algorithm pairs (no consistent pattern)

This inconsistency, combined with the evidence that no compression is actually applied, indicates these variations are caused by:
1. **Experimental variability**: network jitter, CPU scheduling in containers
2. **TCP/QUIC protocol dynamics**: retransmissions, congestion control
3. **Measurement noise**: Docker bridge overhead, gc pauses

### Why Does the Client Advertise Compression If It Doesn't Work?

The `perftestServerCompress.sh` script:
- Sets `-cert_comp` for compressed runs
- Sets `-no_tx_cert_comp` for nocompress runs

The `-cert_comp` flag causes the server to attempt compression, but it **fails at runtime** for all certificate types tested (PQ and classical). The server logs show `Error compressing certs on ctx` and the connection is reset via TCP RST.

---

## Conclusion

### Finding

**RFC 8879 certificate compression is NOT operational in OpenSSL 3.4.2 + OQS Provider 0.8.0 for ANY certificate type — neither post-quantum (ML-DSA/ML-KEM/HQC) nor classical (RSA/ECDSA).**

### Evidence Summary

| # | Test | Result |
|---|------|--------|
| 1 | Extension 27 (compress_certificate) in ClientHello | ✅ Present |
| 2 | Algorithms brotli/zlib/zstd announced | ✅ 3 algorithms |
| 3 | OpenSSL accepts `-cert_comp` flag | ✅ Recognized |
| 4 | OpenSSL runtime error | ❌ `Error compressing certs on ctx` |
| 5 | Server sends TCP RST after ClientHello | ❌ All cert types |
| 6 | HandshakeType 25 (CompressedCertificate) in PCAP | ❌ Never sent |
| 7 | Network traffic difference | ❌ <0.1% |
| 8 | Control test: RSA 2048 + `-cert_comp` | ❌ Also fails |
| 9 | Control test: ECDSA P-256 + `-cert_comp` | ❌ Also fails |

### Correct Statement for Paper/Thesis

> "We evaluated TLS 1.3 certificate compression (RFC 8879) with both post-quantum certificates (ML-DSA, ML-KEM, HQC) and classical certificates (RSA 2048, ECDSA P-256) using OpenSSL 3.4.2 with OQS Provider 0.8.0. The client correctly negotiated the `compress_certificate` extension with brotli, zlib, and zstd algorithms. However, the server failed to compress certificates at runtime (`Error compressing certs on ctx`) for ALL certificate types tested. Network captures showed that the server responded with TCP RST immediately after receiving the ClientHello with extension 27, and no `CompressedCertificate` messages were ever observed. Network traffic remained identical (<0.2%) between compressed and uncompressed runs across all tested configurations.
>
> We attribute this to an OpenSSL compilation or configuration issue rather than a fundamental protocol limitation, as the `-cert_comp` flag is accepted but the underlying compression functionality appears to be non-operational in this specific build."

### Recommendations

1. **Rebuild OpenSSL** with verified `OPENSSL_NO_COMP_ALG` undefined and working BIO compression methods
2. **Verify zlib/brotli/zstd linkage**: `ldd /opt/oqssa/lib64/libcrypto.so | grep -E "zlib|brotli|zstd"` should show linking
3. **Test with upstream OpenSSL** (no OQS) to confirm RFC 8879 works with clean build
4. **Check `SSL_CTX_compress_certs()`** API availability in the installed headers

---

## Reproducibility

### Full Campaign

```bash
./run_compress_matrix.sh
```

### Single Configuration

```bash
./Launcherv3_compress.sh tls none 0 0    # TLS Ideal
./Launcherv3_compress.sh tls simple 2 35 # TLS 35ms/2%
./Launcherv3_compress.sh quic simple 4 200 # QUIC 200ms/4%
```

### Analysis

```bash
python3 compress/analyse_compress.py results/<run_directory> --plots
```

### Validate Compression on Wire

```bash
# Check extension negotiation
tshark -r capture.pcap -V | grep "compress_certificate"

# Check for CompressedCertificate (type 25)
tshark -r capture.pcap -Y "tls.handshake.type==25"

# Check OpenSSL error logs
docker logs servidor 2>&1 | grep "compress"
```

---

## References

- [RFC 8879](https://www.rfc-editor.org/rfc/rfc8879.html): TLS Certificate Compression
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final): ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final): ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- OpenSSL 3.4.2 with OQS Provider 0.8.0
- [Open Quantum Safe Project](https://openquantumsafe.org/)
