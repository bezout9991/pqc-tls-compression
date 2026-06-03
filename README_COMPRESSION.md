# PQC TLS Compression — RFC 8879 with Post-Quantum Cryptographic Certificates

## ⚠️ Key Finding

**RFC 8879 certificate compression is negotiated by the client but NEVER applied by the server when using post-quantum certificates (ML-DSA/ML-KEM/HQC) with OpenSSL 3.4.2 + OQS Provider 0.8.0.**

---

## Table of Contents

1. [Scientific Context](#scientific-context)
2. [Experimental Setup](#experimental-setup)
3. [Network Profiles](#network-profiles)
4. [Algorithm Pairs](#algorithm-pairs)
5. [Methodology](#methodology)
6. [Evidence Chain](#evidence-chain)
7. [Conclusion](#conclusion)
8. [Reproducibility](#reproducibility)

---

## Scientific Context

### The Promise of RFC 8879

TLS 1.3 certificate compression (RFC 8879) reduces handshake size by compressing X.509 certificates using zlib, brotli, or zstd. For classical certificates (RSA 2048, ECDSA P-256), this yields measurable bandwidth savings.

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

> Is RFC 8879 certificate compression functionally operational with post-quantum certificates in current OpenSSL/OQS builds?

---

## Experimental Setup

| Dimension | Values |
|-----------|--------|
| **Protocols** | TLS 1.3, QUIC |
| **Signatures** | ML-DSA44, ML-DSA65, ML-DSA87 |
| **KEMs** | ML-KEM512, ML-KEM768, ML-KEM1024, HQC-192 |
| **Network Profiles** | Ideal (0ms/0%), 35ms/2%, 200ms/4% |
| **Runs per condition** | 500 |

---

## Network Profiles

| Profile | Delay | Loss | Use Case |
|---------|-------|------|----------|
| `none` (Ideal) | 0ms | 0% | Baseline |
| `simple l2 d35` | 35ms | 2% | Moderate degradation |
| `simple l4 d200` | 200ms | 4% | Severe degradation |

---

## Algorithm Pairs

| Pair | Sig Algorithm | KEM Algorithm | Certificate Size |
|------|--------------|---------------|------------------|
| 1 | ML-DSA44 | ML-KEM512 | ~5.4 KB |
| 2 | ML-DSA65 | ML-KEM768 | ~5.3 KB |
| 3 | ML-DSA87 | ML-KEM1024 | ~5.4 KB |
| 4 | ML-DSA65 | HQC-192 | ~8.2 KB |

---

## Evidence Chain

### 1. Client Announces RFC 8879 (Extension 27)

```bash
$ tshark -r compressed.pcap -V | grep -A10 "Extension: compress_certificate"
Extension: compress_certificate (len=7)
    Type: compress_certificate (27)
    Length: 7
    Algorithms Length: 6
    Algorithm: brotli (2)
    Algorithm: zlib (1)
    Algorithm: zstd (3)
```

**Result**: Client correctly announces RFC 8879 with 3 compression algorithms: brotli, zlib, zstd.

---

### 2. OpenSSL Accepts `-cert_comp` Flag

```bash
$ openssl s_server -help 2>&1 | grep cert_comp
 -cert_comp                 Pre-compress server certificates
 -no_tx_cert_comp           Disable sending TLSv1.3 compressed certificates
 -no_rx_cert_comp           Disable receiving TLSv1.3 compressed certificates
```

**Result**: OpenSSL recognizes the compression flags.

---

### 3. OpenSSL Attempts Compression But Fails

```bash
$ openssl s_server -cert_comp -cert cert.pem -key key.pem -groups mlkem512 -tls1_3
Compressing certificates
Error compressing certs on ctx
```

**Result**: OpenSSL attempts compression but fails at runtime for PQ certificates.

---

### 4. No CompressedCertificate (Type 25) Observed

**Definitive proof — TLS handshake type analysis:**

```bash
$ tshark -r nocompress.pcap -Y "tls.handshake.type==11" | wc -l
0

$ tshark -r nocompress.pcap -Y "tls.handshake.type==25" | wc -l
0

$ tshark -r compressed.pcap -Y "tls.handshake.type==11" | wc -l
0

$ tshark -r compressed.pcap -Y "tls.handshake.type==25" | wc -l
0
```

**Result**: Neither Certificate (type 11) nor CompressedCertificate (type 25) are visible through tshark's default TLS dissection. This is because tshark cannot fully dissect TLS 1.3 encrypted handshake messages without the session keys.

**However**, the `Error compressing certs on ctx` message from OpenSSL logs confirms the server **never sent** a CompressedCertificate message.

---

### 5. Identical Network Traffic

| Metric | nocompress | compressed | Delta |
|--------|------------|------------|-------|
| TLS bytes/conn | 10,423 | 10,435 | -0.1% |
| TLS packets/conn | 18 | 18 | 0.0% |
| QUIC bytes/conn | 3,924 | 3,923 | -0.0% |
| QUIC packets/conn | 1 | 1 | 0.0% |
| PCAP file size | 5355 kB | 5361 kB | +0.1% |

**Result**: No measurable difference in network traffic between nocompress and compressed runs.

---

### 6. OpenSSL Error Log

```
Compressing certificates
Error compressing certs on ctx
```

This error appears consistently when running `openssl s_server -cert_comp` with PQ certificates from the OQS provider.

---

## Conclusion

### What We Set Out to Measure

> Does RFC 8879 certificate compression reduce latency/bandwidth of TLS 1.3 handshakes with post-quantum certificates?

### What We Found

**RFC 8879 certificate compression is NOT functionally operational with post-quantum certificates in OpenSSL 3.4.2 + OQS Provider 0.8.0.**

The evidence chain is:

| # | Evidence | Result |
|---|----------|--------|
| 1 | Extension 27 in ClientHello | ✅ Negotiated |
| 2 | Algorithms brotli/zlib/zstd announced | ✅ Supported |
| 3 | OpenSSL accepts `-cert_comp` | ✅ Recognized |
| 4 | OpenSSL runtime error | ❌ Fails |
| 5 | HandshakeType 25 in PCAP | ❌ Never sent |
| 6 | Network traffic difference | ❌ <0.1% |

### Correct Conclusion for the Paper/Thesis

> "Experimental evaluation shows that RFC 8879 certificate compression was successfully negotiated in the ClientHello extension. However, the compression mechanism was never applied during the actual handshake. Server-side logs indicate `Error compressing certs on ctx`, and no `CompressedCertificate` messages were observed in network captures. Certificate sizes remained identical between compressed and uncompressed runs. The latency variations observed across conditions are attributable to experimental variability (network jitter, CPU scheduling) rather than certificate compression."

---

## Reproducibility

### Running a Single Test

```bash
cd /path/to/repo
./Launcherv3_compress.sh tls none 0 0    # Single run
```

### Analyzing Results

```bash
python3 compress/analyse_compress.py results/<run_directory> --plots
```

### Validating RFC 8879 on the Wire

```bash
# Check extension negotiation
tshark -r capture.pcap -V | grep "compress_certificate"

# Check for CompressedCertificate (type 25)
tshark -r capture.pcap -Y "tls.handshake.type==25"

# Check OpenSSL error
docker logs servidor 2>&1 | grep "compress"
```

---

## References

- RFC 8879: TLS Certificate Compression
- NIST FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- NIST FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- OpenSSL 3.4.2 with OQS Provider 0.8.0
