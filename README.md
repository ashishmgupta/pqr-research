# PQC-Radar

A structured learning project documenting Post-Quantum Cryptography (PQC) — from classical RSA
fundamentals through enterprise deployment on Cloudflare and F5 BIG-IP.

## Project Structure

```
phase1-fundamentals/        Python demos: RSA factoring, Shor's algorithm, comparisons
phase2-verification/        Tools: Cloudflare API checker, TLS version checker, openssl scripts
phase3-dashboard/           Flask dashboard (not started — after Phase 1+2)
docs/                       GitHub Pages site (not started)
```

## Quick Start

```bash
pip install sympy matplotlib numpy

# Phase 1 — Run in order:
cd phase1-fundamentals
python rsa_factoring_demo.py        # generates factoring_results.csv
python factoring_chart.py           # reads CSV, produces factoring_chart.png
python shors_algorithm.py           # Shor's algorithm simulation
python classical_vs_quantum.py      # side-by-side comparison

# Phase 2 — Requires Cloudflare API token:
cd ../phase2-verification
export CLOUDFLARE_API_TOKEN="your_token_here"
python check_cloudflare_pq.py       # check all zones for PQ status
python check_tls_version.py cloudflare.com your-f5-host.internal
chmod +x verify_mlkem.sh && ./verify_mlkem.sh cloudflare.com
```

## Key Facts

- ML-KEM (FIPS 203) replaces RSA/ECDH in TLS key exchange — AES-256 is unchanged
- ML-KEM requires TLS 1.3 — will not work on TLS 1.2
- Cloudflare: ML-KEM enabled by default for all TLS 1.3 zones
- F5 BIG-IP: ML-KEM requires TMOS 17.5.1+, configured in Client SSL Profile
- Netskope: outbound proxy leg not yet ML-KEM capable (roadmap Phase 2)
- Threat today: Harvest Now Decrypt Later (HNDL) — capture now, decrypt when quantum arrives
