# recon-pipeline<div align="center">

# 🛰️ recon-pipeline

**Automated subdomain reconnaissance pipeline for authorized security assessments**

`python3 recon.py example.com` → subdomains → DNS validation → HTTP probing → crawling → secret scanning

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Ready-black.svg)]()

</div>

---

## ⚠️ Legal / Ethical Disclaimer

**This tool is intended ONLY for:**
- Domains and systems you **own**
- **Authorized penetration tests** with written permission
- **Bug-bounty targets** explicitly within scope
- **CTF / lab environments** you are permitted to test

Do **NOT** run this against arbitrary third-party infrastructure. Unauthorized
scanning may violate local laws and platform terms. You are responsible for
your own actions.

---

## 📖 Project Description

`recon-pipeline` is a single-command, orchestrated reconnaissance pipeline for
**authorized** domain assessments. Give it one root domain and it:

1. Enumerates subdomains (subfinder)
2. Validates DNS resolution (dnsx)
3. Probes live HTTP/HTTPS services (httpx-toolkit / httpx)
4. Crawls confirmed-live URLs (katana)
5. Scans JavaScript assets for leaked secrets (mantra)

Every stage writes to a **timestamped output directory**, keeps raw and clean
results separate, logs everything, and never hides errors.

---

## 🏗️ Architecture

```text
Domain
  ↓
Subfinder
  ↓
Subdomains
  ↓
dnsx
  ↓
Resolved Domains
  ↓
httpx-toolkit
  ↓
Live HTTP/HTTPS
  ↓
Katana
  ↓
URLs
  ↓
Mantra
  ↓
Results