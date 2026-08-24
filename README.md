<div align="center">

# 🛰️ recon-pipeline

**Automated Subdomain Reconnaissance Pipeline for Authorized Security Assessments**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Ready-black.svg)]()

**One command: `python3 recon.py example.com`**

</div>

---

## 📋 Table of Contents

1. [What is recon-pipeline?](#-what-is-recon-pipeline)
2. [⚠️ Legal Disclaimer — READ FIRST](#️-legal-disclaimer--read-first)
3. [How the Pipeline Works](#-how-the-pipeline-works)
4. [System Requirements](#-system-requirements)
5. [Step-by-Step Installation](#-step-by-step-installation)
6. [Verify Installation](#-verify-installation)
7. [How to Run a Scan](#-how-to-run-a-scan)
8. [All CLI Options](#-all-cli-options)
9. [Output Files Explained](#-output-files-explained)
10. [Configuration (config.yaml)](#-configuration-configyaml)
11. [Troubleshooting Guide](#-troubleshooting-guide)
12. [Running Tests](#-running-tests)
13. [Pushing to GitHub](#-pushing-to-github)
14. [License](#-license)

---

## 📖 What is recon-pipeline?

`recon-pipeline` is a **single-command automated reconnaissance tool** for
authorized security testing. You give it ONE domain (e.g. `example.com`), and
it automatically:

| Step | Tool | What it does |
|------|------|--------------|
| 1 | `subfinder` | Finds all subdomains (e.g. `api.example.com`, `admin.example.com`) |
| 2 | `dnsx` | Checks which subdomains actually resolve in DNS |
| 3 | `httpx-toolkit` | Probes which ones have live HTTP/HTTPS websites |
| 4 | `katana` | Crawls the live websites to discover URLs |
| 5 | `mantra` | Scans JavaScript files for leaked API keys/secrets |

Every result is saved in an organized, timestamped folder. Nothing is
overwritten, everything is logged.

---

## ⚠️ Legal Disclaimer — READ FIRST

**This tool is intended ONLY for:**

- ✅ Domains and systems that **you own**
- ✅ **Authorized penetration tests** (written permission required)
- ✅ **Bug-bounty programs** — targets explicitly within scope
- ✅ **CTF / lab environments** you are allowed to test

**NEVER use this against:**
- ❌ Third-party websites you don't own
- ❌ Any system without explicit written authorization

Unauthorized scanning is **illegal** in most countries and can violate
platform terms of service. You are solely responsible for how you use this
tool.

---

## 🏗️ How the Pipeline Works

```text
        Domain (example.com)
                │
                ▼
        ┌──────────────┐
        │   subfinder  │  → Finds subdomains
        └──────────────┘
                │
                ▼
        subdomains.txt
                │
                ▼
        ┌──────────────┐
        │     dnsx     │  → Validates DNS resolution
        └──────────────┘
                │
                ▼
        resolved.txt
                │
                ▼
        ┌──────────────┐
        │ httpx-toolkit│  → Probes HTTP/HTTPS services
        └──────────────┘
                │
                ▼
        live_urls.txt
                │
                ▼
        ┌──────────────┐
        │    katana    │  → Crawls live URLs
        └──────────────┘
                │
                ▼
        katana.txt
                │
                ▼
        ┌──────────────┐
        │    mantra    │  → Scans JS files for secrets
        └──────────────┘
                │
                ▼
        mantra.txt + summary.txt