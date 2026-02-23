# CloudAudit

**Next-Generation AI-Powered Cloud Security Auditing Framework**

```
  ______  ___                    _____              ___ __
 / ___/ |/ / ___  __ _____ ___  / ___/ __ ___  ___/ (_) /_
/ /__ /    / / _ \/ // / _ `/ _ \ \/ // // _ \/ _  / / __/
\___//_/|_/  \___/\_,_/\___/\___/\___/_//_/\___/\_,_/_/\__/
```

[![Version](https://img.shields.io/badge/version-1.0.1-blue)](#)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](#)
[![Mode](https://img.shields.io/badge/mode-read--only-green)](#)
[![Docs](https://img.shields.io/readthedocs/cloudaudit)](#)
[![License](https://img.shields.io/badge/license-Proprietary-red)](#)

> **Developed by xtawb** | [https://linktr.ee/xtawb](https://linktr.ee/xtawb)

---

CloudAudit is an enterprise-grade cloud storage security posture auditing
framework. It discovers, crawls, and analyses publicly exposed cloud storage
containers — AWS S3, Google Cloud Storage, Azure Blob Storage, open directory
listings — to identify secret leakage, credential exposure, compliance gaps,
and misconfigurations before attackers do.

## Quick Start

```bash
pip install -e ".[gemini]"

cloudaudit -u https://mybucket.s3.amazonaws.com/ \
           --confirm-ownership \
           --org-name "Acme Corp" \
           --provider gemini
```

## Design Philosophy

- **Read-only by architecture** — only GET, HEAD, OPTIONS exist in the HTTP client
- **Ownership-gated** — requires explicit `--confirm-ownership` flag
- **Secrets never stored raw** — all matches are redacted before write or transmission
- **No exploitation guidance** — AI providers are prompted for defensive output only

Navigate the documentation using the tabs above.
