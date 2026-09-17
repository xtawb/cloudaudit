# Installation

## Requirements

- Python 3.11 or later
- pip (any modern version)
- Network access to the target cloud storage endpoints you are authorised to audit

## Quick Install

```bash
git clone https://github.com/xtawb/cloudaudit
cd cloudaudit
pip install -r requirements.txt
pip install -e .
```

Verify the installation:

```bash
cloudaudit --version
cloudaudit selftest
```

`cloudaudit selftest` runs the secret scanner and redaction pipeline against a
small set of built-in, synthetic (non-functional) samples and prints PASS/FAIL
per check — a good sanity check to run right after installing or upgrading.

## Optional Dependencies

CloudAudit's core install has zero optional dependencies required for a scan
to run — every optional feature degrades gracefully with a clear error
message if its dependency is missing.

| Package | Feature | Install |
|---|---|---|
| `google-genai` | Google Gemini AI summaries and analysis | `pip install cloudaudit[gemini]` |
| `openai` | OpenAI GPT and DeepSeek AI (OpenAI-compatible) | `pip install openai` |
| `anthropic` | Anthropic Claude AI | `pip install anthropic` |
| `Pillow` | EXIF metadata extraction from images (`--deep-metadata`) | `pip install Pillow` |
| `cryptography` | Encrypted local API key storage (`cloudaudit config`) | `pip install cryptography` |
| `py7zr` | 7-Zip archive extraction (`--extract-archives`) | `pip install py7zr` |
| `boto3` | Real AWS bucket ACL/policy inspection (`--aws-acl-check`) | `pip install cloudaudit[aws]` |
| `xhtml2pdf` | PDF report export (`--format pdf`) | `pip install cloudaudit[pdf]` |
| `pyyaml` | Custom patterns, baseline files, config profiles | Already a core dependency |
| `rich` | Terminal UI and the live `--tui` dashboard | Already a core dependency |

All-in-one, with every optional feature installed:

```bash
pip install cloudaudit[all]
```

## Verifying a Specific Feature

```bash
# AI provider
cloudaudit config --list-providers

# PDF export
cloudaudit -u https://mybucket.s3.amazonaws.com/ --confirm-ownership \
           --org-name "Acme Corp" --format pdf -o reports/audit

# Terraform state scanning is always active — no extra install required,
# it activates automatically whenever a *.tfstate file is discovered.
```

## Environment

No special environment configuration is required for basic operation. See
[Configuration](configuration.md) for AI provider setup, environment
variables, and named CLI profiles.
