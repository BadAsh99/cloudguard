# CloudGuard

> Multi-cloud red-teaming and misconfiguration scanner for AWS, Azure, and GCP

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![AWS](https://img.shields.io/badge/AWS-boto3-orange?logo=amazonaws)
![Azure](https://img.shields.io/badge/Azure-SDK-blue?logo=microsoftazure)
![GCP](https://img.shields.io/badge/GCP-SDK-red?logo=googlecloud)

---

## Overview

CloudGuard is a cloud security red-teaming framework that discovers and validates misconfigurations across AWS, Azure, and GCP in a single tool. It operates in two modes:

- **Scan Mode** — read-only passive discovery of misconfigurations
- **Red-Team Mode** — active exploitation simulation with multi-step attack chain building

Findings are mapped to **CIS Benchmarks**, **OWASP Cloud Top 10**, and **NIST CSF** with severity scoring so remediation can be prioritized immediately.

---

## Architecture

```
┌──────────────────────────────────────┐
│       Flask Web Dashboard / API      │
│  /api/scan   /api/redteam   /api/payloads │
└────────────────┬─────────────────────┘
                 │
      ┌──────────▼──────────┐
      │    Payload Library   │
      │  (provider-specific) │
      └──┬──────────┬──────┬─┘
         │          │      │
     ┌───▼─┐   ┌───▼─┐ ┌──▼──┐
     │ AWS │   │Azure│ │ GCP │
     │Scan │   │Scan │ │Scan │
     └───┬─┘   └───┬─┘ └──┬──┘
         │          │      │
     ┌───▼───┐  ┌───▼──┐ ┌─▼────┐
     │  AWS  │  │Azure │ │ GCP  │
     │Exploit│  │Exploit│ │Exploit│
     └───────┘  └──────┘ └──────┘
                 │
      ┌──────────▼──────────┐
      │  Attack Chain Builder│
      │  Risk Score / CIS Map│
      └─────────────────────┘
```

---

## Cloud Coverage

| Provider | Checks |
|----------|--------|
| **AWS** | S3 bucket public exposure, IAM over-permissioning, Security Group misconfiguration, CloudTrail logging gaps |
| **Azure** | Storage Account public access, RBAC excessive permissions, NSG rule weaknesses |
| **GCP** | Cloud Storage public ACLs, IAM binding misconfigurations, audit logging gaps |

---

## Features

- Dual-mode operation — safe passive discovery or active red-teaming
- Extensible payload library with provider-specific attack patterns
- Multi-turn attack chains — simulate how misconfigurations chain into full breaches
- CIS Benchmark severity scoring for immediate remediation prioritization
- REST API for integration into existing security pipelines or CI/CD
- Web dashboard for mode selection, provider targeting, and result visualization

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, Flask 3.0 |
| AWS | boto3 |
| Azure | azure-identity, azure-storage-blob |
| GCP | google-cloud-iam, google-cloud-storage |
| Data modeling | Pydantic 2.5 |
| Config | python-dotenv |

---

## Getting Started

```bash
git clone https://github.com/BadAsh99/cloudguard.git
cd cloudguard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add your cloud credentials
python app.py
# Open http://localhost:5000
```

### API Reference

```bash
# Passive misconfiguration scan
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"provider": "aws", "mode": "scan"}'

# Active red-team exploitation
curl -X POST http://localhost:5000/api/redteam \
  -H "Content-Type: application/json" \
  -d '{"provider": "aws", "mode": "redteam", "confirm_exploitation": true}'

# List available payloads for a provider
curl http://localhost:5000/api/payloads/aws
```

---

## Environment Variables

```env
# AWS
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=

# Azure
AZURE_SUBSCRIPTION_ID=
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=

# GCP
GCP_PROJECT_ID=
GOOGLE_APPLICATION_CREDENTIALS=
```

---

## Use Cases

- Pre-audit posture validation across multi-cloud environments
- Red team exercises to simulate realistic cloud attack paths
- Compliance gap analysis mapped to CIS, NIST, and OWASP frameworks
- Security awareness training using real misconfiguration patterns

---

## Author

**Ash Clements** — Sr. Principal Security Consultant | Cloud & AI Security
[github.com/BadAsh99](https://github.com/BadAsh99)
