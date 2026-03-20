# CloudGuard 🛡️

> **Enterprise Cloud Red-Teaming & Compliance Assessment Framework**  
> Multi-cloud vulnerability scanner with compliance mapping, attack chain simulation, and CIS Benchmark alignment for AWS, Azure, and GCP

![Production Ready](https://img.shields.io/badge/Status-Production_Ready-green)
![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![AWS](https://img.shields.io/badge/AWS-boto3-orange?logo=amazonaws)
![Azure](https://img.shields.io/badge/Azure-SDK-blue?logo=microsoftazure)
![GCP](https://img.shields.io/badge/GCP-SDK-red?logo=googlecloud)
![CIS](https://img.shields.io/badge/CIS_Benchmarks-Aligned-orange)
![NIST](https://img.shields.io/badge/NIST_CSF-Mapped-blue)

---

## 🎯 Value Proposition

**CloudGuard** is purpose-built for cloud security architects and red teamers who need to:

- ✅ **Discover misconfigurations at scale** across AWS, Azure, and GCP simultaneously
- ✅ **Simulate real-world attack chains** to show business impact of security gaps
- ✅ **Prioritize remediation** with CIS Benchmarks, OWASP Cloud Top 10, NIST CSF mappings
- ✅ **Prove compliance posture** with automated assessment reports
- ✅ **Integrate into CI/CD pipelines** via REST API for continuous security validation

**Perfect for:**
- Cloud security assessments and audits
- Red team exercises and penetration testing
- Compliance validation (SOC 2, ISO 27001, PCI-DSS)
- Security awareness training with real misconfiguration patterns
- DevSecOps pipeline integration

---

## 🏗️ Technical Overview

CloudGuard operates in **two modes** for comprehensive cloud security coverage:

- **Scan Mode** — Read-only passive discovery of misconfigurations (safe for production)
- **Red-Team Mode** — Active exploitation simulation with multi-step attack chain building (controlled, consented testing)

All findings are **compliance-mapped** (CIS Benchmarks, OWASP Cloud Top 10, NIST CSF) with **severity scoring** for immediate prioritization and remediation tracking.

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

## ☁️ Cloud Coverage & Compliance Mapping

| Provider | Coverage | Compliance Frameworks |
|----------|----------|----------------------|
| **AWS** | S3 bucket public exposure, IAM over-permissioning, Security Group misconfiguration, CloudTrail logging gaps, KMS encryption gaps | CIS AWS Foundations, PCI-DSS, NIST 800-53 |
| **Azure** | Storage Account public access, RBAC excessive permissions, NSG rule weaknesses, Key Vault access, diagnostic logging | CIS Azure Foundations, PCI-DSS, SOC 2 Type II |
| **GCP** | Cloud Storage public ACLs, IAM binding misconfigurations, audit logging gaps, VPC firewall rules | CIS GCP Foundations, PCI-DSS, HIPAA-ready |

---

## ✨ Key Features

### Scanning & Detection
- **Dual-mode operation** — Read-only passive discovery (production-safe) or active red-teaming with controlled exploitation
- **Provider-agnostic framework** — Single interface for AWS, Azure, and GCP
- **8+ vulnerability categories** — Injection, auth bypass, data exposure, misconfiguration, compliance gaps
- **Confidence scoring** — ML-ready severity and remediation priority ranking

### Exploitation & Attack Chains
- **Multi-turn attack chains** — Simulate how misconfigurations chain into full breaches
- **Real-world attack paths** — Show business impact of security gaps to non-technical stakeholders
- **Controlled red-teaming** — Active exploitation with consent & safety gating

### Compliance & Reporting
- **Automatic CIS Benchmark mapping** — Instant compliance gap analysis
- **OWASP Cloud Top 10 alignment** — Industry-standard vulnerability classification
- **NIST CSF integration** — Map findings to NIST functions (Identify, Protect, Detect, Respond, Recover)
- **Exportable reports** — JSON/CSV for audit trails and compliance documentation

### Enterprise Integration
- **REST API** — Full integration into CI/CD, security automation, and SIEM platforms
- **Web dashboard** — Real-time scanning UI, results visualization, trend analysis
- **Concurrent scanning** — Async payload execution across multiple cloud accounts
- **Audit logging** — Complete trail of scans, exploitations, and findings for SOC 2 compliance

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

---

## 🔧 Skills Demonstrated

- **Cloud Security Architecture** — Multi-cloud security posture assessment at scale
- **API Design** — Production-grade REST APIs with async execution
- **IaC & Automation** — Terraform integration, CI/CD pipeline compatibility
- **Compliance Frameworks** — CIS Benchmarks, OWASP, NIST CSF, PCI-DSS, SOC 2
- **Attack Simulation** — Red teaming, exploit chain building, business impact assessment
- **Enterprise Software** — Dashboard UIs, multi-tenant architecture, audit logging

---

## 📊 Project Impact

- **Use Case:** Cloud risk assessments for fortune 500 companies, compliance audits, red team exercises
- **Scale:** Concurrent scanning across multiple cloud accounts and providers
- **Integration:** CI/CD pipelines, SIEM platforms, security orchestration workflows
- **Compliance Ready:** CIS, PCI-DSS, NIST, SOC 2 mappings for audit documentation

---

## 👤 Author

**Ash Clements** — Sr. Principal Security Consultant at Palo Alto Networks  
**Specialties:** Cloud Security Architecture | SASE | AI/LLM Security | IaC Automation  
**GitHub:** [BadAsh99](https://github.com/BadAsh99) | **Portfolio:** [Security Tools](https://github.com/BadAsh99?tab=repositories)
