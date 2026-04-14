# CloudGuard — Project Context

## What This Is
A Flask-based cloud security posture scanner with red-team capabilities. Scans Azure, AWS, and GCP for misconfigurations mapped to CIS Benchmark controls. Generates executive PDF reports. Portfolio/production tool.

## Architecture
```
Flask App (app.py, port 5000)
  ├── /api/scan        → read-only discovery (scanner.py → azure_scanner.py / aws_s3.py)
  ├── /api/redteam     → active exploitation (exploiter.py)
  ├── /api/export/pdf  → PDF report generation (pdf_report.py)
  └── /api/payloads    → payload registry

Result pipeline: raw ScanFinding → result_model.py (EnhancedFinding/ScanSummary) → JSON/PDF
```

## Service Map
| Component | File | Status |
|---|---|---|
| Flask API | `app.py` | Complete |
| Azure Scanner | `azure_scanner.py` | Complete — live Azure SDK calls |
| AWS S3 Scanner | `aws_s3.py` | Complete — S3 only (7 checks) |
| GCP Scanner | `scanner.py` (GCPScanner) | **STUB — returns []** |
| AWS Exploiter | `aws_s3.py` (S3Exploiter) | Partial — S3 only, real API calls |
| Azure Exploiter | `exploiter.py` (AzureExploiter) | **STUB — returns BLOCKED** |
| GCP Exploiter | `exploiter.py` (GCPExploiter) | **STUB — returns BLOCKED** |
| Attack chains | `exploiter.py` (build_attack_chain) | **STUB — returns []** |
| PDF Report | `pdf_report.py` | Complete |
| Result model | `result_model.py` | Complete |
| UI | `templates/index.html` | Complete |

## Run
```bash
cd /home/parallels/Code/my-dev-environments/cloudguard
source venv/bin/activate
python app.py
# → http://127.0.0.1:5000
```

## Azure Auth
Uses `DefaultAzureCredential` — picks up `az login` session automatically. Empty `{}` credentials work for Azure.

## Current Status (as of 2026-03-23)
### Done
- Azure scanner: Storage (public access, HTTPS, soft-delete), RBAC (Owner/Contributor), NSG (RDP/SSH open), Key Vault, Observability, Defender
- AWS S3: 7 checks (public ACL, encryption, versioning, logging, Block Public Access)
- PDF export with executive summary, severity breakdown, category compliance, detailed findings + CLI/Terraform remediation
- Dual-mode UI (scan + red-team toggle)
- XSS fixed — all API data escaped via `esc()` helper before `innerHTML`
- PDF spacing fix — `spaceAfter`/`spaceBefore` added to body/small/code styles

### Next Priorities (in order)
1. Input validation on `/api/export/pdf` — validate against ScanSummary Pydantic model
2. AWS IAM + Security Group checks — payloads registered but not coded into scanner
3. GCP scanner — completely unimplemented
4. Azure/GCP exploiters — stubs
5. Attack chain logic

## Known Issues
- PDF code block line wrapping: long CLI commands wrap without continuation indent (cosmetic)
- Silent `except: pass` in AWS/Azure scanners — permission failures look like passing checks

## Key Files
- `app.py` — Flask API, scan/redteam/export endpoints
- `azure_scanner.py` — Azure live checks (580 lines, fully implemented)
- `aws_s3.py` — AWS S3 scanner + exploiter
- `exploiter.py` — exploitation framework (Azure/GCP stubs)
- `scanner.py` — payload registry, base classes, GCP stub
- `pdf_report.py` — ReportLab PDF generation
- `result_model.py` — ScanFinding → EnhancedFinding → ScanSummary pipeline
- `templates/index.html` — dual-mode UI

## Security Notes (audit findings — not yet fixed)
- C-3: No auth on any endpoint — red-team confirm_exploitation is just a JSON flag
- H-1: Global `_cancel_scan` threading.Event — race condition, unauthenticated DoS
- H-3: Silent exception swallowing in scanners masks permission failures
- H-4: Empty `{}` creds fall back to IMDS — dangerous on cloud-hosted VM
- M-5: No security response headers (no CSP, X-Frame-Options, etc.)
