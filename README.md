# CloudGuard - Cloud Red-Teaming & Compliance Scanner

A cloud security red-teaming framework for discovering and exploiting cloud misconfigurations. Models attack patterns like LLMGuard, with payloads targeting CIS Benchmarks, OWASP Cloud Top 10, and NIST CSF.

## Architecture

**Mode Toggle:**
- **Scan Mode** (Discovery): Read-only enumeration of cloud misconfigurations. Safe, no resource modification.
- **Red-Team Mode** (Exploitation): Active exploitation of discovered issues. Shows real attack chains and impact.

**Coverage (Tier 0):**
- AWS: S3 exposure, IAM over-permission, Security Group misconfiguration, CloudTrail gaps
- Azure: Storage Account public access, RBAC over-permission, Network Security Group misconfiguration
- GCP: Cloud Storage public ACLs, IAM binding over-permission, Audit logging gaps

**Detection Patterns:**
- Payload library (like LLMGuard)
- Behavioral analysis (expected vs. actual cloud behavior)
- Multi-turn attack chains (misconfiguration A + B = full breach)
- Risk scoring aligned to CIS Benchmarks

## Setup

```bash
cd /home/parallels/Code/my-dev-environments/cloudguard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Visit: `http://localhost:5000`

## API

### POST `/api/scan`
Discover misconfiguration (read-only)
```json
{
  "provider": "aws|azure|gcp",
  "credentials": {...},
  "mode": "scan"
}
```

### POST `/api/redteam`
Execute exploitation (active)
```json
{
  "provider": "aws|azure|gcp",
  "credentials": {...},
  "mode": "redteam",
  "findings": [...],
  "confirm_exploitation": true
}
```

### GET `/api/payloads/<provider>`
List available payloads for a provider

## Phase 1: Scaffold ✅

- [x] Flask skeleton
- [x] Mode toggle (Scan/Red-Team UI)
- [x] Payload framework (scanner.py)
- [x] Exploitation framework (exploiter.py)
- [x] API endpoints (app.py)
- [x] Dashboard UI (index.html)
- [x] Environment config (.env)

## Phase 2: Tier 0 Implementation (Next)

- [ ] AWS boto3 integration (S3, IAM, SG, CloudTrail)
- [ ] Azure SDK integration (Storage, RBAC, NSG)
- [ ] GCP integration (Cloud Storage, IAM, Audit Logs)
- [ ] Actual exploitation logic (not just stubs)
- [ ] Multi-turn attack chain builder
- [ ] CIS Benchmark scoring

## Phase 3: Tier 1+ (Future)

- [ ] Kubernetes/container scanning
- [ ] IAM privilege escalation mapping
- [ ] CI/CD pipeline validation
- [ ] Behavioral detection (semantic matching)
