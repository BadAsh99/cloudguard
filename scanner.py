"""
CloudGuard Scanner - CIS/OWASP Cloud Payload Framework

Tier 0: AWS, Azure, GCP basic checks
- Misconfiguration discovery (read-only)
- CIS Benchmark alignment
- Risk scoring
"""

from typing import Dict, List, Any
from pydantic import BaseModel
from enum import Enum


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class ScanSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanFinding(BaseModel):
    """Result of a single scan check"""
    check_id: str
    check_name: str
    provider: CloudProvider
    severity: ScanSeverity
    resource: str
    finding: str
    cis_control: str
    remediation: str
    is_vulnerable: bool


class Payload(BaseModel):
    """Reusable payload template (like LLMGuard)"""
    payload_id: str
    name: str
    description: str
    category: str  # "Storage", "IAM", "Network", "Logging"
    cis_control: str
    provider: CloudProvider
    check_func: str  # Function name to call


class Scanner:
    """Base scanner for cloud misconfiguration discovery"""

    def __init__(self, provider: CloudProvider):
        self.provider = provider
        self.findings: List[ScanFinding] = []

    def scan(self, credentials: Dict[str, Any]) -> List[ScanFinding]:
        """Execute scan (provider-specific implementation)"""
        raise NotImplementedError

    def score_risk(self, findings: List[ScanFinding]) -> Dict[str, Any]:
        """Generate CIS compliance score and risk metrics"""
        critical = len([f for f in findings if f.severity == ScanSeverity.CRITICAL])
        high = len([f for f in findings if f.severity == ScanSeverity.HIGH])
        medium = len([f for f in findings if f.severity == ScanSeverity.MEDIUM])

        risk_score = (critical * 10) + (high * 5) + (medium * 2)
        compliance_pct = max(0, 100 - risk_score)

        return {
            "risk_score": risk_score,
            "compliance_percentage": compliance_pct,
            "critical_issues": critical,
            "high_issues": high,
            "medium_issues": medium,
        }


class AWSScanner(Scanner):
    """AWS S3, IAM, Security Groups, CloudTrail checks"""

    def __init__(self):
        super().__init__(CloudProvider.AWS)
        self.payloads = [
            Payload(
                payload_id="aws_s3_public_001",
                name="S3 Bucket Public Access",
                description="Check if S3 bucket allows public read/write via ACL or policy",
                category="Storage",
                cis_control="2.1.5",
                provider=CloudProvider.AWS,
                check_func="check_s3_public_acl",
            ),
            Payload(
                payload_id="aws_s3_encrypt_001",
                name="S3 Bucket Encryption Status",
                description="Verify default encryption enabled (SSE-S3 or SSE-KMS)",
                category="Storage",
                cis_control="2.1.3",
                provider=CloudProvider.AWS,
                check_func="check_s3_encryption",
            ),
            Payload(
                payload_id="aws_s3_bpa_001",
                name="S3 Block Public Access",
                description="Check if Block Public Access is fully enabled",
                category="Storage",
                cis_control="2.1.5",
                provider=CloudProvider.AWS,
                check_func="check_s3_block_public_access",
            ),
            Payload(
                payload_id="aws_s3_version_001",
                name="S3 Bucket Versioning",
                description="Detect if versioning is enabled (defense against deletion)",
                category="Storage",
                cis_control="2.1.4",
                provider=CloudProvider.AWS,
                check_func="check_s3_versioning",
            ),
            Payload(
                payload_id="aws_s3_logging_001",
                name="S3 Access Logging",
                description="Verify S3 access logging is configured",
                category="Logging",
                cis_control="2.1.5",
                provider=CloudProvider.AWS,
                check_func="check_s3_logging",
            ),
            Payload(
                payload_id="aws_iam_overperm_001",
                name="IAM Over-Permissive Policy",
                description="Detect IAM roles with overly broad permissions",
                category="IAM",
                cis_control="1.1.4",
                provider=CloudProvider.AWS,
                check_func="check_iam_wildcard_policies",
            ),
            Payload(
                payload_id="aws_sg_open_001",
                name="Security Group Overly Open",
                description="Check for 0.0.0.0/0 ingress on sensitive ports",
                category="Network",
                cis_control="5.1.1",
                provider=CloudProvider.AWS,
                check_func="check_sg_open_ports",
            ),
            Payload(
                payload_id="aws_cloudtrail_001",
                name="CloudTrail Disabled/Misconfigured",
                description="Verify CloudTrail logging is enabled and monitored",
                category="Logging",
                cis_control="3.1",
                provider=CloudProvider.AWS,
                check_func="check_cloudtrail_enabled",
            ),
        ]

    def scan(self, credentials: Dict[str, Any]) -> List[ScanFinding]:
        """Execute AWS S3 scan"""
        from aws_s3 import S3Scanner
        
        s3_scanner = S3Scanner(credentials)
        findings = s3_scanner.scan()
        return findings


class AzureScanner(Scanner):
    """Azure Storage, RBAC, Network Security checks"""

    def __init__(self):
        super().__init__(CloudProvider.AZURE)
        self.payloads = [
            Payload(
                payload_id="azure_storage_public_001",
                name="Storage Account Public Access",
                description="Check if Azure Storage allows public blob access",
                category="Storage",
                cis_control="2.1.3",
                provider=CloudProvider.AZURE,
                check_func="check_storage_public_acl",
            ),
            Payload(
                payload_id="azure_rbac_overperm_001",
                name="RBAC Over-Permissive Assignment",
                description="Detect Owner/Contributor roles on non-service accounts",
                category="IAM",
                cis_control="1.3",
                provider=CloudProvider.AZURE,
                check_func="check_rbac_overpermissive",
            ),
            Payload(
                payload_id="azure_nsg_001",
                name="Network Security Group Overly Open",
                description="Check for RDP/SSH open to 0.0.0.0/0",
                category="Network",
                cis_control="5.1",
                provider=CloudProvider.AZURE,
                check_func="check_nsg_open",
            ),
        ]

    def scan(self, credentials: Dict[str, Any]) -> List[ScanFinding]:
        """Placeholder: Will implement Azure SDK integration"""
        print("[AzureScanner] Scan mode: read-only checks (no credentials used yet)")
        return []


class GCPScanner(Scanner):
    """GCP Cloud Storage, IAM Binding, VPC checks"""

    def __init__(self):
        super().__init__(CloudProvider.GCP)
        self.payloads = [
            Payload(
                payload_id="gcp_cs_public_001",
                name="Cloud Storage Public ACL",
                description="Check if bucket allows public read/write",
                category="Storage",
                cis_control="2.1.2",
                provider=CloudProvider.GCP,
                check_func="check_cs_public_iam",
            ),
            Payload(
                payload_id="gcp_iam_overperm_001",
                name="IAM Binding Over-Permissive",
                description="Detect Editor/Owner roles on non-service accounts",
                category="IAM",
                cis_control="1.2",
                provider=CloudProvider.GCP,
                check_func="check_iam_overpermissive",
            ),
            Payload(
                payload_id="gcp_audit_001",
                name="Audit Logging Disabled",
                description="Verify Cloud Audit Logs are enabled",
                category="Logging",
                cis_control="2.2.1",
                provider=CloudProvider.GCP,
                check_func="check_audit_logging",
            ),
        ]

    def scan(self, credentials: Dict[str, Any]) -> List[ScanFinding]:
        """Placeholder: Will implement Google Cloud SDK integration"""
        print("[GCPScanner] Scan mode: read-only checks (no credentials used yet)")
        return []
