"""
CloudGuard Result Model - Aligned with llmguardt2 presentation

Maps cloud security findings to status + confidence model,
grouped by CIS control families.
"""

from typing import Dict, List, Any
from pydantic import BaseModel
from enum import Enum


class FindingStatus(str, Enum):
    """Status levels (aligned with llmguardt2)"""
    VULNERABLE = "vulnerable"  # Misconfiguration confirmed exploitable
    PARTIAL = "partial"         # Misconfiguration found, but with some mitigations
    RESISTANT = "resistant"     # Control properly implemented
    REVIEW = "review"           # Ambiguous, requires manual inspection


class CISCategory(str, Enum):
    """CIS Cloud Security Benchmark categories"""
    IAM = "1"                   # Identity & access management
    STORAGE = "2"               # Storage & data protection
    LOGGING = "6"               # Logging & monitoring / observability
    NETWORKING = "5"            # Network security
    COMPLIANCE = "3"            # Compliance
    SECRETS = "8"               # Secrets management (Key Vault)
    POLICY = "9"                # Policy enforcement (Defender)


class EnhancedFinding(BaseModel):
    """Enhanced finding with status, confidence, category grouping"""
    check_id: str
    check_name: str
    resource: str
    status: FindingStatus          # VULNERABLE | PARTIAL | RESISTANT | REVIEW
    confidence: int                # 0-100%
    cis_control: str               # "2.1.5", "3.1", etc.
    cis_category: CISCategory      # For grouping in UI
    severity_original: str         # Original severity (CRITICAL, HIGH, etc.)
    finding: str
    remediation: str
    remediation_cli: str = ""      # Exact CLI command to fix (az / gcloud / aws)
    remediation_tf: str = ""       # Drop-in Terraform resource block
    is_vulnerable: bool


class CategoryResults(BaseModel):
    """Results grouped by CIS category"""
    category: CISCategory
    category_name: str
    findings: List[EnhancedFinding]
    compliance_percentage: int     # % of findings in RESISTANT status
    count_vulnerable: int
    count_partial: int
    count_resistant: int
    count_review: int


class ScanSummary(BaseModel):
    """Overall scan result (llmguardt2-style)"""
    provider: str
    scan_type: str                 # "scan" | "redteam"
    overall_compliance: int        # 0-100%
    overall_risk_score: int        # 0-100 (inverse of compliance)
    total_findings: int
    categories: List[CategoryResults]
    
    # Breakdown
    vulnerable_count: int          # VULNERABLE status
    partial_count: int             # PARTIAL status
    resistant_count: int           # RESISTANT status
    review_count: int              # REVIEW status
    
    # Risk distribution
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int


def map_severity_to_status(severity: str, is_vulnerable: bool) -> FindingStatus:
    """Map cloud severity to llmguardt2 status model"""
    if not is_vulnerable:
        return FindingStatus.RESISTANT
    
    severity_lower = severity.lower()
    if severity_lower == "critical":
        return FindingStatus.VULNERABLE
    elif severity_lower == "high":
        return FindingStatus.PARTIAL
    elif severity_lower == "medium":
        return FindingStatus.REVIEW
    else:
        return FindingStatus.RESISTANT


def calculate_confidence(severity: str, is_vulnerable: bool, check_type: str = "acl") -> int:
    """Calculate confidence score (0-100) based on finding severity"""
    if not is_vulnerable:
        return 95  # High confidence that it's compliant
    
    base_scores = {
        "critical": 90,
        "high": 70,
        "medium": 50,
        "low": 30,
        "info": 10,
    }
    
    confidence = base_scores.get(severity.lower(), 50)
    
    # Boost for high-confidence check types
    if check_type in ["public_acl", "public_policy"]:
        confidence = min(100, confidence + 10)
    
    return confidence


def get_cis_category(cis_control: str) -> CISCategory:
    """Map CIS control to category"""
    if cis_control.startswith("1"):
        return CISCategory.IAM
    elif cis_control.startswith("2") or cis_control.startswith("3"):
        return CISCategory.STORAGE
    elif cis_control.startswith("5"):
        return CISCategory.NETWORKING
    elif cis_control.startswith("6"):
        return CISCategory.LOGGING
    elif cis_control.startswith("8"):
        return CISCategory.SECRETS
    elif cis_control.startswith("9"):
        return CISCategory.POLICY
    else:
        return CISCategory.STORAGE  # Default


def get_category_name(category: CISCategory) -> str:
    """Get human-readable category name"""
    names = {
        CISCategory.IAM: "Identity & Access (1)",
        CISCategory.STORAGE: "Storage & Data Protection (2/3)",
        CISCategory.NETWORKING: "Network Security (5)",
        CISCategory.LOGGING: "Observability & Logging (6)",
        CISCategory.SECRETS: "Secrets Management (8)",
        CISCategory.POLICY: "Policy Enforcement (9)",
        CISCategory.COMPLIANCE: "Compliance (3)",
    }
    return names.get(category, "Unknown")
