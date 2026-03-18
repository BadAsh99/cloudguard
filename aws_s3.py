"""
AWS S3 Scanner and Exploiter

Tier 0 S3 checks:
- Bucket enumeration (list accessible buckets)
- Public ACL detection
- Bucket policy over-permissiveness
- Encryption status verification
- Versioning and MFA delete
- Access logging configuration
- Block public access settings
"""

import boto3
import json
from typing import Dict, List, Any, Optional
from scanner import ScanFinding, ScanSeverity


class S3Scanner:
    """AWS S3 bucket enumeration and compliance checks"""

    def __init__(self, credentials: Dict[str, Any]):
        """
        Initialize S3 scanner with AWS credentials
        
        credentials format:
        {
            "aws_access_key_id": "...",
            "aws_secret_access_key": "...",
            "region_name": "us-east-1"
        }
        """
        self.credentials = credentials
        self.s3_client = None
        self.iam_client = None
        self.findings = []

    def connect(self) -> bool:
        """Establish AWS connections"""
        try:
            self.s3_client = boto3.client(
                "s3",
                aws_access_key_id=self.credentials.get("aws_access_key_id"),
                aws_secret_access_key=self.credentials.get("aws_secret_access_key"),
                region_name=self.credentials.get("region_name", "us-east-1"),
            )
            self.iam_client = boto3.client(
                "iam",
                aws_access_key_id=self.credentials.get("aws_access_key_id"),
                aws_secret_access_key=self.credentials.get("aws_secret_access_key"),
            )
            # Test connectivity
            self.s3_client.list_buckets()
            return True
        except Exception as e:
            print(f"[S3Scanner] Auth failed: {e}")
            return False

    def scan(self) -> List[ScanFinding]:
        """Execute all S3 checks"""
        if not self.connect():
            return [
                ScanFinding(
                    check_id="aws_s3_auth_001",
                    check_name="AWS Authentication Failed",
                    provider="aws",
                    severity=ScanSeverity.CRITICAL,
                    resource="aws:s3",
                    finding="Could not authenticate to AWS. Check credentials.",
                    cis_control="2.1.5",
                    remediation="Verify AWS access key ID and secret key.",
                    is_vulnerable=True,
                )
            ]

        findings = []
        findings.extend(self._check_bucket_enumeration())
        findings.extend(self._check_public_acl())
        findings.extend(self._check_bucket_policies())
        findings.extend(self._check_encryption())
        findings.extend(self._check_versioning())
        findings.extend(self._check_access_logging())
        findings.extend(self._check_block_public_access())

        return findings

    def _check_bucket_enumeration(self) -> List[ScanFinding]:
        """CIS 2.1.5: List all buckets and their regions"""
        findings = []
        try:
            response = self.s3_client.list_buckets()
            buckets = response.get("Buckets", [])

            if not buckets:
                findings.append(
                    ScanFinding(
                        check_id="aws_s3_enum_001",
                        check_name="No S3 Buckets Found",
                        provider="aws",
                        severity=ScanSeverity.INFO,
                        resource="aws:s3:buckets",
                        finding="No S3 buckets in account.",
                        cis_control="2.1.5",
                        remediation="N/A",
                        is_vulnerable=False,
                    )
                )
            else:
                for bucket in buckets:
                    bucket_name = bucket["Name"]
                    findings.append(
                        ScanFinding(
                            check_id=f"aws_s3_enum_002",
                            check_name="S3 Bucket Enumerated",
                            provider="aws",
                            severity=ScanSeverity.INFO,
                            resource=f"s3://{bucket_name}",
                            finding=f"Bucket enumerated: {bucket_name}",
                            cis_control="2.1.5",
                            remediation="N/A (informational)",
                            is_vulnerable=False,
                        )
                    )
        except Exception as e:
            findings.append(
                ScanFinding(
                    check_id="aws_s3_enum_err",
                    check_name="Bucket Enumeration Error",
                    provider="aws",
                    severity=ScanSeverity.MEDIUM,
                    resource="aws:s3",
                    finding=f"Error enumerating buckets: {str(e)}",
                    cis_control="2.1.5",
                    remediation="Check IAM permissions.",
                    is_vulnerable=True,
                )
            )
        return findings

    def _check_public_acl(self) -> List[ScanFinding]:
        """CIS 2.1.5: Detect public ACLs (PublicRead, PublicReadWrite, AuthenticatedRead)"""
        findings = []
        try:
            response = self.s3_client.list_buckets()
            buckets = response.get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]
                try:
                    # Get bucket ACL
                    acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
                    grants = acl.get("Grants", [])

                    for grant in grants:
                        grantee = grant.get("Grantee", {})
                        grantee_type = grantee.get("Type", "")
                        permission = grant.get("Permission", "")

                        # Check for public access
                        if grantee_type == "Group" and "AllUsers" in grantee.get("URI", ""):
                            findings.append(
                                ScanFinding(
                                    check_id="aws_s3_public_acl_001",
                                    check_name="S3 Bucket Public ACL (PublicRead/Write)",
                                    provider="aws",
                                    severity=ScanSeverity.CRITICAL,
                                    resource=f"s3://{bucket_name}",
                                    finding=f"Bucket allows {permission} to everyone (AllUsers).",
                                    cis_control="2.1.5",
                                    remediation="Remove public ACL: aws s3api put-bucket-acl --bucket {} --acl private".format(bucket_name),
                                    is_vulnerable=True,
                                )
                            )

                        # Check for authenticated users
                        elif grantee_type == "Group" and "AuthenticatedUsers" in grantee.get("URI", ""):
                            findings.append(
                                ScanFinding(
                                    check_id="aws_s3_auth_acl_001",
                                    check_name="S3 Bucket AuthenticatedUsers ACL",
                                    provider="aws",
                                    severity=ScanSeverity.HIGH,
                                    resource=f"s3://{bucket_name}",
                                    finding=f"Bucket allows {permission} to AWS authenticated users.",
                                    cis_control="2.1.5",
                                    remediation="Remove AuthenticatedUsers ACL: aws s3api put-bucket-acl --bucket {} --acl private".format(bucket_name),
                                    is_vulnerable=True,
                                )
                            )
                except self.s3_client.exceptions.NoSuchBucket:
                    pass
                except Exception as e:
                    pass

        except Exception as e:
            pass

        return findings

    def _check_bucket_policies(self) -> List[ScanFinding]:
        """Check for overly permissive bucket policies (Principal: *)"""
        findings = []
        try:
            response = self.s3_client.list_buckets()
            buckets = response.get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]
                try:
                    policy_response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_str = policy_response.get("Policy", "{}")
                    policy = json.loads(policy_str)

                    statements = policy.get("Statement", [])
                    for stmt in statements:
                        principal = stmt.get("Principal", "")
                        effect = stmt.get("Effect", "")
                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]

                        # Check for wildcard principal with Allow
                        if (
                            effect == "Allow"
                            and (principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"))
                        ):
                            findings.append(
                                ScanFinding(
                                    check_id="aws_s3_policy_001",
                                    check_name="S3 Bucket Policy Allows Principal *",
                                    provider="aws",
                                    severity=ScanSeverity.CRITICAL,
                                    resource=f"s3://{bucket_name}",
                                    finding=f"Bucket policy allows Principal * with actions: {', '.join(actions)}",
                                    cis_control="2.1.5",
                                    remediation="Remove wildcard principal: aws s3api delete-bucket-policy --bucket {}".format(bucket_name),
                                    is_vulnerable=True,
                                )
                            )
                except self.s3_client.exceptions.NoSuchBucketPolicy:
                    pass
                except Exception as e:
                    pass

        except Exception as e:
            pass

        return findings

    def _check_encryption(self) -> List[ScanFinding]:
        """CIS 2.1.3: Verify S3 encryption is enabled (SSE-S3 or SSE-KMS)"""
        findings = []
        try:
            response = self.s3_client.list_buckets()
            buckets = response.get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]
                try:
                    encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
                    rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

                    if not rules:
                        findings.append(
                            ScanFinding(
                                check_id="aws_s3_encrypt_001",
                                check_name="S3 Bucket Encryption Not Enabled",
                                provider="aws",
                                severity=ScanSeverity.HIGH,
                                resource=f"s3://{bucket_name}",
                                finding="No default encryption configured.",
                                cis_control="2.1.3",
                                remediation="Enable encryption: aws s3api put-bucket-encryption --bucket {} --server-side-encryption-configuration file://encryption.json".format(bucket_name),
                                is_vulnerable=True,
                            )
                        )
                    else:
                        for rule in rules:
                            sse = rule.get("ApplyServerSideEncryptionByDefault", {})
                            algo = sse.get("SSEAlgorithm", "")
                            findings.append(
                                ScanFinding(
                                    check_id="aws_s3_encrypt_002",
                                    check_name="S3 Bucket Encryption Enabled",
                                    provider="aws",
                                    severity=ScanSeverity.INFO,
                                    resource=f"s3://{bucket_name}",
                                    finding=f"Encryption enabled: {algo}",
                                    cis_control="2.1.3",
                                    remediation="N/A (compliant)",
                                    is_vulnerable=False,
                                )
                            )
                except self.s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                    findings.append(
                        ScanFinding(
                            check_id="aws_s3_encrypt_001",
                            check_name="S3 Bucket Encryption Not Enabled",
                            provider="aws",
                            severity=ScanSeverity.HIGH,
                            resource=f"s3://{bucket_name}",
                            finding="No default encryption configured.",
                            cis_control="2.1.3",
                            remediation="Enable encryption: aws s3api put-bucket-encryption --bucket {} --server-side-encryption-configuration file://encryption.json".format(bucket_name),
                            is_vulnerable=True,
                        )
                    )
                except Exception as e:
                    pass

        except Exception as e:
            pass

        return findings

    def _check_versioning(self) -> List[ScanFinding]:
        """Check if versioning is enabled (defense against accidental deletion)"""
        findings = []
        try:
            response = self.s3_client.list_buckets()
            buckets = response.get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]
                try:
                    versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
                    status = versioning.get("Status", "")

                    if status != "Enabled":
                        findings.append(
                            ScanFinding(
                                check_id="aws_s3_version_001",
                                check_name="S3 Bucket Versioning Not Enabled",
                                provider="aws",
                                severity=ScanSeverity.MEDIUM,
                                resource=f"s3://{bucket_name}",
                                finding="Versioning is disabled. Cannot recover deleted objects.",
                                cis_control="2.1.4",
                                remediation="Enable versioning: aws s3api put-bucket-versioning --bucket {} --versioning-configuration Status=Enabled".format(bucket_name),
                                is_vulnerable=True,
                            )
                        )
                    else:
                        findings.append(
                            ScanFinding(
                                check_id="aws_s3_version_002",
                                check_name="S3 Bucket Versioning Enabled",
                                provider="aws",
                                severity=ScanSeverity.INFO,
                                resource=f"s3://{bucket_name}",
                                finding="Versioning is enabled.",
                                cis_control="2.1.4",
                                remediation="N/A (compliant)",
                                is_vulnerable=False,
                            )
                        )
                except Exception as e:
                    pass

        except Exception as e:
            pass

        return findings

    def _check_access_logging(self) -> List[ScanFinding]:
        """Check if access logging is enabled (CIS 2.1.5)"""
        findings = []
        try:
            response = self.s3_client.list_buckets()
            buckets = response.get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]
                try:
                    logging = self.s3_client.get_bucket_logging(Bucket=bucket_name)
                    log_config = logging.get("LoggingEnabled")

                    if not log_config:
                        findings.append(
                            ScanFinding(
                                check_id="aws_s3_logging_001",
                                check_name="S3 Bucket Access Logging Not Enabled",
                                provider="aws",
                                severity=ScanSeverity.MEDIUM,
                                resource=f"s3://{bucket_name}",
                                finding="Access logging is not configured.",
                                cis_control="2.1.5",
                                remediation="Enable logging: aws s3api put-bucket-logging --bucket {} --bucket-logging-status file://logging.json".format(bucket_name),
                                is_vulnerable=True,
                            )
                        )
                    else:
                        target = log_config.get("TargetBucket", "")
                        findings.append(
                            ScanFinding(
                                check_id="aws_s3_logging_002",
                                check_name="S3 Bucket Access Logging Enabled",
                                provider="aws",
                                severity=ScanSeverity.INFO,
                                resource=f"s3://{bucket_name}",
                                finding=f"Logging to {target}",
                                cis_control="2.1.5",
                                remediation="N/A (compliant)",
                                is_vulnerable=False,
                            )
                        )
                except Exception as e:
                    pass

        except Exception as e:
            pass

        return findings

    def _check_block_public_access(self) -> List[ScanFinding]:
        """Check if S3 Block Public Access is enabled"""
        findings = []
        try:
            response = self.s3_client.list_buckets()
            buckets = response.get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]
                try:
                    bpa = self.s3_client.get_public_access_block(Bucket=bucket_name)
                    config = bpa.get("PublicAccessBlockConfiguration", {})

                    block_acl = config.get("BlockPublicAcls", False)
                    block_policy = config.get("BlockPublicPolicy", False)
                    ignore_acl = config.get("IgnorePublicAcls", False)
                    restrict_policy = config.get("RestrictPublicBuckets", False)

                    if all([block_acl, block_policy, ignore_acl, restrict_policy]):
                        findings.append(
                            ScanFinding(
                                check_id="aws_s3_bpa_002",
                                check_name="S3 Block Public Access Fully Enabled",
                                provider="aws",
                                severity=ScanSeverity.INFO,
                                resource=f"s3://{bucket_name}",
                                finding="All BPA settings enabled.",
                                cis_control="2.1.5",
                                remediation="N/A (compliant)",
                                is_vulnerable=False,
                            )
                        )
                    else:
                        findings.append(
                            ScanFinding(
                                check_id="aws_s3_bpa_001",
                                check_name="S3 Block Public Access Not Fully Enabled",
                                provider="aws",
                                severity=ScanSeverity.HIGH,
                                resource=f"s3://{bucket_name}",
                                finding="BPA incomplete: BlockAcls={}, BlockPolicy={}, IgnoreAcls={}, RestrictPolicy={}".format(block_acl, block_policy, ignore_acl, restrict_policy),
                                cis_control="2.1.5",
                                remediation="Enable all BPA settings: aws s3api put-public-access-block --bucket {} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true".format(bucket_name),
                                is_vulnerable=True,
                            )
                        )
                except self.s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                    findings.append(
                        ScanFinding(
                            check_id="aws_s3_bpa_001",
                            check_name="S3 Block Public Access Not Enabled",
                            provider="aws",
                            severity=ScanSeverity.HIGH,
                            resource=f"s3://{bucket_name}",
                            finding="Block Public Access not configured.",
                            cis_control="2.1.5",
                            remediation="Enable BPA: aws s3api put-public-access-block --bucket {} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true".format(bucket_name),
                            is_vulnerable=True,
                        )
                    )
                except Exception as e:
                    pass

        except Exception as e:
            pass

        return findings


class S3Exploiter:
    """AWS S3 active exploitation (red-team mode)"""

    def __init__(self, credentials: Dict[str, Any]):
        self.credentials = credentials
        self.s3_client = None

    def connect(self) -> bool:
        """Establish AWS connection"""
        try:
            self.s3_client = boto3.client(
                "s3",
                aws_access_key_id=self.credentials.get("aws_access_key_id"),
                aws_secret_access_key=self.credentials.get("aws_secret_access_key"),
                region_name=self.credentials.get("region_name", "us-east-1"),
            )
            self.s3_client.list_buckets()
            return True
        except Exception as e:
            print(f"[S3Exploiter] Auth failed: {e}")
            return False

    def exploit_public_access(self, bucket_name: str, object_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Try to access/download object from public bucket
        
        Returns:
        {
            "success": bool,
            "bucket": str,
            "object": str,
            "data_size": int,
            "message": str
        }
        """
        try:
            if object_key:
                # Try specific object
                response = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
                data = response["Body"].read()
                return {
                    "success": True,
                    "bucket": bucket_name,
                    "object": object_key,
                    "data_size": len(data),
                    "message": f"Successfully downloaded {object_key} ({len(data)} bytes)",
                }
            else:
                # List objects
                response = self.s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=5)
                objects = response.get("Contents", [])
                return {
                    "success": True,
                    "bucket": bucket_name,
                    "objects_found": len(objects),
                    "objects": [obj["Key"] for obj in objects[:5]],
                    "message": f"Successfully listed {len(objects)} objects",
                }
        except Exception as e:
            return {
                "success": False,
                "bucket": bucket_name,
                "object": object_key,
                "message": f"Exploitation failed: {str(e)}",
            }
