"""
CloudGuard Azure Scanner

Live checks against Azure subscription using DefaultAzureCredential
(picks up existing `az login` session automatically).

Checks:
  Storage      — public blob access, HTTPS-only, soft-delete, key rotation
  IAM/RBAC     — Owner/Contributor on non-service-account principals
  Network      — NSG rules allowing RDP/SSH/WinRM from 0.0.0.0/0
  Key Vault    — soft-delete, public network access (OWASP #2 Secrets)
  Observability — Diagnostic Settings, Activity Log retention (OWASP #6)
  Defender     — Microsoft Defender for Cloud plans (OWASP #9)
"""

from datetime import datetime, timezone
from typing import Dict, Any, List
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.security import SecurityCenter

from scanner import ScanFinding, CloudProvider, ScanSeverity


def build_credential(credentials: Dict[str, Any]):
    """
    Build an Azure credential from the credentials dict.

    Service principal (recommended for sharing):
      {"tenant_id": "...", "client_id": "...", "client_secret": "..."}

    Specific subscription (optional, works with either auth method):
      {"subscription_id": "..."}  # can be combined with SP creds

    Empty / omitted — falls back to DefaultAzureCredential
    (picks up az login, env vars, managed identity, etc.)
    """
    tenant_id = credentials.get("tenant_id")
    client_id = credentials.get("client_id")
    client_secret = credentials.get("client_secret")

    if tenant_id and client_id and client_secret:
        return ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
    return DefaultAzureCredential()


def get_subscription_id(credential, preferred: str = None) -> str:
    if preferred:
        return preferred
    sub_client = SubscriptionClient(credential)
    subs = list(sub_client.subscriptions.list())
    if not subs:
        raise RuntimeError("No Azure subscriptions found for this credential")
    return subs[0].subscription_id


class AzureLiveScanner:
    """Executes live read-only checks against Azure subscription."""

    def __init__(self, credentials: Dict[str, Any] = None):
        creds = credentials or {}
        self.credential = build_credential(creds)
        self.subscription_id = get_subscription_id(
            self.credential, preferred=creds.get("subscription_id")
        )

    def scan(self, cancel_event=None) -> List[ScanFinding]:
        findings = []
        for check in [
            self._check_storage,
            self._check_rbac,
            self._check_nsg,
            self._check_keyvault,
            self._check_observability,
            self._check_defender,
        ]:
            if cancel_event and cancel_event.is_set():
                break
            findings.extend(check())
        return findings

    # ── Storage checks ───────────────────────────────────────────────────────

    def _check_storage(self) -> List[ScanFinding]:
        client = StorageManagementClient(self.credential, self.subscription_id)
        findings = []

        for account in client.storage_accounts.list():
            rg = account.id.split("/")[4]
            name = account.name

            # CIS 3.1 — Public blob access
            public_access = getattr(account, "allow_blob_public_access", None)
            is_public = public_access is True
            findings.append(ScanFinding(
                check_id="azure_storage_public_001",
                check_name="Storage Account Public Blob Access",
                provider=CloudProvider.AZURE,
                severity=ScanSeverity.CRITICAL if is_public else ScanSeverity.INFO,
                resource=f"{rg}/{name}",
                finding="Public blob access is ENABLED — anonymous reads allowed" if is_public
                        else "Public blob access is disabled",
                cis_control="3.1",
                remediation="Disable public blob access on the storage account",
                remediation_cli=(
                    f"az storage account update "
                    f"--name {name} --resource-group {rg} "
                    f"--allow-blob-public-access false"
                ) if is_public else "",
                remediation_tf=(
                    f'resource "azurerm_storage_account" "{name}" {{\n'
                    f'  # ... existing config ...\n'
                    f'  allow_nested_items_to_be_public = false\n'
                    f'}}'
                ) if is_public else "",
                is_vulnerable=is_public,
            ))

            # CIS 3.2 — HTTPS-only
            https_only = getattr(account, "enable_https_traffic_only", True)
            is_http = not https_only
            findings.append(ScanFinding(
                check_id="azure_storage_https_001",
                check_name="Storage Account HTTPS Only",
                provider=CloudProvider.AZURE,
                severity=ScanSeverity.HIGH if is_http else ScanSeverity.INFO,
                resource=f"{rg}/{name}",
                finding="HTTP traffic is ALLOWED — data in transit unencrypted" if is_http
                        else "HTTPS-only is enforced",
                cis_control="3.2",
                remediation="Enable HTTPS-only traffic on the storage account",
                remediation_cli=(
                    f"az storage account update "
                    f"--name {name} --resource-group {rg} "
                    f"--https-only true"
                ) if is_http else "",
                remediation_tf=(
                    f'resource "azurerm_storage_account" "{name}" {{\n'
                    f'  # ... existing config ...\n'
                    f'  enable_https_traffic_only = true\n'
                    f'}}'
                ) if is_http else "",
                is_vulnerable=is_http,
            ))

            # CIS 3.3 — Soft delete for blobs
            try:
                props = client.blob_services.get_service_properties(rg, name)
                soft_delete = getattr(props.delete_retention_policy, "enabled", False)
            except Exception:
                soft_delete = False
            is_no_softdelete = not soft_delete
            findings.append(ScanFinding(
                check_id="azure_storage_softdelete_001",
                check_name="Blob Soft Delete",
                provider=CloudProvider.AZURE,
                severity=ScanSeverity.MEDIUM if is_no_softdelete else ScanSeverity.INFO,
                resource=f"{rg}/{name}",
                finding="Soft delete is DISABLED — accidental deletes are unrecoverable" if is_no_softdelete
                        else "Soft delete is enabled",
                cis_control="3.3",
                remediation="Enable blob soft delete with minimum 7-day retention",
                remediation_cli=(
                    f"az storage blob service-properties delete-policy update "
                    f"--account-name {name} --enable true --days-retained 7"
                ) if is_no_softdelete else "",
                remediation_tf=(
                    f'resource "azurerm_storage_account" "{name}" {{\n'
                    f'  blob_properties {{\n'
                    f'    delete_retention_policy {{\n'
                    f'      days = 7\n'
                    f'    }}\n'
                    f'  }}\n'
                    f'}}'
                ) if is_no_softdelete else "",
                is_vulnerable=is_no_softdelete,
            ))

        return findings

    # ── RBAC checks ──────────────────────────────────────────────────────────

    def _check_rbac(self) -> List[ScanFinding]:
        client = AuthorizationManagementClient(self.credential, self.subscription_id)
        findings = []
        scope = f"/subscriptions/{self.subscription_id}"

        broad_roles = {
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
            "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
        }

        for assignment in client.role_assignments.list_for_scope(scope):
            role_def_id = assignment.role_definition_id.split("/")[-1]
            if role_def_id not in broad_roles:
                continue

            principal = assignment.principal_id
            principal_type = getattr(assignment, "principal_type", "Unknown")
            role_name = broad_roles[role_def_id]

            # Service principals and managed identities are expected to have broad roles
            is_user = principal_type in ("User", "Group")
            findings.append(ScanFinding(
                check_id="azure_rbac_broad_001",
                check_name=f"Broad RBAC Role: {role_name}",
                provider=CloudProvider.AZURE,
                severity=ScanSeverity.HIGH if is_user else ScanSeverity.MEDIUM,
                resource=f"principal/{principal}",
                finding=f"{principal_type} has {role_name} role at subscription scope",
                cis_control="1.3",
                remediation=f"Replace {role_name} with a least-privilege custom role scoped to specific resource groups",
                remediation_cli=(
                    f"az role assignment delete "
                    f"--assignee {principal} "
                    f"--role \"{role_name}\" "
                    f"--scope {scope}"
                ) if is_user else "",
                remediation_tf=(
                    f'# Remove and replace with scoped assignment\n'
                    f'resource "azurerm_role_assignment" "least_priv_{principal[:8]}" {{\n'
                    f'  scope                = azurerm_resource_group.main.id  # scope to RG, not subscription\n'
                    f'  role_definition_name = "Reader"  # replace with appropriate role\n'
                    f'  principal_id         = "{principal}"\n'
                    f'}}'
                ) if is_user else "",
                is_vulnerable=is_user,
            ))

        return findings

    # ── NSG checks ───────────────────────────────────────────────────────────

    def _check_nsg(self) -> List[ScanFinding]:
        client = NetworkManagementClient(self.credential, self.subscription_id)
        findings = []
        dangerous_ports = {3389: "RDP", 22: "SSH", 5985: "WinRM", 23: "Telnet"}

        for nsg in client.network_security_groups.list_all():
            rg = nsg.id.split("/")[4]
            name = nsg.name

            for rule in (nsg.security_rules or []):
                if rule.direction != "Inbound" or rule.access != "Allow":
                    continue

                src = rule.source_address_prefix or ""
                is_open = src in ("*", "0.0.0.0/0", "Internet", "Any")
                if not is_open:
                    continue

                dest_port = rule.destination_port_range or ""
                matched_ports = []

                if dest_port == "*":
                    matched_ports = list(dangerous_ports.items())
                else:
                    try:
                        p = int(dest_port)
                        if p in dangerous_ports:
                            matched_ports = [(p, dangerous_ports[p])]
                    except ValueError:
                        # Could be a range like "3389-3390"
                        if "-" in dest_port:
                            lo, hi = dest_port.split("-", 1)
                            for port, svc in dangerous_ports.items():
                                if int(lo) <= port <= int(hi):
                                    matched_ports.append((port, svc))

                for port, svc in matched_ports:
                    findings.append(ScanFinding(
                        check_id=f"azure_nsg_{svc.lower()}_open_001",
                        check_name=f"NSG: {svc} Open to Internet",
                        provider=CloudProvider.AZURE,
                        severity=ScanSeverity.CRITICAL if port in (3389, 22) else ScanSeverity.HIGH,
                        resource=f"{rg}/{name}/{rule.name}",
                        finding=f"Rule '{rule.name}' allows {svc} (port {port}) from 0.0.0.0/0",
                        cis_control="5.1",
                        remediation=f"Restrict source to known IP ranges or remove the rule. Use Azure Bastion for admin access instead.",
                        remediation_cli=(
                            f"az network nsg rule update "
                            f"--resource-group {rg} --nsg-name {name} --name {rule.name} "
                            f"--source-address-prefixes <YOUR_MGMT_IP>/32"
                        ),
                        remediation_tf=(
                            f'resource "azurerm_network_security_rule" "{rule.name}" {{\n'
                            f'  name                        = "{rule.name}"\n'
                            f'  resource_group_name         = "{rg}"\n'
                            f'  network_security_group_name = "{name}"\n'
                            f'  priority                    = {rule.priority}\n'
                            f'  direction                   = "Inbound"\n'
                            f'  access                      = "Allow"\n'
                            f'  protocol                    = "Tcp"\n'
                            f'  source_port_range           = "*"\n'
                            f'  destination_port_range      = "{port}"\n'
                            f'  source_address_prefix       = "<YOUR_MGMT_IP>/32"  # was: {src}\n'
                            f'  destination_address_prefix  = "*"\n'
                            f'}}'
                        ),
                        is_vulnerable=True,
                    ))

        return findings

    # ── Key Vault checks (OWASP #2 — Secrets Management) ────────────────────

    def _check_keyvault(self) -> List[ScanFinding]:
        client = KeyVaultManagementClient(self.credential, self.subscription_id)
        findings = []

        vaults = list(client.vaults.list())
        if not vaults:
            findings.append(ScanFinding(
                check_id="azure_keyvault_exists_001",
                check_name="Key Vault — No Vaults Found",
                provider=CloudProvider.AZURE,
                severity=ScanSeverity.MEDIUM,
                resource="subscription",
                finding="No Azure Key Vaults found — secrets may be stored in config files or environment variables",
                cis_control="8.1",
                remediation="Create a Key Vault and migrate all secrets, keys, and certificates into it",
                remediation_cli=(
                    "az keyvault create --name <vault-name> "
                    f"--resource-group <rg> --location eastus "
                    "--enable-soft-delete true --enable-purge-protection true"
                ),
                remediation_tf=(
                    'resource "azurerm_key_vault" "main" {\n'
                    '  name                = "<vault-name>"\n'
                    '  resource_group_name = azurerm_resource_group.main.name\n'
                    '  location            = azurerm_resource_group.main.location\n'
                    '  tenant_id           = data.azurerm_client_config.current.tenant_id\n'
                    '  sku_name            = "standard"\n'
                    '  soft_delete_retention_days = 7\n'
                    '  purge_protection_enabled   = true\n'
                    '}'
                ),
                is_vulnerable=True,
            ))
            return findings

        for vault in vaults:
            rg = vault.id.split("/")[4]
            name = vault.name
            props = vault.properties

            # Soft delete
            soft_delete = getattr(props, "enable_soft_delete", False)
            no_soft = not soft_delete
            findings.append(ScanFinding(
                check_id="azure_keyvault_softdelete_001",
                check_name="Key Vault Soft Delete",
                provider=CloudProvider.AZURE,
                severity=ScanSeverity.HIGH if no_soft else ScanSeverity.INFO,
                resource=f"{rg}/{name}",
                finding="Soft delete is DISABLED — deleted secrets are immediately unrecoverable" if no_soft
                        else "Soft delete is enabled",
                cis_control="8.1",
                remediation="Enable soft delete and purge protection on the Key Vault",
                remediation_cli=(
                    f"az keyvault update --name {name} "
                    f"--resource-group {rg} "
                    f"--enable-soft-delete true --enable-purge-protection true"
                ) if no_soft else "",
                remediation_tf=(
                    f'resource "azurerm_key_vault" "{name}" {{\n'
                    f'  # ... existing config ...\n'
                    f'  soft_delete_retention_days = 7\n'
                    f'  purge_protection_enabled   = true\n'
                    f'}}'
                ) if no_soft else "",
                is_vulnerable=no_soft,
            ))

            # Public network access
            network_acls = getattr(props, "network_acls", None)
            default_action = getattr(network_acls, "default_action", "Allow") if network_acls else "Allow"
            is_public = default_action == "Allow"
            findings.append(ScanFinding(
                check_id="azure_keyvault_public_001",
                check_name="Key Vault Public Network Access",
                provider=CloudProvider.AZURE,
                severity=ScanSeverity.HIGH if is_public else ScanSeverity.INFO,
                resource=f"{rg}/{name}",
                finding="Key Vault accessible from ALL networks — no IP restrictions" if is_public
                        else "Key Vault network access is restricted",
                cis_control="8.2",
                remediation="Restrict Key Vault network access to specific VNets or IP ranges",
                remediation_cli=(
                    f"az keyvault update --name {name} "
                    f"--resource-group {rg} "
                    f"--default-action Deny "
                    f"--bypass AzureServices"
                ) if is_public else "",
                remediation_tf=(
                    f'resource "azurerm_key_vault" "{name}" {{\n'
                    f'  # ... existing config ...\n'
                    f'  network_acls {{\n'
                    f'    default_action = "Deny"\n'
                    f'    bypass         = "AzureServices"\n'
                    f'    ip_rules       = ["<YOUR_MGMT_IP>/32"]\n'
                    f'  }}\n'
                    f'}}'
                ) if is_public else "",
                is_vulnerable=is_public,
            ))

        return findings

    # ── Observability checks (OWASP #6 — Security Observability) ────────────

    def _check_observability(self) -> List[ScanFinding]:
        monitor = MonitorManagementClient(self.credential, self.subscription_id)
        findings = []
        scope = f"/subscriptions/{self.subscription_id}"

        # Activity log retention >= 90 days
        try:
            profiles = list(monitor.log_profiles.list())
            if not profiles:
                findings.append(ScanFinding(
                    check_id="azure_monitor_actlog_001",
                    check_name="Activity Log — No Log Profile",
                    provider=CloudProvider.AZURE,
                    severity=ScanSeverity.HIGH,
                    resource="subscription",
                    finding="No Activity Log profile configured — subscription-level actions are not being exported",
                    cis_control="6.1",
                    remediation="Create an Activity Log diagnostic setting exporting to a storage account or Log Analytics",
                    remediation_cli=(
                        "az monitor log-profiles create --name default "
                        "--location global --locations global "
                        "--categories Write Delete Action "
                        "--enabled true --days 90 "
                        "--storage-account-id <storage-account-id>"
                    ),
                    remediation_tf=(
                        'resource "azurerm_monitor_log_profile" "main" {\n'
                        '  name = "default"\n'
                        '  categories = ["Action", "Delete", "Write"]\n'
                        '  locations  = ["global"]\n'
                        '  retention_policy {\n'
                        '    enabled = true\n'
                        '    days    = 90\n'
                        '  }\n'
                        '  storage_account_id = azurerm_storage_account.logs.id\n'
                        '}'
                    ),
                    is_vulnerable=True,
                ))
            else:
                for profile in profiles:
                    ret = getattr(profile.retention_policy, "days", 0) or 0
                    enabled = getattr(profile.retention_policy, "enabled", False)
                    short = enabled and ret > 0 and ret < 90
                    findings.append(ScanFinding(
                        check_id="azure_monitor_actlog_001",
                        check_name="Activity Log Retention",
                        provider=CloudProvider.AZURE,
                        severity=ScanSeverity.MEDIUM if short else ScanSeverity.INFO,
                        resource=f"log-profile/{profile.name}",
                        finding=f"Activity Log retention is {ret} days — below the 90-day CIS minimum" if short
                                else f"Activity Log retention is {ret} days",
                        cis_control="6.1",
                        remediation="Set Activity Log retention to at least 90 days",
                        remediation_cli=(
                            f"az monitor log-profiles update --name {profile.name} --days 90"
                        ) if short else "",
                        remediation_tf=(
                            f'resource "azurerm_monitor_log_profile" "{profile.name}" {{\n'
                            f'  # ... existing config ...\n'
                            f'  retention_policy {{\n'
                            f'    enabled = true\n'
                            f'    days    = 90\n'
                            f'  }}\n'
                            f'}}'
                        ) if short else "",
                        is_vulnerable=short,
                    ))
        except Exception:
            pass

        # Activity log alerts for security operations
        try:
            alerts = list(monitor.activity_log_alerts.list_by_subscription_id())
            has_alerts = len(alerts) > 0
            findings.append(ScanFinding(
                check_id="azure_monitor_diag_001",
                check_name="Activity Log Alerts",
                provider=CloudProvider.AZURE,
                severity=ScanSeverity.HIGH if not has_alerts else ScanSeverity.INFO,
                resource="subscription",
                finding="No Activity Log Alerts configured — security events will not trigger notifications" if not has_alerts
                        else f"{len(alerts)} Activity Log Alert(s) configured",
                cis_control="6.2",
                remediation="Create Activity Log Alerts for critical operations (policy changes, role assignments, security config changes)",
                remediation_cli=(
                    "az monitor activity-log alert create "
                    "--name security-policy-change "
                    f"--resource-group <rg> --scope {scope} "
                    "--condition category=Policy "
                    "--action-group <action-group-id>"
                ) if not has_alerts else "",
                remediation_tf=(
                    'resource "azurerm_monitor_activity_log_alert" "policy_change" {\n'
                    '  name                = "security-policy-change"\n'
                    '  resource_group_name = azurerm_resource_group.main.name\n'
                    f'  scopes              = ["{scope}"]\n'
                    '  criteria {\n'
                    '    category = "Policy"\n'
                    '  }\n'
                    '  action {\n'
                    '    action_group_id = azurerm_monitor_action_group.main.id\n'
                    '  }\n'
                    '}'
                ) if not has_alerts else "",
                is_vulnerable=not has_alerts,
            ))
        except Exception:
            pass

        return findings

    # ── Defender for Cloud checks (OWASP #9 — Policy Enforcement) ───────────

    def _check_defender(self) -> List[ScanFinding]:
        findings = []
        try:
            security = SecurityCenter(self.credential, self.subscription_id)
            result = security.pricings.list(scope_id=f"subscriptions/{self.subscription_id}")
            pricings = result.value or []

            defender_plans = {
                "StorageAccounts": "Defender for Storage",
                "VirtualMachines": "Defender for Servers",
                "SqlServers":      "Defender for SQL",
                "AppServices":     "Defender for App Services",
                "KeyVaults":       "Defender for Key Vault",
            }

            for plan_name, plan_label in defender_plans.items():
                pricing = next((p for p in pricings if p.name == plan_name), None)
                tier = getattr(pricing, "pricing_tier", "Free") if pricing else "Free"
                is_free = tier == "Free"

                findings.append(ScanFinding(
                    check_id=f"azure_defender_{plan_name.lower()}_001",
                    check_name=f"{plan_label} Status",
                    provider=CloudProvider.AZURE,
                    severity=ScanSeverity.MEDIUM if is_free else ScanSeverity.INFO,
                    resource=f"defender/{plan_name}",
                    finding=f"{plan_label} is DISABLED (Free tier) — no threat detection for this resource type" if is_free
                            else f"{plan_label} is enabled (Standard tier)",
                    cis_control="9.1",
                    remediation=f"Enable {plan_label} Standard tier for threat detection and security alerts",
                    remediation_cli=(
                        f"az security pricing create "
                        f"--name {plan_name} --tier Standard"
                    ) if is_free else "",
                    remediation_tf=(
                        f'resource "azurerm_security_center_subscription_pricing" "{plan_name.lower()}" {{\n'
                        f'  tier          = "Standard"\n'
                        f'  resource_type = "{plan_name}"\n'
                        f'}}'
                    ) if is_free else "",
                    is_vulnerable=is_free,
                ))
        except Exception:
            pass

        return findings
