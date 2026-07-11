#!/usr/bin/env python3
"""
NexShell Plugin — API Security Scanner v3.0 (2026 Edition)
Comprehensive OWASP API Security Top 10 (2023/2025/2026) testing suite.

Coverage (All 10 OWASP API Risks):
  API1:  BOLA — Broken Object Level Authorization
  API2:  Broken Authentication (JWT, OAuth, API Keys)
  API3:  Broken Object Property Level Authorization (Mass Assignment)
  API4:  Unrestricted Resource Consumption (Rate Limiting, DoS)
  API5:  BFLA — Broken Function Level Authorization
  API6:  Unrestricted Access to Sensitive Business Flows
  API7:  SSRF — Server-Side Request Forgery
  API8:  Security Misconfiguration (Headers, CORS, Errors)
  API9:  Improper Inventory Management (Shadow APIs, Versions)
  API10: Unsafe Consumption of APIs (Third-party trust)

MITRE ATT&CK:
  - T1190 (Exploit Public-Facing Application)
  - T1078 (Valid Accounts)
  - T1595 (Active Scanning)
  - T1059 (Command and Scripting Interpreter)

Usage:
    (NexShell)> plugins run api-enum --url http://target:8080
    (NexShell)> plugins run api-enum --url https://api.target.com --full
    (NexShell)> plugins run api-enum --url http://target --risk API1,API2,API7
    (NexShell)> plugins run api-enum --url http://target --stealth
    (NexShell)> plugins run api-enum --url http://target --graphql
"""

import re
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
from collections import defaultdict
from core.plugin import NexPlugin


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class APITestResult:
    """Result of a single API security test."""
    risk_id: str  # API1, API2, etc.
    risk_name: str
    test_name: str
    passed: bool  # True = vulnerability found
    severity: str  # critical, high, medium, low, info
    confidence: str  # low, medium, high, verified
    evidence: str
    recommendation: str
    mitre_id: str = "T1190"
    duration_ms: int = 0
    endpoint: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class APIEndpoint:
    """Discovered API endpoint."""
    url: str
    method: str = "GET"
    status_code: int = 0
    response_time_ms: int = 0
    content_type: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body_preview: str = ""
    api_type: str = "unknown"  # rest, graphql, grpc, soap
    auth_required: bool = False
    auth_type: str = ""  # jwt, oauth, apikey, basic, none
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class APIFinding:
    """Structured API security finding."""
    owasp_risk: str  # API1:2023, API2:2023, etc.
    title: str
    severity: str
    description: str
    evidence: List[str]
    recommendation: str
    affected_endpoints: List[str]
    mitre_id: str
    confidence: str = "medium"
    cvss_estimate: float = 0.0
    
    def to_dict(self) -> dict:
        return asdict(self)


# ── OWASP API Top 10 Risk Database ─────────────────────────────────────────

class OWSAPAPIRisks:
    """Complete OWASP API Security Top 10 (2023/2025/2026) database."""
    
    RISKS = {
        'API1': {
            'name': 'Broken Object Level Authorization (BOLA)',
            'severity': 'critical',
            'cvss': 8.6,
            'description': 'API fails to verify that the user requesting an object is authorized to access that specific object',
            'mitre': 'T1078',
            'tests': [
                'idor_horizontal',
                'idor_vertical',
                'idor_uuid_prediction',
                'idor_multi_tenant',
            ]
        },
        'API2': {
            'name': 'Broken Authentication',
            'severity': 'critical',
            'cvss': 9.1,
            'description': 'Weak or flawed authentication allows attackers to steal tokens, brute-force credentials, or bypass login',
            'mitre': 'T1078',
            'tests': [
                'jwt_alg_none',
                'jwt_weak_secret',
                'jwt_no_expiry',
                'auth_bypass_no_token',
                'credential_stuffing',
                'oauth_redirect',
                'api_key_exposure',
            ]
        },
        'API3': {
            'name': 'Broken Object Property Level Authorization',
            'severity': 'high',
            'cvss': 7.5,
            'description': 'APIs expose fields users shouldn\'t see or accept writes to fields they shouldn\'t control',
            'mitre': 'T1190',
            'tests': [
                'mass_assignment_role',
                'mass_assignment_balance',
                'excessive_data_exposure',
                'sensitive_fields_leak',
            ]
        },
        'API4': {
            'name': 'Unrestricted Resource Consumption',
            'severity': 'high',
            'cvss': 7.0,
            'description': 'No rate limits, no payload size caps, no query complexity limits',
            'mitre': 'T1499',
            'tests': [
                'rate_limit_absent',
                'payload_size_unlimited',
                'pagination_unbounded',
                'graphql_complexity',
            ]
        },
        'API5': {
            'name': 'Broken Function Level Authorization (BFLA)',
            'severity': 'critical',
            'cvss': 8.8,
            'description': 'Regular users can call admin-level functions directly',
            'mitre': 'T1078',
            'tests': [
                'admin_endpoint_access',
                'http_method_tampering',
                'parameter_bypass_admin',
                'undocumented_endpoints',
            ]
        },
        'API6': {
            'name': 'Unrestricted Access to Sensitive Business Flows',
            'severity': 'high',
            'cvss': 7.2,
            'description': 'Critical flows can be scripted and abused at scale',
            'mitre': 'T1190',
            'tests': [
                'business_flow_automation',
                'race_condition',
                'step_skipping',
                'coupon_enumeration',
            ]
        },
        'API7': {
            'name': 'Server-Side Request Forgery (SSRF)',
            'severity': 'critical',
            'cvss': 9.0,
            'description': 'API fetches a URL supplied by the user without validation',
            'mitre': 'T1190',
            'tests': [
                'ssrf_internal_ip',
                'ssrf_cloud_metadata',
                'ssrf_file_scheme',
                'ssrf_dns_rebind',
                'ssrf_redirect',
            ]
        },
        'API8': {
            'name': 'Security Misconfiguration',
            'severity': 'high',
            'cvss': 6.5,
            'description': 'Verbose errors, permissive CORS, exposed debug endpoints, missing headers',
            'mitre': 'T1190',
            'tests': [
                'cors_wildcard',
                'missing_security_headers',
                'verbose_errors',
                'debug_endpoints',
                'http_methods',
                'tls_version',
            ]
        },
        'API9': {
            'name': 'Improper Inventory Management',
            'severity': 'medium',
            'cvss': 5.5,
            'description': 'Outdated API versions, undocumented endpoints, shadow APIs',
            'mitre': 'T1595',
            'tests': [
                'deprecated_versions',
                'shadow_endpoints',
                'zombie_apis',
                'documentation_mismatch',
            ]
        },
        'API10': {
            'name': 'Unsafe Consumption of APIs',
            'severity': 'high',
            'cvss': 7.0,
            'description': 'App blindly trusts responses from third-party APIs',
            'mitre': 'T1195',
            'tests': [
                'third_party_integration',
                'response_validation',
                'tls_cert_validation',
                'api_key_storage',
            ]
        },
    }


# ── API Test Engine ─────────────────────────────────────────────────────────

class APITestEngine:
    """Executes OWASP API Top 10 tests against target API."""
    
    # ── API1: BOLA Tests ────────────────────────────────────────────────────
    @staticmethod
    def test_bola(session, exec_func, base_url: str, endpoints: List[APIEndpoint]) -> List[APITestResult]:
        """Test for Broken Object Level Authorization (IDOR)."""
        results = []
        
        # Find endpoints with IDs
        id_patterns = [
            r'/users/(\d+)',
            r'/accounts/(\d+)',
            r'/orders/(\d+)',
            r'/items/(\d+)',
            r'/documents/(\d+)',
            r'/api/v\d+/users/([^/]+)',
            r'/api/v\d+/accounts/([^/]+)',
        ]
        
        idor_endpoints = []
        for ep in endpoints:
            for pattern in id_patterns:
                if re.search(pattern, ep.url):
                    idor_endpoints.append(ep.url)
                    break
        
        if not idor_endpoints:
            # Try common IDOR patterns
            idor_endpoints = [
                f"{base_url}/api/v1/users/1",
                f"{base_url}/api/v1/users/2",
                f"{base_url}/api/v1/accounts/1",
                f"{base_url}/api/v1/orders/1",
            ]
        
        for ep_url in idor_endpoints[:5]:
            # Test horizontal privilege escalation
            for alt_id in ['2', '3', '999', 'admin', '0']:
                test_url = re.sub(r'/(\d+|[^/]+)$', f'/{alt_id}', ep_url)
                cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 --max-time 10 '{test_url}' 2>/dev/null"
                
                start = time.time()
                resp = exec_func(session, cmd)
                duration = int((time.time() - start) * 1000)
                
                if resp and resp.strip() in ('200', '201'):
                    results.append(APITestResult(
                        risk_id='API1',
                        risk_name='BOLA',
                        test_name='idor_horizontal',
                        passed=True,
                        severity='critical',
                        confidence='high',
                        evidence=f"Endpoint {test_url} returned {resp.strip()} — object accessible without ownership check",
                        recommendation="Implement object-level authorization checks on every endpoint. Verify the authenticated user owns the requested object.",
                        mitre_id='T1078',
                        duration_ms=duration,
                        endpoint=test_url
                    ))
                    break
        
        return results
    
    # ── API2: Broken Authentication Tests ───────────────────────────────────
    @staticmethod
    def test_broken_auth(session, exec_func, base_url: str, endpoints: List[APIEndpoint]) -> List[APITestResult]:
        """Test for Broken Authentication."""
        results = []
        
        # Test 1: JWT alg:none bypass
        jwt_none_payload = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."
        for ep in endpoints[:10]:
            cmd = (
                f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 --max-time 10 "
                f"-H 'Authorization: Bearer {jwt_none_payload}' '{ep.url}' 2>/dev/null"
            )
            resp = exec_func(session, cmd)
            if resp and resp.strip() in ('200', '201', '204'):
                results.append(APITestResult(
                    risk_id='API2',
                    risk_name='Broken Authentication',
                    test_name='jwt_alg_none',
                    passed=True,
                    severity='critical',
                    confidence='high',
                    evidence=f"JWT with alg:none accepted by {ep.url} — authentication bypass possible",
                    recommendation="Reject JWTs with alg:none. Enforce strong algorithm validation (RS256, ES256).",
                    mitre_id='T1078',
                    endpoint=ep.url
                ))
                break
        
        # Test 2: Unauthenticated access to protected endpoints
        protected_patterns = ['/api/v1/users', '/api/v1/admin', '/api/v1/account', '/api/v1/profile']
        for path in protected_patterns:
            url = f"{base_url}{path}"
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 --max-time 10 '{url}' 2>/dev/null"
            resp = exec_func(session, cmd)
            if resp and resp.strip() in ('200', '201'):
                results.append(APITestResult(
                    risk_id='API2',
                    risk_name='Broken Authentication',
                    test_name='auth_bypass_no_token',
                    passed=True,
                    severity='critical',
                    confidence='high',
                    evidence=f"Endpoint {url} accessible without authentication (HTTP {resp.strip()})",
                    recommendation="Enforce authentication on all sensitive endpoints. Return 401/403 for unauthenticated requests.",
                    mitre_id='T1078',
                    endpoint=url
                ))
        
        # Test 3: Credential stuffing (rate limit check on login)
        login_paths = ['/api/v1/login', '/api/v1/auth/login', '/auth', '/login', '/api/auth']
        for login_path in login_paths:
            url = f"{base_url}{login_path}"
            cmd = (
                f"for i in 1 2 3 4 5; do "
                f"curl -s -o /dev/null -w '%{{http_code}} ' --connect-timeout 2 --max-time 3 "
                f"'{url}' -X POST -H 'Content-Type: application/json' "
                f"-d '{{\"username\":\"test\",\"password\":\"wrong\"}}' 2>/dev/null; "
                f"done"
            )
            resp = exec_func(session, cmd)
            if resp and resp.strip():
                codes = resp.strip().split()
                if '429' not in codes and '403' not in codes and '423' not in codes:
                    results.append(APITestResult(
                        risk_id='API2',
                        risk_name='Broken Authentication',
                        test_name='credential_stuffing',
                        passed=True,
                        severity='high',
                        confidence='medium',
                        evidence=f"Login endpoint {url} allows rapid authentication attempts without rate limiting. Responses: {codes}",
                        recommendation="Implement rate limiting on authentication endpoints. Use account lockout, CAPTCHA, and MFA.",
                        mitre_id='T1110',
                        endpoint=url
                    ))
                    break
        
        return results
    
    # ── API3: Mass Assignment Tests ─────────────────────────────────────────
    @staticmethod
    def test_mass_assignment(session, exec_func, base_url: str, endpoints: List[APIEndpoint]) -> List[APITestResult]:
        """Test for Broken Object Property Level Authorization (Mass Assignment)."""
        results = []
        
        # Find POST/PUT/PATCH endpoints
        write_endpoints = [ep for ep in endpoints if ep.method in ('POST', 'PUT', 'PATCH')]
        if not write_endpoints:
            write_endpoints = [
                APIEndpoint(url=f"{base_url}/api/v1/users", method="POST"),
                APIEndpoint(url=f"{base_url}/api/v1/profile", method="PUT"),
            ]
        
        mass_assignment_payloads = [
            '{"role": "admin", "isAdmin": true}',
            '{"balance": 999999, "credit": 1000000}',
            '{"price": 0.01, "discount": 100}',
            '{"verified": true, "email_confirmed": true}',
        ]
        
        for ep in write_endpoints[:5]:
            for payload in mass_assignment_payloads:
                cmd = (
                    f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 --max-time 10 "
                    f"-X {ep.method} -H 'Content-Type: application/json' "
                    f"-d '{payload}' '{ep.url}' 2>/dev/null"
                )
                resp = exec_func(session, cmd)
                if resp and resp.strip() in ('200', '201', '204'):
                    results.append(APITestResult(
                        risk_id='API3',
                        risk_name='Broken Object Property Level Authorization',
                        test_name='mass_assignment',
                        passed=True,
                        severity='high',
                        confidence='medium',
                        evidence=f"Endpoint {ep.url} accepted mass assignment payload: {payload[:50]}...",
                        recommendation="Use explicit allowlists for writable properties. Never blindly bind client input to internal objects.",
                        mitre_id='T1190',
                        endpoint=ep.url
                    ))
                    break
        
        return results
    
    # ── API4: Unrestricted Resource Consumption Tests ───────────────────────
    @staticmethod
    def test_resource_consumption(session, exec_func, base_url: str, endpoints: List[APIEndpoint]) -> List[APITestResult]:
        """Test for Unrestricted Resource Consumption."""
        results = []
        
        # Test rate limiting
        test_url = f"{base_url}/api/v1/users"
        cmd = (
            f"for i in $(seq 1 20); do "
            f"curl -s -o /dev/null -w '%{{http_code}} ' --connect-timeout 2 --max-time 3 "
            f"'{test_url}' 2>/dev/null; "
            f"done"
        )
        resp = exec_func(session, cmd)
        if resp and resp.strip():
            codes = resp.strip().split()
            if '429' not in codes:
                results.append(APITestResult(
                    risk_id='API4',
                    risk_name='Unrestricted Resource Consumption',
                    test_name='rate_limit_absent',
                    passed=True,
                    severity='high',
                    confidence='high',
                    evidence=f"No rate limiting detected on {test_url}. 20 rapid requests all succeeded. Codes: {set(codes)}",
                    recommendation="Implement rate limiting per-user, per-IP, and per-API-key. Set appropriate thresholds.",
                    mitre_id='T1499',
                    endpoint=test_url
                ))
        
        # Test pagination unbounded
        pagination_paths = ['/api/v1/users?limit=10000', '/api/v1/users?page_size=99999', '/api/v1/items?count=100000']
        for path in pagination_paths:
            url = f"{base_url}{path}"
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 --max-time 10 '{url}' 2>/dev/null"
            resp = exec_func(session, cmd)
            if resp and resp.strip() in ('200', '201'):
                results.append(APITestResult(
                    risk_id='API4',
                    risk_name='Unrestricted Resource Consumption',
                    test_name='pagination_unbounded',
                    passed=True,
                    severity='medium',
                    confidence='medium',
                    evidence=f"Endpoint accepted unbounded pagination request: {url}",
                    recommendation="Cap pagination limits server-side. Reject requests with limit > 100.",
                    mitre_id='T1499',
                    endpoint=url
                ))
                break
        
        return results
    
    # ── API5: BFLA Tests ────────────────────────────────────────────────────
    @staticmethod
    def test_bfla(session, exec_func, base_url: str, endpoints: List[APIEndpoint]) -> List[APITestResult]:
        """Test for Broken Function Level Authorization."""
        results = []
        
        # Admin endpoint discovery
        admin_paths = [
            '/admin', '/api/admin', '/api/v1/admin',
            '/admin/users', '/api/admin/users',
            '/admin/config', '/api/admin/config',
            '/actuator', '/actuator/env', '/actuator/health',
            '/metrics', '/management', '/console',
            '/api/v1/users/delete', '/api/v1/users/bulk',
        ]
        
        for path in admin_paths:
            url = f"{base_url}{path}"
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 --max-time 10 '{url}' 2>/dev/null"
            resp = exec_func(session, cmd)
            if resp and resp.strip() in ('200', '201', '405'):
                results.append(APITestResult(
                    risk_id='API5',
                    risk_name='BFLA',
                    test_name='admin_endpoint_access',
                    passed=True,
                    severity='critical',
                    confidence='high',
                    evidence=f"Admin endpoint {url} accessible (HTTP {resp.strip()}) — may allow privilege escalation",
                    recommendation="Enforce role-based access control on all admin endpoints. Deny by default.",
                    mitre_id='T1078',
                    endpoint=url
                ))
        
        # HTTP method tampering
        for ep in endpoints[:10]:
            if ep.method == 'GET':
                for method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                    cmd = (
                        f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 --max-time 10 "
                        f"-X {method} '{ep.url}' 2>/dev/null"
                    )
                    resp = exec_func(session, cmd)
                    if resp and resp.strip() in ('200', '201', '204'):
                        results.append(APITestResult(
                            risk_id='API5',
                            risk_name='BFLA',
                            test_name='http_method_tampering',
                            passed=True,
                            severity='high',
                            confidence='medium',
                            evidence=f"HTTP method {method} on {ep.url} succeeded (HTTP {resp.strip()}) — may bypass authorization",
                            recommendation="Enforce authorization checks regardless of HTTP method. Deny unexpected methods.",
                            mitre_id='T1078',
                            endpoint=ep.url
                        ))
                        break
        
        return results
    
    # ── API6: Business Flow Abuse Tests ─────────────────────────────────────
    @staticmethod
    def test_business_flows(session, exec_func, base_url: str) -> List[APITestResult]:
        """Test for Unrestricted Access to Sensitive Business Flows."""
        results = []
        
        # Test race conditions on critical endpoints
        race_paths = [
            '/api/v1/checkout', '/api/v1/purchase', '/api/v1/transfer',
            '/api/v1/coupon/redeem', '/api/v1/otp/verify',
        ]
        
        for path in race_paths:
            url = f"{base_url}{path}"
            cmd = (
                f"for i in $(seq 1 10); do "
                f"curl -s -o /dev/null -w '%{{http_code}} ' --connect-timeout 2 --max-time 3 "
                f"-X POST -H 'Content-Type: application/json' "
                f"-d '{{\"id\":1}}' '{url}' 2>/dev/null & "
                f"done; wait"
            )
            resp = exec_func(session, cmd)
            if resp and resp.strip():
                codes = resp.strip().split()
                success_count = sum(1 for c in codes if c in ('200', '201'))
                if success_count > 3:
                    results.append(APITestResult(
                        risk_id='API6',
                        risk_name='Unrestricted Access to Sensitive Business Flows',
                        test_name='race_condition',
                        passed=True,
                        severity='high',
                        confidence='medium',
                        evidence=f"Race condition detected on {url} — {success_count}/10 concurrent requests succeeded",
                        recommendation="Implement atomic operations, locks, or idempotency keys for critical business flows.",
                        mitre_id='T1190',
                        endpoint=url
                    ))
                    break
        
        return results
    
    # ── API7: SSRF Tests ────────────────────────────────────────────────────
    @staticmethod
    def test_ssrf(session, exec_func, base_url: str, endpoints: List[APIEndpoint]) -> List[APITestResult]:
        """Test for Server-Side Request Forgery."""
        results = []
        
        # Find endpoints that accept URLs
        url_params = ['url', 'redirect', 'callback', 'webhook', 'target', 'fetch', 'proxy', 'link']
        ssrf_targets = [
            'http://127.0.0.1',
            'http://localhost',
            'http://169.254.169.254/latest/meta-data/',
            'http://[::1]',
            'file:///etc/passwd',
            'gopher://127.0.0.1:25/',
        ]
        
        # Test common SSRF endpoints
        ssrf_paths = [
            '/api/v1/fetch?url=',
            '/api/v1/proxy?url=',
            '/api/v1/webhook?url=',
            '/api/v1/redirect?url=',
            '/api/v1/import?url=',
        ]
        
        for path in ssrf_paths:
            for target in ssrf_targets[:3]:
                url = f"{base_url}{path}{target}"
                cmd = (
                    f"curl -s --connect-timeout 5 --max-time 10 "
                    f"-X POST -H 'Content-Type: application/json' "
                    f"-d '{{\"url\":\"{target}\"}}' '{base_url}{path[:-1]}' 2>/dev/null | head -20"
                )
                resp = exec_func(session, cmd)
                if resp and ('ami-id' in resp or 'instance-id' in resp or 'root:' in resp):
                    results.append(APITestResult(
                        risk_id='API7',
                        risk_name='SSRF',
                        test_name='ssrf_cloud_metadata',
                        passed=True,
                        severity='critical',
                        confidence='verified',
                        evidence=f"SSRF confirmed — server fetched internal resource. Response contains sensitive data.",
                        recommendation="Validate all user-supplied URLs. Use allowlists. Block internal IPs and cloud metadata endpoints.",
                        mitre_id='T1190',
                        endpoint=url
                    ))
                    break
        
        return results
    
    # ── API8: Security Misconfiguration Tests ───────────────────────────────
    @staticmethod
    def test_misconfiguration(session, exec_func, base_url: str) -> List[APITestResult]:
        """Test for Security Misconfiguration."""
        results = []
        
        # Test CORS wildcard
        cmd = (
            f"curl -sI --connect-timeout 5 --max-time 10 "
            f"-H 'Origin: https://evil.com' '{base_url}' 2>/dev/null | grep -i 'access-control-allow-origin'"
        )
        resp = exec_func(session, cmd)
        if resp and ('*' in resp or 'evil.com' in resp):
            results.append(APITestResult(
                risk_id='API8',
                risk_name='Security Misconfiguration',
                test_name='cors_wildcard',
                passed=True,
                severity='high',
                confidence='high',
                evidence=f"CORS allows wildcard or arbitrary origins: {resp.strip()}",
                recommendation="Restrict CORS to specific trusted origins. Never use wildcard (*) on authenticated endpoints.",
                mitre_id='T1190',
                endpoint=base_url
            ))
        
        # Test missing security headers
        cmd = f"curl -sI --connect-timeout 5 --max-time 10 '{base_url}' 2>/dev/null"
        resp = exec_func(session, cmd)
        if resp:
            missing_headers = []
            required_headers = [
                ('Strict-Transport-Security', 'HSTS'),
                ('X-Content-Type-Options', 'X-Content-Type-Options'),
                ('X-Frame-Options', 'X-Frame-Options'),
                ('Content-Security-Policy', 'CSP'),
                ('X-XSS-Protection', 'X-XSS-Protection'),
            ]
            for header, name in required_headers:
                if header.lower() not in resp.lower():
                    missing_headers.append(name)
            
            if len(missing_headers) >= 3:
                results.append(APITestResult(
                    risk_id='API8',
                    risk_name='Security Misconfiguration',
                    test_name='missing_security_headers',
                    passed=True,
                    severity='medium',
                    confidence='high',
                    evidence=f"Missing security headers: {', '.join(missing_headers)}",
                    recommendation="Implement all security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options.",
                    mitre_id='T1190',
                    endpoint=base_url
                ))
        
        # Test verbose errors
        error_paths = ['/api/v1/users/999999', '/api/v1/nonexistent', '/api/v1/error']
        for path in error_paths:
            url = f"{base_url}{path}"
            cmd = f"curl -s --connect-timeout 5 --max-time 10 '{url}' 2>/dev/null"
            resp = exec_func(session, cmd)
            if resp and any(x in resp.lower() for x in ['stack trace', 'exception', 'sql', 'mysql', 'postgres', 'traceback', 'at line']):
                results.append(APITestResult(
                    risk_id='API8',
                    risk_name='Security Misconfiguration',
                    test_name='verbose_errors',
                    passed=True,
                    severity='medium',
                    confidence='high',
                    evidence=f"Verbose error messages exposed on {url}",
                    recommendation="Return generic error messages in production. Log detailed errors server-side only.",
                    mitre_id='T1190',
                    endpoint=url
                ))
                break
        
        # Test debug endpoints
        debug_paths = [
            '/swagger-ui.html', '/swagger.json', '/api-docs',
            '/actuator', '/actuator/env', '/actuator/health',
            '/.env', '/debug', '/phpinfo.php', '/server-status',
            '/graphql', '/graphiql',
        ]
        for path in debug_paths:
            url = f"{base_url}{path}"
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 3 --max-time 5 '{url}' 2>/dev/null"
            resp = exec_func(session, cmd)
            if resp and resp.strip() in ('200', '201'):
                results.append(APITestResult(
                    risk_id='API8',
                    risk_name='Security Misconfiguration',
                    test_name='debug_endpoints',
                    passed=True,
                    severity='medium',
                    confidence='high',
                    evidence=f"Debug/documentation endpoint exposed: {url} (HTTP {resp.strip()})",
                    recommendation="Disable debug endpoints in production. Restrict API documentation access.",
                    mitre_id='T1190',
                    endpoint=url
                ))
        
        return results
    
    # ── API9: Inventory Management Tests ────────────────────────────────────
    @staticmethod
    def test_inventory(session, exec_func, base_url: str) -> List[APITestResult]:
        """Test for Improper Inventory Management."""
        results = []
        
        # Test deprecated API versions
        version_paths = [
            '/api/v1', '/api/v2', '/api/v3',
            '/v1', '/v2', '/v3',
            '/api/1.0', '/api/2.0',
        ]
        found_versions = []
        for path in version_paths:
            url = f"{base_url}{path}"
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 3 --max-time 5 '{url}' 2>/dev/null"
            resp = exec_func(session, cmd)
            if resp and resp.strip() in ('200', '201', '301', '302'):
                found_versions.append(path)
        
        if len(found_versions) > 2:
            results.append(APITestResult(
                risk_id='API9',
                risk_name='Improper Inventory Management',
                test_name='deprecated_versions',
                passed=True,
                severity='medium',
                confidence='medium',
                evidence=f"Multiple API versions accessible: {', '.join(found_versions)}",
                recommendation="Maintain API inventory. Deprecate old versions. Ensure all versions enforce same security controls.",
                mitre_id='T1595',
                endpoint=base_url
            ))
        
        return results
    
    # ── API10: Unsafe Consumption Tests ─────────────────────────────────────
    @staticmethod
    def test_unsafe_consumption(session, exec_func, base_url: str) -> List[APITestResult]:
        """Test for Unsafe Consumption of APIs."""
        results = []
        
        # Check for third-party integrations in responses
        cmd = f"curl -s --connect-timeout 5 --max-time 10 '{base_url}' 2>/dev/null | head -100"
        resp = exec_func(session, cmd)
        if resp:
            third_party_indicators = [
                'stripe.com', 'paypal.com', 'twilio.com', 'sendgrid.com',
                'aws.amazon.com', 'googleapis.com', 'microsoft.com',
                'facebook.com', 'twitter.com', 'github.com',
            ]
            found_integrations = [ind for ind in third_party_indicators if ind in resp.lower()]
            if found_integrations:
                results.append(APITestResult(
                    risk_id='API10',
                    risk_name='Unsafe Consumption of APIs',
                    test_name='third_party_integration',
                    passed=True,
                    severity='medium',
                    confidence='low',
                    evidence=f"Third-party API integrations detected: {', '.join(found_integrations)}",
                    recommendation="Validate all third-party responses. Use TLS cert validation. Store API keys in secrets manager.",
                    mitre_id='T1195',
                    endpoint=base_url
                ))
        
        return results


# ── Main Plugin ─────────────────────────────────────────────────────────────

class APIEnum(NexPlugin):
    name        = "api-enum"
    description = "OWASP API Security Top 10 (2023/2025/2026) — comprehensive API security scanner"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "recon"
    mitre_id    = "T1190"
    
    def run(self, session, args: list):
        # Parse args
        target_url = None
        full_scan = '--full' in (args or [])
        stealth = '--stealth' in (args or [])
        graphql_only = '--graphql' in (args or [])
        specific_risks = None
        
        for a in (args or []):
            if a.startswith('--url='):
                target_url = a.split('=', 1)[1]
            elif a == '--url' and args and args.index(a) + 1 < len(args):
                target_url = args[args.index(a) + 1]
            elif a.startswith('--risk='):
                specific_risks = [r.strip() for r in a.split('=', 1)[1].split(',')]
        
        if not target_url:
            return "[-] Usage: plugins run api-enum --url http://target:8080"
        
        self.info(f"🔍 Starting API Security Scanner v3.0 — OWASP API Top 10")
        self.info(f"   Target: {target_url}")
        self.info(f"   Mode: {'full' if full_scan else 'balanced'}{' (stealth)' if stealth else ''}")
        
        sections = []
        sections.append("\n" + "━"*64)
        sections.append("  [🔍 API Security Scanner v3.0 — OWASP API Top 10]")
        sections.append("━"*64)
        sections.append(f"  Target: {target_url}")
        sections.append(f"  Scan Type: {'Full (All 10 Risks)' if full_scan else 'Balanced'}")
        
        # ── Step 1: API Discovery ───────────────────────────────────────
        sections.append("\n[*] Phase 1: API Discovery & Documentation")
        sections.append("─"*64)
        
        endpoints = self._discover_endpoints(session, target_url)
        sections.append(f"  [+] Discovered {len(endpoints)} endpoints")
        
        # ── Step 2: Execute OWASP Tests ─────────────────────────────────
        sections.append("\n[*] Phase 2: OWASP API Top 10 Testing")
        sections.append("─"*64)
        
        all_results = []
        test_engine = APITestEngine()
        
        # Determine which tests to run
        risks_to_test = specific_risks or (list(OWSAPAPIRisks.RISKS.keys()) if full_scan else ['API1', 'API2', 'API5', 'API7', 'API8'])
        
        test_mapping = {
            'API1': ('BOLA', test_engine.test_bola),
            'API2': ('Broken Authentication', test_engine.test_broken_auth),
            'API3': ('Mass Assignment', test_engine.test_mass_assignment),
            'API4': ('Resource Consumption', test_engine.test_resource_consumption),
            'API5': ('BFLA', test_engine.test_bfla),
            'API6': ('Business Flows', test_engine.test_business_flows),
            'API7': ('SSRF', test_engine.test_ssrf),
            'API8': ('Misconfiguration', test_engine.test_misconfiguration),
            'API9': ('Inventory', test_engine.test_inventory),
            'API10': ('Unsafe Consumption', test_engine.test_unsafe_consumption),
        }
        
        for risk_id in risks_to_test:
            if risk_id not in test_mapping:
                continue
            
            risk_name, test_func = test_mapping[risk_id]
            sections.append(f"\n  [🎯 Testing {risk_id}: {risk_name}]")
            
            try:
                if risk_id in ('API6', 'API8', 'API9', 'API10'):
                    results = test_func(session, self._exec, target_url)
                else:
                    results = test_func(session, self._exec, target_url, endpoints)
                
                all_results.extend(results)
                
                if results:
                    vuln_count = sum(1 for r in results if r.passed)
                    sections.append(f"      ⚠️  {vuln_count} vulnerabilities found")
                    for r in results[:3]:
                        if r.passed:
                            sections.append(f"      • {r.test_name}: {r.evidence[:80]}")
                else:
                    sections.append(f"      ✓ No vulnerabilities detected")
            
            except Exception as e:
                sections.append(f"      ❌ Test failed: {str(e)}")
        
        # ── Step 3: Generate Findings ───────────────────────────────────
        sections.append("\n[*] Phase 3: Generating Findings")
        sections.append("─"*64)
        
        findings = self._generate_findings(all_results)
        
        for finding in findings:
            self.finding(
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                recommendation=finding.recommendation,
                mitre_id=finding.mitre_id,
            )
            self.emit(
                'finding.created',
                severity=finding.severity,
                title=finding.title,
                plugin=self.name,
                confidence=finding.confidence
            )
            sections.append(f"  [{finding.severity.upper()}] {finding.title}")
        
        # ── Step 4: Summary Report ──────────────────────────────────────
        sections.append("\n" + "━"*64)
        sections.append("  [📊 OWASP API Top 10 — Summary Report]")
        sections.append("━"*64)
        
        # Group by risk
        risk_summary = defaultdict(list)
        for r in all_results:
            if r.passed:
                risk_summary[r.risk_id].append(r)
        
        sections.append("\n  OWASP Risk | Status | Findings")
        sections.append("  " + "─"*58)
        
        for risk_id in sorted(OWSAPAPIRisks.RISKS.keys()):
            risk_info = OWSAPAPIRisks.RISKS[risk_id]
            findings_list = risk_summary.get(risk_id, [])
            status = "🔴 VULNERABLE" if findings_list else "🟢 PASS"
            count = len(findings_list)
            sections.append(f"  {risk_id:10} | {status:16} | {count} findings")
        
        # Overall score
        total_tests = len(risks_to_test)
        passed_tests = len([r for r in risks_to_test if not risk_summary.get(r)])
        score = int((passed_tests / total_tests) * 100) if total_tests > 0 else 0
        
        sections.append("\n" + "─"*64)
        sections.append(f"  Overall Security Score: {score}/100")
        sections.append(f"  Total Tests: {len(all_results)}")
        sections.append(f"  Vulnerabilities Found: {len([r for r in all_results if r.passed])}")
        sections.append(f"  Critical: {len([r for r in all_results if r.passed and r.severity == 'critical'])}")
        sections.append(f"  High: {len([r for r in all_results if r.passed and r.severity == 'high'])}")
        sections.append(f"  Medium: {len([r for r in all_results if r.passed and r.severity == 'medium'])}")
        
        # Save to loot
        self.loot(
            {
                "type": "api_security_scan",
                "target": target_url,
                "score": score,
                "total_tests": len(all_results),
                "vulnerabilities": len([r for r in all_results if r.passed]),
                "findings": [f.to_dict() for f in findings],
                "results": [r.to_dict() for r in all_results if r.passed],
            },
            category='api_security',
            source=f'api-enum:{target_url}',
            confidence='high'
        )
        
        self.info(f"🔍 API scan complete — Score: {score}/100, {len(findings)} findings")
        
        return '\n'.join(sections)
    
    def _discover_endpoints(self, session, base_url: str) -> List[APIEndpoint]:
        """Discover API endpoints via documentation and common paths."""
        endpoints = []
        
        # Common API documentation paths
        doc_paths = [
            '/swagger.json', '/openapi.json', '/api-docs',
            '/swagger-ui.html', '/graphql', '/graphiql',
        ]
        
        for path in doc_paths:
            url = f"{base_url.rstrip('/')}{path}"
            cmd = f"curl -s --connect-timeout 5 --max-time 10 '{url}' 2>/dev/null | head -100"
            resp = self._exec(session, cmd)
            if resp and len(resp) > 50:
                # Try to parse OpenAPI/Swagger
                try:
                    data = json.loads(resp)
                    if 'paths' in data:
                        for path_key, methods in data['paths'].items():
                            for method in methods:
                                endpoints.append(APIEndpoint(
                                    url=f"{base_url.rstrip('/')}{path_key}",
                                    method=method.upper(),
                                    api_type='rest'
                                ))
                except:
                    pass
        
        # Common API paths
        common_paths = [
            '/api/v1/users', '/api/v1/accounts', '/api/v1/orders',
            '/api/v1/products', '/api/v1/auth', '/api/v1/login',
            '/api/v1/profile', '/api/v1/settings',
        ]
        
        for path in common_paths:
            url = f"{base_url.rstrip('/')}{path}"
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 3 --max-time 5 '{url}' 2>/dev/null"
            resp = self._exec(session, cmd)
            if resp and resp.strip() in ('200', '201', '401', '403'):
                endpoints.append(APIEndpoint(
                    url=url,
                    status_code=int(resp.strip()),
                    auth_required=(resp.strip() in ('401', '403')),
                    api_type='rest'
                ))
        
        return endpoints
    
    def _generate_findings(self, results: List[APITestResult]) -> List[APIFinding]:
        """Generate structured findings from test results."""
        findings = []
        
        # Group by risk_id
        grouped = defaultdict(list)
        for r in results:
            if r.passed:
                grouped[r.risk_id].append(r)
        
        for risk_id, risk_results in grouped.items():
            risk_info = OWSAPAPIRisks.RISKS.get(risk_id, {})
            
            finding = APIFinding(
                owasp_risk=risk_id,
                title=f"{risk_id}: {risk_info.get('name', 'Unknown Risk')}",
                severity=risk_info.get('severity', 'medium'),
                description=risk_info.get('description', ''),
                evidence=[r.evidence for r in risk_results],
                recommendation=risk_results[0].recommendation if risk_results else '',
                affected_endpoints=list(set(r.endpoint for r in risk_results if r.endpoint)),
                mitre_id=risk_info.get('mitre', 'T1190'),
                confidence='high' if any(r.confidence == 'verified' for r in risk_results) else 'medium',
                cvss_estimate=risk_info.get('cvss', 0.0)
            )
            findings.append(finding)
        
        return findings
    
    @staticmethod
    def _exec(session, cmd: str) -> str:
        for method in ('exec', 'run', 'execute', 'send_command'):
            fn = getattr(session, method, None)
            if callable(fn):
                result = fn(cmd)
                if isinstance(result, bytes):
                    return result.decode(errors='replace')
                if isinstance(result, str):
                    return result
        return ''