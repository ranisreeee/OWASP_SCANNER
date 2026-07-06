#!/usr/bin/env python3
"""
OWASP Top 10 Web Application Vulnerability Scanner
A comprehensive security testing tool for web applications.
"""

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for testing
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('OWASPScanner')


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class Vulnerability:
    id: str
    name: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    url: str
    parameter: Optional[str] = None
    confidence: str = "High"
    references: List[str] = field(default_factory=list)


class OWASPScanner:
    """Main scanner class that coordinates all vulnerability checks."""
    
    OWASP_CATEGORIES = {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures", 
        "A03": "Injection",
        "A04": "Insecure Design",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable and Outdated Components",
        "A07": "Identification and Authentication Failures",
        "A08": "Software and Data Integrity Failures",
        "A09": "Security Logging and Monitoring Failures",
        "A10": "Server-Side Request Forgery (SSRF)"
    }
    
    def __init__(self, target_url: str, timeout: int = 30, threads: int = 5):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'OWASP-Scanner/1.0 (Security Testing Tool)'
        })
        self.vulnerabilities: List[Vulnerability] = []
        self.discovered_urls: Set[str] = set()
        self.forms: List[Dict] = []
        
    def scan(self) -> List[Vulnerability]:
        """Run all vulnerability checks."""
        logger.info(f"Starting OWASP Top 10 scan of {self.target_url}")
        start_time = time.time()
        
        # Discovery phase
        self._discover_content()
        
        # Run all vulnerability checks
        self._check_sql_injection()
        self._check_xss()
        self._check_command_injection()
        self._check_ssrf()
        self._check_security_misconfig()
        self._check_broken_auth()
        self._check_sensitive_data_exposure()
        self._check_xxe()
        self._check_insecure_deserialization()
        self._check_idor()
        self._check_security_headers()
        
        duration = time.time() - start_time
        logger.info(f"Scan completed in {duration:.2f} seconds")
        logger.info(f"Found {len(self.vulnerabilities)} vulnerabilities")
        
        return self.vulnerabilities
    
    def _discover_content(self):
        """Crawl the target to discover URLs and forms."""
        logger.info("Starting content discovery...")
        
        try:
            response = self.session.get(
                self.target_url,
                timeout=self.timeout,
                allow_redirects=True
            )
            self.discovered_urls.add(self.target_url)
            
            # Extract links
            links = re.findall(r'href=["\'](.*?)["\']', response.text)
            for link in links:
                full_url = urljoin(self.target_url, link)
                if full_url.startswith(self.target_url):
                    self.discovered_urls.add(full_url)
            
            # Extract forms
            forms = re.findall(
                r'<form[^>]*action=["\'](.*?)["\'][^>]*method=["\'](.*?)["\'][^>]*>(.*?)</form>',
                response.text,
                re.DOTALL | re.IGNORECASE
            )
            for action, method, form_content in forms:
                inputs = re.findall(r'<input[^>]*name=["\'](.*?)["\']', form_content, re.IGNORECASE)
                self.forms.append({
                    'action': urljoin(self.target_url, action),
                    'method': method.upper() if method else 'GET',
                    'inputs': {inp: '' for inp in inputs}
                })
                    
        except Exception as e:
            logger.error(f"Discovery failed: {e}")
    
    def _check_sql_injection(self):
        """Test for SQL Injection vulnerabilities (A03: Injection)."""
        logger.info("Checking for SQL Injection...")
        
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "' UNION SELECT NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--",
        ]
        
        error_patterns = [
            "mysql_fetch_array",
            "ORA-",
            "Microsoft SQL Server",
            "PostgreSQL",
            "SQLite",
            "syntax error",
            "SQL syntax",
            "Warning: mysql",
        ]
        
        for url in self.discovered_urls:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    for payload in payloads:
                        test_url = url.replace(
                            f"{param}={params[param][0]}",
                            f"{param}={payload}"
                        )
                        try:
                            response = self.session.get(test_url, timeout=self.timeout)
                            for pattern in error_patterns:
                                if pattern.lower() in response.text.lower():
                                    self.vulnerabilities.append(Vulnerability(
                                        id="A03-SQLi",
                                        name="SQL Injection",
                                        severity=Severity.CRITICAL,
                                        description="SQL injection vulnerability allows attackers to execute arbitrary SQL commands.",
                                        evidence=f"Parameter '{param}' with payload '{payload}' triggered SQL error: {pattern}",
                                        remediation="Use parameterized queries/prepared statements. Validate and sanitize all user inputs.",
                                        url=url,
                                        parameter=param,
                                        references=[
                                            "https://owasp.org/www-community/attacks/SQL_Injection",
                                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                                        ]
                                    ))
                                    return
                        except:
                            continue
    
    def _check_xss(self):
        """Test for Cross-Site Scripting vulnerabilities (A03: Injection)."""
        logger.info("Checking for XSS...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>",
        ]
        
        for url in self.discovered_urls:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    for payload in xss_payloads:
                        test_url = url.replace(
                            f"{param}={params[param][0]}",
                            f"{param}={payload}"
                        )
                        try:
                            response = self.session.get(test_url, timeout=self.timeout)
                            if payload in response.text:
                                self.vulnerabilities.append(Vulnerability(
                                    id="A03-XSS",
                                    name="Cross-Site Scripting (XSS)",
                                    severity=Severity.HIGH,
                                    description="Reflected XSS allows attackers to execute JavaScript in victim's browser.",
                                    evidence=f"Parameter '{param}' reflects unencoded payload: {payload[:50]}...",
                                    remediation="Encode all output. Use Content Security Policy. Validate input.",
                                    url=url,
                                    parameter=param,
                                    references=[
                                        "https://owasp.org/www-community/attacks/xss/",
                                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                                    ]
                                ))
                                return
                        except:
                            continue
    
    def _check_command_injection(self):
        """Test for Command Injection vulnerabilities (A03: Injection)."""
        logger.info("Checking for Command Injection...")
        
        cmd_payloads = [
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            "; whoami",
            "| whoami",
        ]
        
        indicators = [
            "root:x:",
            "daemon:x:",
            "bin:x:",
        ]
        
        for form in self.forms:
            for payload in cmd_payloads:
                data = {k: payload for k in form['inputs']}
                try:
                    response = self.session.post(
                        form['action'],
                        data=data,
                        timeout=self.timeout
                    )
                    for indicator in indicators:
                        if indicator in response.text:
                            self.vulnerabilities.append(Vulnerability(
                                id="A03-CMDi",
                                name="Command Injection",
                                severity=Severity.CRITICAL,
                                description="OS command injection allows arbitrary command execution on the server.",
                                evidence=f"Payload '{payload}' executed, found '{indicator}' in response",
                                remediation="Avoid OS commands. Use parameterized APIs. Input validation.",
                                url=form['action'],
                                references=[
                                    "https://owasp.org/www-community/attacks/Command_Injection",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
                                ]
                            ))
                            return
                except:
                    continue
    
    def _check_ssrf(self):
        """Test for Server-Side Request Forgery (A10: SSRF)."""
        logger.info("Checking for SSRF...")
        
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",
            "file:///etc/passwd",
        ]
        
        ssrf_indicators = [
            "root:x:",
            "[extensions]",
            "ami-id",
        ]
        
        for form in self.forms:
            for payload in ssrf_payloads:
                data = {k: payload for k in form['inputs']}
                try:
                    response = self.session.post(
                        form['action'],
                        data=data,
                        timeout=self.timeout
                    )
                    for indicator in ssrf_indicators:
                        if indicator in response.text:
                            self.vulnerabilities.append(Vulnerability(
                                id="A10-SSRF",
                                name="Server-Side Request Forgery (SSRF)",
                                severity=Severity.HIGH,
                                description="SSRF allows attackers to make requests from the server to internal resources.",
                                evidence=f"Payload '{payload}' accessed internal resource, found '{indicator}'",
                                remediation="Validate and sanitize URLs. Use allowlists. Disable unnecessary protocols.",
                                url=form['action'],
                                references=[
                                    "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
                                ]
                            ))
                            return
                except:
                    continue
    
    def _check_security_misconfig(self):
        """Test for Security Misconfiguration (A05)."""
        logger.info("Checking for Security Misconfiguration...")
        
        checks = [
            ("/.env", "DB_PASSWORD|APP_KEY|SECRET", "Exposed Environment File"),
            ("/.git/config", "\\[core\\]", "Exposed Git Repository"),
            ("/config.php", "<?php", "Exposed Config File"),
            ("/phpinfo.php", "phpinfo()", "PHP Info Exposure"),
            ("/api/", "\"", "API Endpoint Exposure"),
            ("/admin/", "login|admin", "Admin Panel"),
            ("/robots.txt", "Disallow", "Robots.txt Disclosure"),
        ]
        
        for path, pattern, name in checks:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        severity = Severity.HIGH if "admin" in path.lower() else Severity.MEDIUM
                        self.vulnerabilities.append(Vulnerability(
                            id="A05-Misconfig",
                            name=f"Security Misconfiguration: {name}",
                            severity=severity,
                            description=f"Sensitive resource exposed at {path}",
                            evidence=f"Accessible at {url} with pattern match: {pattern}",
                            remediation="Remove or restrict access to sensitive files and directories.",
                            url=url,
                            references=[
                                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Security_Misconfiguration_Cheat_Sheet.html"
                            ]
                        ))
            except:
                continue
    
    def _check_broken_auth(self):
        """Test for Broken Authentication (A07)."""
        logger.info("Checking for Broken Authentication...")
        
        auth_paths = ["/login", "/admin", "/signin", "/auth"]
        
        for path in auth_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    # Check for missing CSRF protection
                    if '<form' in response.text.lower():
                        if 'csrf' not in response.text.lower() and 'token' not in response.text.lower():
                            self.vulnerabilities.append(Vulnerability(
                                id="A07-NoCSRF",
                                name="Missing CSRF Protection",
                                severity=Severity.MEDIUM,
                                description="Login form lacks CSRF tokens, allowing cross-site request forgery attacks.",
                                evidence=f"Form at {url} has no CSRF token",
                                remediation="Implement CSRF tokens for all state-changing operations.",
                                url=url,
                                references=[
                                    "https://owasp.org/www-community/attacks/csrf",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                                ]
                            ))
            except:
                continue
    
    def _check_sensitive_data_exposure(self):
        """Test for Sensitive Data Exposure (A02)."""
        logger.info("Checking for Sensitive Data Exposure...")
        
        # Check for HTTPS
        if not self.target_url.startswith('https://'):
            self.vulnerabilities.append(Vulnerability(
                id="A02-NoHTTPS",
                name="Unencrypted Communication",
                severity=Severity.HIGH,
                description="Application does not use HTTPS, allowing interception of sensitive data.",
                evidence="Target uses HTTP instead of HTTPS",
                remediation="Enforce HTTPS with TLS 1.2 or higher for all communications.",
                url=self.target_url,
                references=[
                    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                ]
            ))
        
        # Check for sensitive patterns
        sensitive_patterns = [
            (r'\b\d{16}\b', "Potential Credit Card Number"),
            (r'password\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded Password"),
            (r'api[_-]?key\s*[=:]\s*["\'][^"\']+["\']', "API Key"),
            (r'secret\s*[=:]\s*["\'][^"\']+["\']', "Secret Key"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
        ]
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            for pattern, name in sensitive_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    self.vulnerabilities.append(Vulnerability(
                        id="A02-DataExposure",
                        name=f"Sensitive Data Exposure: {name}",
                        severity=Severity.CRITICAL,
                        description=f"Application exposes {name} in response.",
                        evidence=f"Found pattern: {matches[0][:30]}...",
                        remediation="Remove sensitive data from client-side code. Use secure vaults.",
                        url=self.target_url,
                        references=[
                            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
                        ]
                    ))
        except:
            pass
    
    def _check_xxe(self):
        """Test for XML External Entity vulnerabilities (A04)."""
        logger.info("Checking for XXE...")
        
        xxe_payloads = [
            """<?xml version="1.0"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <foo>&xxe;</foo>""",
        ]
        
        indicators = ["root:x:", "[extensions]"]
        
        xml_endpoints = ["/api", "/xml", "/soap"]
        
        for endpoint in xml_endpoints:
            url = urljoin(self.target_url, endpoint)
            try:
                headers = {'Content-Type': 'application/xml'}
                for payload in xxe_payloads:
                    response = self.session.post(
                        url,
                        data=payload,
                        headers=headers,
                        timeout=self.timeout
                    )
                    for indicator in indicators:
                        if indicator in response.text:
                            self.vulnerabilities.append(Vulnerability(
                                id="A04-XXE",
                                name="XML External Entity (XXE)",
                                severity=Severity.CRITICAL,
                                description="XXE allows attackers to read local files and perform SSRF attacks.",
                                evidence=f"XXE payload executed, found '{indicator}' in response",
                                remediation="Disable DTD processing. Use JSON instead. Validate XML input.",
                                url=url,
                                references=[
                                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
                                ]
                            ))
                            return
            except:
                continue
    
    def _check_insecure_deserialization(self):
        """Test for Insecure Deserialization (A08)."""
        logger.info("Checking for Insecure Deserialization...")
        
        serialized_patterns = [
            (r'[Oa]:\d+:"[^"]+":\d+:\{', "PHP Serialized Object"),
            (r'rO0ABXNyAC', "Java Serialized Object (Base64)"),
        ]
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            for pattern, name in serialized_patterns:
                if re.search(pattern, response.text):
                    self.vulnerabilities.append(Vulnerability(
                        id="A08-Deserialization",
                        name=f"Insecure Deserialization: {name}",
                        severity=Severity.HIGH,
                        description=f"Application may deserialize {name} without proper validation.",
                        evidence=f"Found pattern matching {name}",
                        remediation="Avoid deserializing untrusted data. Use JSON with schema validation.",
                        url=self.target_url,
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
                        ]
                    ))
        except:
            pass
    
    def _check_idor(self):
        """Test for Insecure Direct Object Reference (A01)."""
        logger.info("Checking for IDOR/Broken Access Control...")
        
        idor_patterns = [
            "/user/1",
            "/user/2", 
            "/account/1",
            "/profile/1",
            "/order/1",
        ]
        
        for pattern in idor_patterns:
            url = urljoin(self.target_url, pattern)
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    if len(response.text) > 100 and "error" not in response.text.lower():
                        self.vulnerabilities.append(Vulnerability(
                            id="A01-IDOR",
                            name="Insecure Direct Object Reference (IDOR)",
                            severity=Severity.HIGH,
                            description="Sequential IDs allow attackers to access other users' resources.",
                            evidence=f"Resource at {url} accessible without proper authorization",
                            remediation="Implement access control checks. Use UUIDs instead of sequential IDs.",
                            url=url,
                            references=[
                                "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html"
                            ]
                        ))
                        return
            except:
                continue
    
    def _check_security_headers(self):
        """Check for security headers (A05)."""
        logger.info("Checking Security Headers...")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            headers = response.headers
            
            required_headers = {
                'X-Content-Type-Options': {
                    'value': 'nosniff',
                    'description': 'Prevents MIME type sniffing',
                    'severity': Severity.MEDIUM
                },
                'X-Frame-Options': {
                    'value': ['DENY', 'SAMEORIGIN'],
                    'description': 'Prevents clickjacking attacks',
                    'severity': Severity.MEDIUM
                },
                'Content-Security-Policy': {
                    'value': None,
                    'description': 'Mitigates XSS and data injection',
                    'severity': Severity.HIGH
                },
                'Strict-Transport-Security': {
                    'value': None,
                    'description': 'Enforces HTTPS',
                    'severity': Severity.HIGH
                },
            }
            
            for header, config in required_headers.items():
                if header not in headers:
                    self.vulnerabilities.append(Vulnerability(
                        id="A05-Headers",
                        name=f"Missing Security Header: {header}",
                        severity=config['severity'],
                        description=config['description'],
                        evidence=f"Header {header} not present in response",
                        remediation=f"Add {header} header to all responses.",
                        url=self.target_url,
                        references=[
                            "https://owasp.org/www-project-secure-headers/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
                        ]
                    ))
            
            # Check for dangerous headers
            dangerous_headers = ['Server', 'X-Powered-By']
            for header in dangerous_headers:
                if header in headers:
                    self.vulnerabilities.append(Vulnerability(
                        id="A05-InfoLeak",
                        name="Information Disclosure",
                        severity=Severity.LOW,
                        description=f"Server version exposed via {header} header.",
                        evidence=f"{header}: {headers[header]}",
                        remediation=f"Remove or obfuscate {header} header.",
                        url=self.target_url,
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/"
                        ]
                    ))
                    
        except Exception as e:
            logger.error(f"Security headers check failed: {e}")
    
    def generate_report(self, output_format: str = "json", output_file: Optional[str] = None):
        """Generate scan report in specified format."""
        report = {
            "scan_info": {
                "target": self.target_url,
                "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_vulnerabilities": len(self.vulnerabilities),
                "severity_counts": {
                    "Critical": len([v for v in self.vulnerabilities if v.severity == Severity.CRITICAL]),
                    "High": len([v for v in self.vulnerabilities if v.severity == Severity.HIGH]),
                    "Medium": len([v for v in self.vulnerabilities if v.severity == Severity.MEDIUM]),
                    "Low": len([v for v in self.vulnerabilities if v.severity == Severity.LOW]),
                    "Info": len([v for v in self.vulnerabilities if v.severity == Severity.INFO])
                }
            },
            "vulnerabilities": [
                {
                    **asdict(v),
                    "severity": v.severity.value
                }
                for v in self.vulnerabilities
            ]
        }
        
        if output_format == "json":
            output = json.dumps(report, indent=2)
        elif output_format == "html":
            output = self._generate_html_report(report)
        else:
            output = self._generate_text_report(report)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            logger.info(f"Report saved to {output_file}")
        
        return output
    
    def _generate_html_report(self, report: Dict) -> str:
        """Generate HTML report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>OWASP Scan Report - {report['scan_info']['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .vulnerability {{ background: white; padding: 20px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 5px solid #e74c3c; }}
        .vulnerability.Critical {{ border-left-color: #c0392b; }}
        .vulnerability.High {{ border-left-color: #e74c3c; }}
        .vulnerability.Medium {{ border-left-color: #f39c12; }}
        .vulnerability.Low {{ border-left-color: #3498db; }}
        .severity {{ display: inline-block; padding: 5px 15px; border-radius: 3px; color: white; font-weight: bold; }}
        .severity.Critical {{ background: #c0392b; }}
        .severity.High {{ background: #e74c3c; }}
        .severity.Medium {{ background: #f39c12; }}
        .severity.Low {{ background: #3498db; }}
        .evidence {{ background: #ecf0f1; padding: 10px; border-radius: 3px; font-family: monospace; margin: 10px 0; }}
        .remediation {{ background: #d5f5e3; padding: 10px; border-radius: 3px; margin: 10px 0; }}
        .count-box {{ display: inline-block; padding: 10px 20px; margin: 5px; border-radius: 5px; font-weight: bold; }}
        .count.Critical {{ background: #c0392b; color: white; }}
        .count.High {{ background: #e74c3c; color: white; }}
        .count.Medium {{ background: #f39c12; color: white; }}
        .count.Low {{ background: #3498db; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>OWASP Top 10 Security Scan Report</h1>
        <p>Target: {report['scan_info']['target']}</p>
        <p>Scan Date: {report['scan_info']['scan_date']}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div>
            <span class="count-box count Critical">Critical: {report['scan_info']['severity_counts']['Critical']}</span>
            <span class="count-box count High">High: {report['scan_info']['severity_counts']['High']}</span>
            <span class="count-box count Medium">Medium: {report['scan_info']['severity_counts']['Medium']}</span>
            <span class="count-box count Low">Low: {report['scan_info']['severity_counts']['Low']}</span>
        </div>
        <p>Total Vulnerabilities Found: <strong>{report['scan_info']['total_vulnerabilities']}</strong></p>
    </div>
    
    <h2>Detailed Findings</h2>
"""
        
        for vuln in report['vulnerabilities']:
            html += f"""
    <div class="vulnerability {vuln['severity']}">
        <h3>{vuln['name']} <span class="severity {vuln['severity']}">{vuln['severity']}</span></h3>
        <p><strong>OWASP Category:</strong> {vuln['id']}</p>
        <p><strong>Description:</strong> {vuln['description']}</p>
        <p><strong>URL:</strong> {vuln['url']}</p>
        {f"<p><strong>Parameter:</strong> {vuln['parameter']}</p>" if vuln['parameter'] else ""}
        <div class="evidence">
            <strong>Evidence:</strong><br>
            {vuln['evidence']}
        </div>
        <div class="remediation">
            <strong>Remediation:</strong><br>
            {vuln['remediation']}
        </div>
    </div>
"""
        
        html += """
</body>
</html>"""
        return html
    
    def _generate_text_report(self, report: Dict) -> str:
        """Generate plain text report."""
        lines = [
            "=" * 80,
            "OWASP TOP 10 SECURITY SCAN REPORT",
            "=" * 80,
            f"Target: {report['scan_info']['target']}",
            f"Scan Date: {report['scan_info']['scan_date']}",
            "-" * 80,
            "SUMMARY",
            "-" * 80,
            f"Critical: {report['scan_info']['severity_counts']['Critical']}",
            f"High: {report['scan_info']['severity_counts']['High']}",
            f"Medium: {report['scan_info']['severity_counts']['Medium']}",
            f"Low: {report['scan_info']['severity_counts']['Low']}",
            f"Total: {report['scan_info']['total_vulnerabilities']}",
            "=" * 80,
            "DETAILED FINDINGS",
            "=" * 80,
            ""
        ]
        
        for i, vuln in enumerate(report['vulnerabilities'], 1):
            lines.extend([
                f"[{i}] {vuln['name']}",
                "-" * 40,
                f"Severity: {vuln['severity']}",
                f"Category: {vuln['id']}",
                f"URL: {vuln['url']}",
                f"Description: {vuln['description']}",
                f"Evidence: {vuln['evidence']}",
                f"Remediation: {vuln['remediation']}",
                ""
            ])
        
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="OWASP Top 10 Web Application Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py -u http://target.com
  python scanner.py -u http://target.com -o report.html -f html
  python scanner.py -u http://target.com -t 60 --threads 10
        """
    )
    
    parser.add_argument('-u', '--url', required=True,
                        help='Target URL to scan')
    parser.add_argument('-o', '--output',
                        help='Output file for report')
    parser.add_argument('-f', '--format', choices=['json', 'html', 'text'],
                        default='json', help='Report format (default: json)')
    parser.add_argument('-t', '--timeout', type=int, default=30,
                        help='Request timeout in seconds (default: 30)')
    parser.add_argument('--threads', type=int, default=5,
                        help='Number of concurrent threads (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║           OWASP TOP 10 VULNERABILITY SCANNER v1.0            ║
    ║                                                              ║
    ║  WARNING: Only use on systems you own or have permission to   ║
    ║           test. Unauthorized scanning is illegal.            ║
    ╚══════════════════════════════════════════════════════════════╝
    
    Target: {args.url}
    Starting scan...
    """)
    
    scanner = OWASPScanner(
        target_url=args.url,
        timeout=args.timeout,
        threads=args.threads
    )
    
    vulnerabilities = scanner.scan()
    
    if vulnerabilities:
        report = scanner.generate_report(
            output_format=args.format,
            output_file=args.output
        )
        
        if not args.output:
            print(report)
        
        print(f"\n[!] Scan complete. Found {len(vulnerabilities)} vulnerabilities.")
        critical = len([v for v in vulnerabilities if v.severity == Severity.CRITICAL])
        high = len([v for v in vulnerabilities if v.severity == Severity.HIGH])
        if critical > 0 or high > 0:
            print(f"[!] ATTENTION: {critical} Critical and {high} High severity issues found!")
    else:
        print("\n[+] No vulnerabilities detected.")
    
    return 0 if len(vulnerabilities) == 0 else 1


if __name__ == '__main__':
    sys.exit(main())