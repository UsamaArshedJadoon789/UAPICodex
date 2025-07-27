#!/usr/bin/env python3
"""
Comprehensive Security Testing Script for sandbox.contracts.com.sa/login
This script performs various security tests on the target login endpoint.
"""

import requests
import sys
import json
from urllib.parse import urlparse
import time
import random
import string

class SecurityTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.results = []
        
    def log_result(self, test_name, status, details):
        result = {
            "test": test_name,
            "status": status,
            "details": details,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.results.append(result)
        print(f"[{status}] {test_name}: {details}")
        
    def test_http_headers(self):
        """Test for security headers"""
        print("\n=== HTTP Security Headers Analysis ===")
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            # Check for important security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS header',
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Content-Security-Policy': 'CSP header',
                'X-XSS-Protection': 'XSS protection',
                'Referrer-Policy': 'Referrer policy',
                'Permissions-Policy': 'Feature policy'
            }
            
            for header, description in security_headers.items():
                if header in headers:
                    self.log_result(f"Security Header: {header}", "PASS", f"Present: {headers[header]}")
                else:
                    self.log_result(f"Security Header: {header}", "FAIL", f"Missing {description}")
                    
            # Check server information disclosure
            if 'Server' in headers:
                self.log_result("Server Header", "WARNING", f"Server info disclosed: {headers['Server']}")
            
        except Exception as e:
            self.log_result("HTTP Headers Test", "ERROR", str(e))
            
    def test_ssl_tls(self):
        """Test SSL/TLS configuration"""
        print("\n=== SSL/TLS Configuration Test ===")
        try:
            # Test HTTPS enforcement
            http_url = self.target_url.replace('https://', 'http://')
            try:
                response = requests.get(http_url, timeout=10, allow_redirects=False)
                if response.status_code in [301, 302, 307, 308]:
                    self.log_result("HTTPS Redirect", "PASS", "HTTP redirects to HTTPS")
                else:
                    self.log_result("HTTPS Redirect", "FAIL", "HTTP does not redirect to HTTPS")
            except:
                self.log_result("HTTPS Redirect", "PASS", "HTTP connection refused (good)")
                
        except Exception as e:
            self.log_result("SSL/TLS Test", "ERROR", str(e))
            
    def test_information_disclosure(self):
        """Test for information disclosure"""
        print("\n=== Information Disclosure Tests ===")
        
        # Test common paths for information disclosure
        test_paths = [
            '/robots.txt',
            '/.well-known/security.txt',
            '/sitemap.xml',
            '/admin',
            '/login',
            '/api',
            '/swagger',
            '/docs',
            '/.git/',
            '/web.config',
            '/wp-admin'
        ]
        
        for path in test_paths:
            try:
                test_url = self.target_url.replace('/login', path)
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    self.log_result(f"Path Discovery: {path}", "WARNING", f"Accessible (Status: {response.status_code})")
                elif response.status_code in [403, 401]:
                    self.log_result(f"Path Discovery: {path}", "INFO", f"Protected (Status: {response.status_code})")
            except:
                continue
                
    def test_input_validation(self):
        """Test input validation on login form"""
        print("\n=== Input Validation Tests ===")
        
        # Common SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' OR '1'='1' /*",
            "'; DROP TABLE users;--"
        ]
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]
        
        # Test SQL injection
        for payload in sql_payloads:
            try:
                data = {
                    'username': payload,
                    'password': 'test',
                    'email': payload
                }
                response = self.session.post(self.target_url, data=data, timeout=10)
                if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax error', 'database']):
                    self.log_result("SQL Injection", "CRITICAL", f"Possible SQL injection with payload: {payload}")
                else:
                    self.log_result("SQL Injection", "PASS", f"No SQL error with payload: {payload[:20]}...")
            except:
                continue
                
        # Test XSS
        for payload in xss_payloads:
            try:
                data = {
                    'username': payload,
                    'password': 'test'
                }
                response = self.session.post(self.target_url, data=data, timeout=10)
                if payload in response.text:
                    self.log_result("XSS", "CRITICAL", f"Possible XSS reflection with payload: {payload}")
                else:
                    self.log_result("XSS", "PASS", f"No XSS reflection with payload: {payload[:20]}...")
            except:
                continue
                
    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        print("\n=== Authentication Bypass Tests ===")
        
        bypass_attempts = [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'administrator', 'password': 'administrator'},
            {'username': 'root', 'password': 'root'},
            {'username': 'admin', 'password': ''},
            {'username': '', 'password': ''},
            {'username': 'admin', 'password': '123456'},
            {'username': 'test', 'password': 'test'}
        ]
        
        for creds in bypass_attempts:
            try:
                response = self.session.post(self.target_url, data=creds, timeout=10)
                if response.status_code == 200 and 'dashboard' in response.text.lower():
                    self.log_result("Weak Credentials", "CRITICAL", f"Possible login with {creds['username']}/{creds['password']}")
                elif response.status_code in [302, 301] and 'dashboard' in str(response.headers.get('Location', '')):
                    self.log_result("Weak Credentials", "CRITICAL", f"Possible login redirect with {creds['username']}/{creds['password']}")
                else:
                    self.log_result("Weak Credentials", "PASS", f"No bypass with {creds['username']}")
            except:
                continue
                
    def test_rate_limiting(self):
        """Test for rate limiting and brute force protection"""
        print("\n=== Rate Limiting Tests ===")
        
        # Send multiple rapid requests
        start_time = time.time()
        blocked_count = 0
        
        for i in range(10):
            try:
                data = {'username': f'test{i}', 'password': 'wrongpassword'}
                response = self.session.post(self.target_url, data=data, timeout=5)
                
                if response.status_code == 429:  # Too Many Requests
                    blocked_count += 1
                elif response.status_code == 403:  # Forbidden
                    blocked_count += 1
                    
            except:
                continue
                
        if blocked_count > 0:
            self.log_result("Rate Limiting", "PASS", f"Rate limiting detected after {blocked_count} requests")
        else:
            self.log_result("Rate Limiting", "FAIL", "No rate limiting detected")
            
    def test_csrf_protection(self):
        """Test for CSRF protection"""
        print("\n=== CSRF Protection Tests ===")
        
        try:
            # Get the login page to check for CSRF tokens
            response = self.session.get(self.target_url, timeout=10)
            
            csrf_indicators = ['csrf', 'token', '_token', 'authenticity_token']
            csrf_found = any(indicator in response.text.lower() for indicator in csrf_indicators)
            
            if csrf_found:
                self.log_result("CSRF Protection", "PASS", "CSRF tokens detected in page")
            else:
                self.log_result("CSRF Protection", "WARNING", "No obvious CSRF protection detected")
                
        except Exception as e:
            self.log_result("CSRF Protection", "ERROR", str(e))
            
    def test_error_handling(self):
        """Test error handling and information disclosure"""
        print("\n=== Error Handling Tests ===")
        
        # Test various malformed requests
        test_cases = [
            {'data': {'username': 'A' * 10000}, 'test': 'Long username'},
            {'data': {'password': 'A' * 10000}, 'test': 'Long password'},
            {'data': {'username': '\x00\x01\x02'}, 'test': 'Binary data'},
            {'data': {}, 'test': 'Empty data'},
            {'headers': {'Content-Type': 'application/xml'}, 'test': 'Wrong content type'}
        ]
        
        for case in test_cases:
            try:
                response = self.session.post(
                    self.target_url, 
                    data=case.get('data', {}),
                    headers=case.get('headers', {}),
                    timeout=10
                )
                
                # Check for verbose error messages
                error_indicators = ['stack trace', 'exception', 'error', 'debug', 'warning']
                if any(indicator in response.text.lower() for indicator in error_indicators):
                    self.log_result(f"Error Handling: {case['test']}", "WARNING", "Verbose error messages detected")
                else:
                    self.log_result(f"Error Handling: {case['test']}", "PASS", "Clean error handling")
                    
            except:
                continue
                
    def generate_report(self):
        """Generate a summary report"""
        print("\n" + "="*50)
        print("SECURITY TEST SUMMARY REPORT")
        print("="*50)
        
        total_tests = len(self.results)
        critical_issues = len([r for r in self.results if r['status'] == 'CRITICAL'])
        warnings = len([r for r in self.results if r['status'] == 'WARNING'])
        failures = len([r for r in self.results if r['status'] == 'FAIL'])
        passes = len([r for r in self.results if r['status'] == 'PASS'])
        
        print(f"Total Tests Run: {total_tests}")
        print(f"Critical Issues: {critical_issues}")
        print(f"Warnings: {warnings}")
        print(f"Failures: {failures}")
        print(f"Passes: {passes}")
        
        print("\n=== CRITICAL ISSUES ===")
        for result in self.results:
            if result['status'] == 'CRITICAL':
                print(f"- {result['test']}: {result['details']}")
                
        print("\n=== WARNINGS ===")
        for result in self.results:
            if result['status'] == 'WARNING':
                print(f"- {result['test']}: {result['details']}")
                
        # Save detailed report to file
        with open('security_test_report.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nDetailed report saved to: security_test_report.json")
        
    def run_all_tests(self):
        """Run all security tests"""
        print("Starting comprehensive security testing...")
        print(f"Target: {self.target_url}")
        print("="*50)
        
        self.test_http_headers()
        self.test_ssl_tls()
        self.test_information_disclosure()
        self.test_input_validation()
        self.test_authentication_bypass()
        self.test_rate_limiting()
        self.test_csrf_protection()
        self.test_error_handling()
        
        self.generate_report()

def main():
    target_url = "https://sandbox.contracts.com.sa/login"
    
    print("Security Testing Suite")
    print("Target: sandbox.contracts.com.sa/login")
    print("="*50)
    
    tester = SecurityTester(target_url)
    tester.run_all_tests()

if __name__ == "__main__":
    main()