#!/bin/bash

# Security Testing Script for sandbox.contracts.com.sa/login
# Using provided credentials: azmadmin / P@ssw0rd

TARGET_URL="https://sandbox.contracts.com.sa/login"
USERNAME="azmadmin"
PASSWORD="P@ssw0rd"

echo "=========================================="
echo "Security Testing Suite"
echo "Target: $TARGET_URL"
echo "Credentials: $USERNAME / [REDACTED]"
echo "=========================================="

# Create output directory
mkdir -p security_results

# Function to log results
log_result() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    echo "[$status] $test_name: $details"
    echo "$(date): [$status] $test_name: $details" >> security_results/security_test.log
}

echo
echo "=== 1. HTTP Security Headers Analysis ==="
curl -I -s "$TARGET_URL" > security_results/headers.txt
echo "Response headers saved to security_results/headers.txt"

# Check for security headers
if grep -qi "strict-transport-security" security_results/headers.txt; then
    log_result "HSTS Header" "PASS" "Strict-Transport-Security header present"
else
    log_result "HSTS Header" "FAIL" "Missing Strict-Transport-Security header"
fi

if grep -qi "x-frame-options" security_results/headers.txt; then
    log_result "X-Frame-Options" "PASS" "X-Frame-Options header present"
else
    log_result "X-Frame-Options" "FAIL" "Missing X-Frame-Options header (clickjacking protection)"
fi

if grep -qi "x-content-type-options" security_results/headers.txt; then
    log_result "X-Content-Type-Options" "PASS" "X-Content-Type-Options header present"
else
    log_result "X-Content-Type-Options" "FAIL" "Missing X-Content-Type-Options header"
fi

if grep -qi "content-security-policy" security_results/headers.txt; then
    log_result "CSP Header" "PASS" "Content-Security-Policy header present"
else
    log_result "CSP Header" "FAIL" "Missing Content-Security-Policy header"
fi

if grep -qi "server:" security_results/headers.txt; then
    server_info=$(grep -i "server:" security_results/headers.txt)
    log_result "Server Header" "WARNING" "Server information disclosed: $server_info"
fi

echo
echo "=== 2. SSL/TLS Configuration Test ==="
# Test HTTPS enforcement
http_url="${TARGET_URL/https:/http:}"
http_response=$(curl -I -s -o /dev/null -w "%{http_code}" --max-time 10 "$http_url" 2>/dev/null)

if [[ "$http_response" =~ ^30[1-8]$ ]]; then
    log_result "HTTPS Redirect" "PASS" "HTTP redirects to HTTPS (Status: $http_response)"
elif [[ "$http_response" == "000" ]]; then
    log_result "HTTPS Redirect" "PASS" "HTTP connection refused (good security practice)"
else
    log_result "HTTPS Redirect" "FAIL" "HTTP does not redirect to HTTPS (Status: $http_response)"
fi

echo
echo "=== 3. Information Disclosure Tests ==="
base_url="${TARGET_URL%/login}"
test_paths=(
    "/robots.txt"
    "/.well-known/security.txt"
    "/sitemap.xml"
    "/admin"
    "/api"
    "/swagger"
    "/docs"
    "/.git/"
    "/web.config"
    "/wp-admin"
    "/phpmyadmin"
    "/adminer"
    "/config"
    "/.env"
)

for path in "${test_paths[@]}"; do
    test_url="${base_url}${path}"
    status_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$test_url")
    
    if [[ "$status_code" == "200" ]]; then
        log_result "Path Discovery: $path" "WARNING" "Accessible (Status: $status_code)"
    elif [[ "$status_code" =~ ^40[13]$ ]]; then
        log_result "Path Discovery: $path" "INFO" "Protected (Status: $status_code)"
    fi
done

echo
echo "=== 4. Authentication Testing with Provided Credentials ==="
# Test the provided credentials
echo "Testing provided credentials..."
login_response=$(curl -s -X POST "$TARGET_URL" \
    -d "username=$USERNAME" \
    -d "password=$PASSWORD" \
    -c security_results/cookies.txt \
    -w "%{http_code}" \
    -o security_results/login_response.html)

echo "Login response status: $login_response"
echo "Login response saved to security_results/login_response.html"

if [[ "$login_response" =~ ^20[0-9]$ ]]; then
    if grep -qi "dashboard\|welcome\|home\|profile\|logout" security_results/login_response.html; then
        log_result "Authentication Test" "SUCCESS" "Login successful with provided credentials"
        
        # Check if we got session cookies
        if [[ -f security_results/cookies.txt ]] && [[ -s security_results/cookies.txt ]]; then
            log_result "Session Management" "INFO" "Session cookies received"
            cat security_results/cookies.txt
        fi
    else
        log_result "Authentication Test" "FAIL" "Login appears unsuccessful despite 200 status"
    fi
elif [[ "$login_response" =~ ^30[0-9]$ ]]; then
    # Check redirect location
    redirect_location=$(curl -s -I -X POST "$TARGET_URL" \
        -d "username=$USERNAME" \
        -d "password=$PASSWORD" | grep -i "location:")
    
    if [[ "$redirect_location" =~ dashboard|home|profile ]]; then
        log_result "Authentication Test" "SUCCESS" "Login successful - redirected to: $redirect_location"
    else
        log_result "Authentication Test" "UNCERTAIN" "Redirect received: $redirect_location"
    fi
else
    log_result "Authentication Test" "FAIL" "Login failed with status: $login_response"
fi

echo
echo "=== 5. Session Security Tests ==="
if [[ -f security_results/cookies.txt ]] && [[ -s security_results/cookies.txt ]]; then
    # Check cookie security attributes
    if grep -qi "secure" security_results/cookies.txt; then
        log_result "Cookie Security" "PASS" "Secure flag found on cookies"
    else
        log_result "Cookie Security" "FAIL" "Missing Secure flag on cookies"
    fi
    
    if grep -qi "httponly" security_results/cookies.txt; then
        log_result "Cookie HTTPOnly" "PASS" "HTTPOnly flag found on cookies"
    else
        log_result "Cookie HTTPOnly" "FAIL" "Missing HTTPOnly flag on cookies"
    fi
    
    if grep -qi "samesite" security_results/cookies.txt; then
        log_result "Cookie SameSite" "PASS" "SameSite attribute found on cookies"
    else
        log_result "Cookie SameSite" "WARNING" "Missing SameSite attribute on cookies"
    fi
fi

echo
echo "=== 6. Input Validation Tests ==="
# Test SQL injection payloads
sql_payloads=(
    "' OR '1'='1"
    "admin'--"
    "' UNION SELECT NULL--"
    "1' OR '1'='1' /*"
)

for payload in "${sql_payloads[@]}"; do
    response=$(curl -s -X POST "$TARGET_URL" \
        -d "username=$payload" \
        -d "password=test" \
        -o security_results/sqli_test.html \
        -w "%{http_code}")
    
    if grep -qi "sql\|mysql\|syntax error\|database\|query" security_results/sqli_test.html; then
        log_result "SQL Injection" "CRITICAL" "Possible SQL injection with payload: ${payload:0:20}..."
    else
        log_result "SQL Injection" "PASS" "No SQL error with payload: ${payload:0:20}..."
    fi
done

# Test XSS payloads
xss_payloads=(
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert('XSS')>"
    "javascript:alert('XSS')"
)

for payload in "${xss_payloads[@]}"; do
    response=$(curl -s -X POST "$TARGET_URL" \
        -d "username=$payload" \
        -d "password=test" \
        -o security_results/xss_test.html \
        -w "%{http_code}")
    
    if grep -q "$payload" security_results/xss_test.html; then
        log_result "XSS" "CRITICAL" "Possible XSS reflection with payload: ${payload:0:20}..."
    else
        log_result "XSS" "PASS" "No XSS reflection with payload: ${payload:0:20}..."
    fi
done

echo
echo "=== 7. Rate Limiting Tests ==="
echo "Testing rate limiting with multiple rapid requests..."
blocked_count=0

for i in {1..10}; do
    response=$(curl -s -X POST "$TARGET_URL" \
        -d "username=test$i" \
        -d "password=wrongpassword" \
        -w "%{http_code}" \
        -o /dev/null \
        --max-time 5)
    
    if [[ "$response" == "429" ]] || [[ "$response" == "403" ]]; then
        ((blocked_count++))
    fi
    
    # Small delay between requests
    sleep 0.1
done

if [[ $blocked_count -gt 0 ]]; then
    log_result "Rate Limiting" "PASS" "Rate limiting detected after $blocked_count blocked requests"
else
    log_result "Rate Limiting" "FAIL" "No rate limiting detected in 10 rapid requests"
fi

echo
echo "=== 8. CSRF Protection Tests ==="
# Get the login page and check for CSRF tokens
curl -s "$TARGET_URL" > security_results/login_page.html

if grep -qi "csrf\|token\|_token\|authenticity_token" security_results/login_page.html; then
    log_result "CSRF Protection" "PASS" "CSRF tokens detected in login page"
else
    log_result "CSRF Protection" "WARNING" "No obvious CSRF protection detected"
fi

echo
echo "=== 9. Error Handling Tests ==="
# Test with malformed data
test_cases=(
    "username=$(printf 'A%.0s' {1..1000})"
    "password=$(printf 'B%.0s' {1..1000})"
    "username=$(printf '\x00\x01\x02')"
)

for test_case in "${test_cases[@]}"; do
    response=$(curl -s -X POST "$TARGET_URL" \
        -d "$test_case" \
        -o security_results/error_test.html \
        -w "%{http_code}")
    
    if grep -qi "stack trace\|exception\|error\|debug\|warning" security_results/error_test.html; then
        log_result "Error Handling" "WARNING" "Verbose error messages detected with: ${test_case:0:30}..."
    else
        log_result "Error Handling" "PASS" "Clean error handling with: ${test_case:0:30}..."
    fi
done

echo
echo "=== 10. Post-Authentication Tests ==="
if [[ -f security_results/cookies.txt ]] && [[ -s security_results/cookies.txt ]]; then
    echo "Testing authenticated requests..."
    
    # Test if we can access protected areas
    auth_response=$(curl -s -b security_results/cookies.txt \
        "${base_url}/dashboard" \
        -w "%{http_code}" \
        -o security_results/dashboard_response.html)
    
    if [[ "$auth_response" == "200" ]]; then
        log_result "Post-Auth Access" "SUCCESS" "Successfully accessed dashboard with session"
        
        # Check for sensitive information disclosure
        if grep -qi "password\|secret\|key\|token\|admin" security_results/dashboard_response.html; then
            log_result "Information Disclosure" "WARNING" "Potential sensitive information in dashboard"
        fi
    else
        log_result "Post-Auth Access" "INFO" "Dashboard access returned status: $auth_response"
    fi
fi

echo
echo "=========================================="
echo "SECURITY TEST SUMMARY"
echo "=========================================="

total_tests=$(grep -c "^\[" security_results/security_test.log 2>/dev/null || echo "0")
critical_issues=$(grep -c "^\[CRITICAL\]" security_results/security_test.log 2>/dev/null || echo "0")
warnings=$(grep -c "^\[WARNING\]" security_results/security_test.log 2>/dev/null || echo "0")
failures=$(grep -c "^\[FAIL\]" security_results/security_test.log 2>/dev/null || echo "0")
passes=$(grep -c "^\[PASS\]" security_results/security_test.log 2>/dev/null || echo "0")

echo "Total Tests Run: $total_tests"
echo "Critical Issues: $critical_issues"
echo "Warnings: $warnings"
echo "Failures: $failures"
echo "Passes: $passes"

echo
echo "=== CRITICAL ISSUES ==="
grep "^\[CRITICAL\]" security_results/security_test.log 2>/dev/null || echo "None found"

echo
echo "=== WARNINGS ==="
grep "^\[WARNING\]" security_results/security_test.log 2>/dev/null || echo "None found"

echo
echo "=== FAILURES ==="
grep "^\[FAIL\]" security_results/security_test.log 2>/dev/null || echo "None found"

echo
echo "=========================================="
echo "All results saved to security_results/ directory"
echo "Main log: security_results/security_test.log"
echo "=========================================="