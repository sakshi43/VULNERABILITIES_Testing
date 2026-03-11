import requests

# 🔹 Full Vulnerabilities Database
VULNERABILITIES = {
    "lack_of_mfa": {
        "severity": "Medium",
        "title": "Lack of Multifactor Authentication (MFA)",
        "description": (
            "The system does not require more than one form of authentication during login. "
            "Attackers who obtain passwords can gain access easily. Users are more susceptible to phishing attacks."
        ),
        "fix": "Implement MFA and enforce strong password policies.",
        "reference": "https://cwe.mitre.org/data/definitions/308.html"
    },
    "missing_hsts": {
        "severity": "Medium",
        "title": "Missing Strict-Transport-Security (HSTS) Header",
        "description": (
            "The response does not include the Strict-Transport-Security header, which enforces secure HTTPS connections."
        ),
        "fix": "Add Strict-Transport-Security header with max-age and includeSubDomains.",
        "reference": "https://owasp.org/www-project-secure-headers/#strict-transport-security"
    },
    "missing_csp": {
        "severity": "Medium",
        "title": "Missing Content-Security-Policy (CSP) Header",
        "description": (
            "The response does not include a CSP header, which helps prevent XSS and data injection attacks."
        ),
        "fix": "Add a strong Content-Security-Policy header.",
        "reference": "https://owasp.org/www-project-secure-headers/#content-security-policy"
    },
    "missing_x_frame_options": {
        "severity": "Medium",
        "title": "Missing X-Frame-Options Header",
        "description": "Prevents clickjacking attacks. Without it, attacker can embed your site in iframe.",
        "fix": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'.",
        "reference": "https://owasp.org/www-project-secure-headers/#x-frame-options"
    },
    "missing_x_xss_protection": {
        "severity": "Low",
        "title": "Missing X-XSS-Protection Header",
        "description": "Some older browsers won't block reflected XSS attacks without this header.",
        "fix": "Set X-XSS-Protection to '1; mode=block'.",
        "reference": "https://owasp.org/www-project-secure-headers/#x-xss-protection"
    },
    "missing_x_content_type_options": {
        "severity": "Low",
        "title": "Missing X-Content-Type-Options Header",
        "description": "Prevents MIME type sniffing. Without it, browsers might execute malicious scripts.",
        "fix": "Set X-Content-Type-Options to 'nosniff'.",
        "reference": "https://owasp.org/www-project-secure-headers/#x-content-type-options"
    },
    "cors_wildcard": {
        "severity": "High",
        "title": "CORS Misconfiguration (wildcard *)",
        "description": "API allows any domain to access it. Can lead to data leaks.",
        "fix": "Restrict Access-Control-Allow-Origin to trusted domains.",
        "reference": "https://owasp.org/www-project-secure-headers/#cors"
    },
    "server_header": {
        "severity": "Low",
        "title": "Server Version Disclosure",
        "description": "Server header exposes version info, can help attackers.",
        "fix": "Hide or remove the server header.",
        "reference": "https://owasp.org/www-project-secure-headers/#server"
    },
    "reflected_xss": {
        "severity": "Critical",
        "title": "Reflected XSS",
        "description": "User input is reflected without sanitization, can execute scripts in victim's browser.",
        "fix": "Sanitize input and encode output.",
        "reference": "https://owasp.org/www-community/attacks/xss/"
    },
    "sql_injection": {
        "severity": "Critical",
        "title": "SQL Injection",
        "description": "Input not sanitized, attacker can modify SQL queries.",
        "fix": "Use parameterized queries or ORM.",
        "reference": "https://owasp.org/www-community/attacks/SQL_Injection"
    },
    "rate_limit_missing": {
        "severity": "High",
        "title": "No Rate Limiting",
        "description": "API does not limit requests, can be brute-forced.",
        "fix": "Implement rate limiting per IP or user.",
        "reference": "https://owasp.org/www-community/controls/Rate_limiting"
    },
    "insecure_cookie": {
        "severity": "Medium",
        "title": "Insecure Cookie",
        "description": "Cookies are missing Secure or HttpOnly flags.",
        "fix": "Set Secure and HttpOnly flags.",
        "reference": "https://owasp.org/www-project-secure-headers/#cookies"
    },
    "open_redirect": {
        "severity": "High",
        "title": "Open Redirect",
        "description": "API redirects to untrusted domains.",
        "fix": "Validate redirect URLs.",
        "reference": "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"
    },
    "directory_traversal": {
        "severity": "Critical",
        "title": "Directory Traversal",
        "description": "API exposes filesystem paths, attacker can access sensitive files.",
        "fix": "Sanitize file paths and restrict access.",
        "reference": "https://owasp.org/www-community/attacks/Path_Traversal"
    }
}


# 🔹 Scanner Function
def scan_api(url):
    results = []
    try:
        headers_req = {"User-Agent": "API-Security-Scanner/1.0"}
        response = requests.get(url, headers=headers_req)
        headers = response.headers
        cookies = response.cookies
        content = response.text.lower()

        # Header checks
        if "strict-transport-security" not in headers:
            results.append(VULNERABILITIES["missing_hsts"])
        if "content-security-policy" not in headers:
            results.append(VULNERABILITIES["missing_csp"])
        if "x-frame-options" not in headers:
            results.append(VULNERABILITIES["missing_x_frame_options"])
        if "x-xss-protection" not in headers:
            results.append(VULNERABILITIES["missing_x_xss_protection"])
        if "x-content-type-options" not in headers:
            results.append(VULNERABILITIES["missing_x_content_type_options"])
        if "access-control-allow-origin" in headers and headers["access-control-allow-origin"] == "*":
            results.append(VULNERABILITIES["cors_wildcard"])
        if "server" in headers:
            results.append(VULNERABILITIES["server_header"])
        if "login" in url.lower():
            results.append(VULNERABILITIES["lack_of_mfa"])

        # XSS test
        xss_payload = "<script>alert(1)</script>"
        test_response = requests.get(url, headers=headers_req, params={"test": xss_payload})
        if xss_payload in test_response.text:
            results.append(VULNERABILITIES["reflected_xss"])

        # SQLi test
        sql_payload = "' OR 1=1 --"
        test_response = requests.get(url, headers=headers_req, params={"id": sql_payload})
        if "error" in test_response.text.lower() or "sql" in test_response.text.lower():
            results.append(VULNERABILITIES["sql_injection"])

        # Rate limit
        rate_limited = False
        for _ in range(50):
            r = requests.get(url, headers=headers_req)
            if r.status_code == 429:
                rate_limited = True
                break
        if not rate_limited:
            results.append(VULNERABILITIES["rate_limit_missing"])

        # Cookie check
        for cookie in cookies:
            if not cookie.secure or not getattr(cookie, 'httponly', False):
                results.append(VULNERABILITIES["insecure_cookie"])

       
        return {
            "url": url,
            "vulnerabilities": results
        }

    except Exception as e:
        return {
            "url": url,
            "vulnerabilities": [{"title": "API not reachable", "description": str(e), "fix": "", "severity": "Critical", "reference": ""}]
        }