import requests
import json
import re
# 🔹 Full Vulnerabilities Database
# VULNERABILITIES = {
#     "pagination_attack": {
#     "severity": "Medium",
#     "title": "Pagination Abuse / Large Data Extraction",
#     "description": (
#         "API allows extremely large pagination values such as high limit, offset, or page numbers. "
#         "Attackers can exploit this to scrape entire datasets or cause heavy database queries."
#     ),
#     "fix": "Restrict maximum limit, validate page parameters, and implement pagination boundaries.",
#     "reference": "https://owasp.org/www-community/attacks/Denial_of_Service"
# },
#     "lack_of_mfa": {
#         "severity": "Medium",
#         "title": "Lack of Multifactor Authentication (MFA)",
#         "description": (
#             "The system does not require more than one form of authentication during login. "
#             "Attackers who obtain passwords can gain access easily. Users are more susceptible to phishing attacks."
#         ),
#         "fix": "Implement MFA and enforce strong password policies.",
#         "reference": "https://cwe.mitre.org/data/definitions/308.html"
#     },
#     "missing_hsts": {
#         "severity": "Medium",
#         "title": "Missing Strict-Transport-Security (HSTS) Header",
#         "description": (
#             "The response does not include the Strict-Transport-Security header, which enforces secure HTTPS connections."
#         ),
#         "fix": "Add Strict-Transport-Security header with max-age and includeSubDomains.",
#         "reference": "https://owasp.org/www-project-secure-headers/#strict-transport-security"
#     },
#     "missing_csp": {
#         "severity": "Medium",
#         "title": "Missing Content-Security-Policy (CSP) Header",
#         "description": (
#             "The response does not include a CSP header, which helps prevent XSS and data injection attacks."
#         ),
#         "fix": "Add a strong Content-Security-Policy header.",
#         "reference": "https://owasp.org/www-project-secure-headers/#content-security-policy"
#     },
#     "missing_x_frame_options": {
#         "severity": "Medium",
#         "title": "Missing X-Frame-Options Header",
#         "description": "Prevents clickjacking attacks. Without it, attacker can embed your site in iframe.",
#         "fix": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'.",
#         "reference": "https://owasp.org/www-project-secure-headers/#x-frame-options"
#     },
#     "missing_x_xss_protection": {
#         "severity": "Low",
#         "title": "Missing X-XSS-Protection Header",
#         "description": "Some older browsers won't block reflected XSS attacks without this header.",
#         "fix": "Set X-XSS-Protection to '1; mode=block'.",
#         "reference": "https://owasp.org/www-project-secure-headers/#x-xss-protection"
#     },
#     "missing_x_content_type_options": {
#         "severity": "Low",
#         "title": "Missing X-Content-Type-Options Header",
#         "description": "Prevents MIME type sniffing. Without it, browsers might execute malicious scripts.",
#         "fix": "Set X-Content-Type-Options to 'nosniff'.",
#         "reference": "https://owasp.org/www-project-secure-headers/#x-content-type-options"
#     },
#     "cors_wildcard": {
#         "severity": "High",
#         "title": "CORS Misconfiguration (wildcard *)",
#         "description": "API allows any domain to access it. Can lead to data leaks.",
#         "fix": "Restrict Access-Control-Allow-Origin to trusted domains.",
#         "reference": "https://owasp.org/www-project-secure-headers/#cors"
#     },
#     "server_header": {
#         "severity": "Low",
#         "title": "Server Version Disclosure",
#         "description": "Server header exposes version info, can help attackers.",
#         "fix": "Hide or remove the server header.",
#         "reference": "https://owasp.org/www-project-secure-headers/#server"
#     },
#     "reflected_xss": {
#         "severity": "Critical",
#         "title": "Reflected XSS",
#         "description": "User input is reflected without sanitization, can execute scripts in victim's browser.",
#         "fix": "Sanitize input and encode output.",
#         "reference": "https://owasp.org/www-community/attacks/xss/"
#     },
#     "sql_injection": {
#         "severity": "Critical",
#         "title": "SQL Injection",
#         "description": "Input not sanitized, attacker can modify SQL queries.",
#         "fix": "Use parameterized queries or ORM.",
#         "reference": "https://owasp.org/www-community/attacks/SQL_Injection"
#     },
#     "rate_limit_missing": {
#         "severity": "High",
#         "title": "No Rate Limiting",
#         "description": "API does not limit requests, can be brute-forced.",
#         "fix": "Implement rate limiting per IP or user.",
#         "reference": "https://owasp.org/www-community/controls/Rate_limiting"
#     },
#     "insecure_cookie": {
#         "severity": "Medium",
#         "title": "Insecure Cookie",
#         "description": "Cookies are missing Secure or HttpOnly flags.",
#         "fix": "Set Secure and HttpOnly flags.",
#         "reference": "https://owasp.org/www-project-secure-headers/#cookies"
#     },
#     "open_redirect": {
#         "severity": "High",
#         "title": "Open Redirect",
#         "description": "API redirects to untrusted domains.",
#         "fix": "Validate redirect URLs.",
#         "reference": "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"
#     },
#     "directory_traversal": {
#         "severity": "Critical",
#         "title": "Directory Traversal",
#         "description": "API exposes filesystem paths, attacker can access sensitive files.",
#         "fix": "Sanitize file paths and restrict access.",
#         "reference": "https://owasp.org/www-community/attacks/Path_Traversal"
#     }
# }


# ─────────────────────────────────────────────
# 🔹 Full Vulnerabilities Database
# ─────────────────────────────────────────────
VULNERABILITIES = {

    # ── HEADERS ──────────────────────────────
    "missing_hsts": {
        "severity": "Medium",
        "title": "Missing Strict-Transport-Security (HSTS) Header",
        "description": "The response does not include the Strict-Transport-Security header, which enforces secure HTTPS connections.",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "reference": "https://owasp.org/www-project-secure-headers/#strict-transport-security"
    },
    "missing_csp": {
        "severity": "Medium",
        "title": "Missing Content-Security-Policy (CSP) Header",
        "description": "No CSP header found. This leaves the site open to XSS and data injection attacks.",
        "fix": "Add a strict Content-Security-Policy header, e.g.: default-src 'self'",
        "reference": "https://owasp.org/www-project-secure-headers/#content-security-policy"
    },
    "missing_x_frame_options": {
        "severity": "Medium",
        "title": "Missing X-Frame-Options Header",
        "description": "Without this header, attackers can embed your site in an iframe for clickjacking attacks.",
        "fix": "Set X-Frame-Options: DENY or SAMEORIGIN",
        "reference": "https://owasp.org/www-project-secure-headers/#x-frame-options"
    },
    "missing_x_xss_protection": {
        "severity": "Low",
        "title": "Missing X-XSS-Protection Header",
        "description": "Older browsers won't block reflected XSS attacks without this header.",
        "fix": "Set X-XSS-Protection: 1; mode=block",
        "reference": "https://owasp.org/www-project-secure-headers/#x-xss-protection"
    },
    "missing_x_content_type_options": {
        "severity": "Low",
        "title": "Missing X-Content-Type-Options Header",
        "description": "Without this, browsers may MIME-sniff responses and execute malicious scripts.",
        "fix": "Set X-Content-Type-Options: nosniff",
        "reference": "https://owasp.org/www-project-secure-headers/#x-content-type-options"
    },
    "missing_referrer_policy": {
        "severity": "Low",
        "title": "Missing Referrer-Policy Header",
        "description": "Without a Referrer-Policy, sensitive URL data can leak to third-party sites.",
        "fix": "Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin",
        "reference": "https://owasp.org/www-project-secure-headers/#referrer-policy"
    },
    "missing_permissions_policy": {
        "severity": "Low",
        "title": "Missing Permissions-Policy Header",
        "description": "Without this header, browser features (camera, mic, geolocation) can be exploited.",
        "fix": "Add Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "reference": "https://owasp.org/www-project-secure-headers/#permissions-policy"
    },
    "server_header": {
        "severity": "Low",
        "title": "Server Version Disclosure",
        "description": "The Server header exposes version info that can help attackers fingerprint the system.",
        "fix": "Remove or obscure the Server header in your web server config.",
        "reference": "https://owasp.org/www-project-secure-headers/#server"
    },
    "x_powered_by": {
        "severity": "Low",
        "title": "X-Powered-By Header Disclosure",
        "description": "The X-Powered-By header reveals backend technology (e.g., PHP, Express), aiding attackers.",
        "fix": "Remove the X-Powered-By header.",
        "reference": "https://owasp.org/www-project-secure-headers/"
    },

    # ── CORS ─────────────────────────────────
    "cors_wildcard": {
        "severity": "High",
        "title": "CORS Misconfiguration (Wildcard *)",
        "description": "The API allows any domain to make cross-origin requests, which can lead to data leaks.",
        "fix": "Restrict Access-Control-Allow-Origin to specific trusted domains.",
        "reference": "https://owasp.org/www-project-secure-headers/#cors"
    },
    "cors_credentials_wildcard": {
        "severity": "Critical",
        "title": "CORS Misconfiguration with Credentials",
        "description": "API allows wildcard CORS with credentials=true, enabling cross-site data theft.",
        "fix": "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
        "reference": "https://portswigger.net/web-security/cors"
    },

    # ── INJECTION ────────────────────────────
    "reflected_xss": {
        "severity": "Critical",
        "title": "Reflected XSS",
        "description": "User input is reflected in the response without sanitization, allowing script injection.",
        "fix": "Sanitize all user input server-side and encode all output.",
        "reference": "https://owasp.org/www-community/attacks/xss/"
    },
    "sql_injection": {
        "severity": "Critical",
        "title": "SQL Injection",
        "description": "Unsanitized input is used in SQL queries, allowing attackers to manipulate the database.",
        "fix": "Use parameterized queries or an ORM. Never concatenate user input into SQL.",
        "reference": "https://owasp.org/www-community/attacks/SQL_Injection"
    },
    "directory_traversal": {
        "severity": "Critical",
        "title": "Directory Traversal",
        "description": "The API may expose filesystem paths, allowing access to sensitive files.",
        "fix": "Sanitize file path inputs and restrict access to the web root only.",
        "reference": "https://owasp.org/www-community/attacks/Path_Traversal"
    },
    "command_injection": {
        "severity": "Critical",
        "title": "Command Injection",
        "description": "The API may execute OS commands using unsanitized user input.",
        "fix": "Never pass user input to shell commands. Use safe APIs or whitelisted inputs.",
        "reference": "https://owasp.org/www-community/attacks/Command_Injection"
    },
    "ssti": {
        "severity": "Critical",
        "title": "Server-Side Template Injection (SSTI)",
        "description": "The API may evaluate template expressions from user input, enabling remote code execution.",
        "fix": "Never render user input as a template. Sanitize and escape all inputs.",
        "reference": "https://portswigger.net/web-security/server-side-template-injection"
    },

    # ── AUTH / ACCESS ─────────────────────────
    "lack_of_mfa": {
        "severity": "Medium",
        "title": "Lack of Multifactor Authentication (MFA)",
        "description": "Login endpoints do not require a second factor, making accounts vulnerable to credential theft.",
        "fix": "Implement MFA (TOTP, SMS, or hardware key) for all login flows.",
        "reference": "https://cwe.mitre.org/data/definitions/308.html"
    },
    "rate_limit_missing": {
        "severity": "High",
        "title": "No Rate Limiting",
        "description": "The API does not restrict request rates, enabling brute force and DoS attacks.",
        "fix": "Implement rate limiting per IP or user token using tools like nginx, express-rate-limit, etc.",
        "reference": "https://owasp.org/www-community/controls/Rate_limiting"
    },
    "open_redirect": {
        "severity": "High",
        "title": "Open Redirect",
        "description": "The API redirects to untrusted external domains, enabling phishing attacks.",
        "fix": "Validate and whitelist all redirect URLs server-side.",
        "reference": "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"
    },
    "http_methods_exposed": {
        "severity": "Medium",
        "title": "Dangerous HTTP Methods Exposed",
        "description": "Methods like PUT, DELETE, TRACE, or OPTIONS may be enabled and exploitable.",
        "fix": "Disable unused HTTP methods in your server or API gateway config.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"
    },

    # ── COOKIES ──────────────────────────────
    "insecure_cookie": {
        "severity": "Medium",
        "title": "Insecure Cookie",
        "description": "Cookies are missing Secure and/or HttpOnly flags, making them vulnerable to theft.",
        "fix": "Set Secure, HttpOnly, and SameSite=Strict or Lax on all sensitive cookies.",
        "reference": "https://owasp.org/www-project-secure-headers/#cookies"
    },
    "cookie_no_samesite": {
        "severity": "Medium",
        "title": "Cookie Missing SameSite Attribute",
        "description": "Cookies without SameSite can be sent in cross-site requests, enabling CSRF attacks.",
        "fix": "Set SameSite=Strict or SameSite=Lax on all cookies.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#samesite_cookies"
    },

    # ── DATA EXPOSURE ─────────────────────────
    "pagination_attack": {
        "severity": "Medium",
        "title": "Pagination Abuse / Large Data Extraction",
        "description": "API allows extremely large pagination values, enabling full dataset scraping.",
        "fix": "Restrict max limit values, validate page parameters, and enforce pagination boundaries.",
        "reference": "https://owasp.org/www-community/attacks/Denial_of_Service"
    },
    "sensitive_data_exposure": {
        "severity": "High",
        "title": "Sensitive Data in Response",
        "description": "The response body may contain sensitive fields like passwords, tokens, or private keys.",
        "fix": "Audit all API responses. Never expose passwords, tokens, or internal keys in responses.",
        "reference": "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
    },
    "json_hijacking": {
        "severity": "Medium",
        "title": "JSON Array Response Vulnerable to Hijacking",
        "description": "API returns a JSON array as a top-level response, which older browsers may expose cross-origin.",
        "fix": "Always return JSON objects (not bare arrays) as root responses.",
        "reference": "https://owasp.org/www-community/vulnerabilities/JSON_Hijacking"
    },

    # ── TLS / HTTPS ───────────────────────────
    "http_used": {
        "severity": "High",
        "title": "HTTP (Non-HTTPS) Endpoint",
        "description": "The API is accessible over plain HTTP, meaning data is transmitted unencrypted.",
        "fix": "Enforce HTTPS across all endpoints. Redirect HTTP to HTTPS.",
        "reference": "https://owasp.org/www-project-secure-headers/#strict-transport-security"
    },
}
from urllib.parse import urljoin, urlparse

# 🔹 Scanner Function
def scan_api(url):
    """
    Scans a given API URL for common security vulnerabilities.
    Returns a dict with the URL and a list of found vulnerabilities.
    """
    results = []
    seen_titles = set()  # Prevent duplicate entries

    def add_vuln(key: str):
        vuln = VULNERABILITIES.get(key)
        if vuln and vuln["title"] not in seen_titles:
            results.append(vuln)
            seen_titles.add(vuln["title"])

    req_headers = {"User-Agent": "API-Security-Scanner/1.0"}

    try:
        response = requests.get(url, headers=req_headers, timeout=10)
        headers = response.headers
        cookies = response.cookies
        body = response.text

        parsed = urlparse(url)

        # ── TLS Check ──────────────────────────────────
        if parsed.scheme == "http":
            add_vuln("http_used")

        # ── Security Headers ───────────────────────────
        header_checks = {
            "strict-transport-security":  "missing_hsts",
            "content-security-policy":    "missing_csp",
            "x-frame-options":            "missing_x_frame_options",
            "x-xss-protection":           "missing_x_xss_protection",
            "x-content-type-options":     "missing_x_content_type_options",
            "referrer-policy":            "missing_referrer_policy",
            "permissions-policy":         "missing_permissions_policy",
        }
        for header, vuln_key in header_checks.items():
            if header not in [h.lower() for h in headers]:
                add_vuln(vuln_key)

        if "server" in headers:
            add_vuln("server_header")

        if "x-powered-by" in headers:
            add_vuln("x_powered_by")

        # ── CORS ───────────────────────────────────────
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        if acao == "*":
            if acac == "true":
                add_vuln("cors_credentials_wildcard")
            else:
                add_vuln("cors_wildcard")

        # ── Login Endpoint → MFA Check ─────────────────
        if any(kw in url.lower() for kw in ["login", "signin", "auth", "token"]):
            add_vuln("lack_of_mfa")

        # ── Reflected XSS ──────────────────────────────
        xss_payload = "<script>alert(1)</script>"
        xss_resp = requests.get(url, headers=req_headers, params={"q": xss_payload}, timeout=10)
        if xss_payload in xss_resp.text:
            add_vuln("reflected_xss")

        # ── SQL Injection ──────────────────────────────
        sql_payload = "' OR '1'='1' --"
        sql_resp = requests.get(url, headers=req_headers, params={"id": sql_payload}, timeout=10)
        sql_error_patterns = [
            "sql syntax", "mysql_fetch", "ora-", "pg_query",
            "unclosed quotation", "sqlite_", "odbc driver"
        ]
        if any(p in sql_resp.text.lower() for p in sql_error_patterns):
            add_vuln("sql_injection")

        # ── Command Injection ──────────────────────────
        cmd_payloads = ["; ls", "| whoami", "`id`", "$(cat /etc/passwd)"]
        for cmd in cmd_payloads:
            cmd_resp = requests.get(url, headers=req_headers, params={"cmd": cmd}, timeout=10)
            if any(kw in cmd_resp.text.lower() for kw in ["root:", "uid=", "bin/bash", "volume"]):
                add_vuln("command_injection")
                break

        # ── SSTI ───────────────────────────────────────
        ssti_payloads = {"name": "{{7*7}}", "q": "${7*7}"}
        for param, payload in ssti_payloads.items():
            ssti_resp = requests.get(url, headers=req_headers, params={param: payload}, timeout=10)
            if "49" in ssti_resp.text:
                add_vuln("ssti")
                break

        # ── Directory Traversal ────────────────────────
        traversal_payloads = ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini"]
        for trav in traversal_payloads:
            t_resp = requests.get(url, headers=req_headers, params={"file": trav}, timeout=10)
            if "root:x:" in t_resp.text or "[extensions]" in t_resp.text:
                add_vuln("directory_traversal")
                break

        # ── Rate Limiting ──────────────────────────────
        rate_limited = False
        for _ in range(30):
            r = requests.get(url, headers=req_headers, timeout=10)
            if r.status_code == 429:
                rate_limited = True
                break
        if not rate_limited:
            add_vuln("rate_limit_missing")

        # ── Open Redirect ──────────────────────────────
        redirect_payloads = ["https://evil.com", "//evil.com", "/\\evil.com"]
        for rp in redirect_payloads:
            r = requests.get(
                url, headers=req_headers, params={"redirect": rp, "next": rp, "url": rp},
                timeout=10, allow_redirects=False
            )
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("location", "")
                if "evil.com" in location:
                    add_vuln("open_redirect")
                    break

        # ── HTTP Methods ───────────────────────────────
        try:
            options_resp = requests.options(url, headers=req_headers, timeout=10)
            allow = options_resp.headers.get("allow", options_resp.headers.get("Allow", ""))
            dangerous_methods = {"PUT", "DELETE", "TRACE", "CONNECT"}
            if dangerous_methods & set(m.strip().upper() for m in allow.split(",")):
                add_vuln("http_methods_exposed")
        except Exception:
            pass

        # ── Cookies ────────────────────────────────────
        for cookie in cookies:
            if not cookie.secure or not getattr(cookie, "has_nonstandard_attr", lambda x: False)("HttpOnly"):
                add_vuln("insecure_cookie")
            samesite = cookie._rest.get("SameSite", "") if hasattr(cookie, "_rest") else ""
            if not samesite:
                add_vuln("cookie_no_samesite")

        # ── Sensitive Data Exposure ────────────────────
        sensitive_patterns = [
            r'"password"\s*:', r'"passwd"\s*:', r'"secret"\s*:',
            r'"api_key"\s*:', r'"private_key"\s*:', r'"token"\s*:\s*"[A-Za-z0-9+/=]{20,}"'
        ]
        for pattern in sensitive_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                add_vuln("sensitive_data_exposure")
                break

        # ── JSON Hijacking ─────────────────────────────
        stripped = body.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                parsed_body = json.loads(stripped)
                if isinstance(parsed_body, list):
                    add_vuln("json_hijacking")
            except json.JSONDecodeError:
                pass

        # ── Pagination Attack ──────────────────────────
        pagination_payloads = [
            {"page": 1, "limit": 100000},
            {"page": -1, "limit": 10},
            {"offset": -100},
            {"page": 999999},
        ]
        for payload in pagination_payloads:
            try:
                p_resp = requests.get(url, headers=req_headers, params=payload, timeout=10)
                if p_resp.status_code == 200 and len(p_resp.text) > 10000:
                    add_vuln("pagination_attack")
                    break
            except Exception:
                pass

        return {"url": url, "vulnerabilities": results}

    except Exception as e:
        return {
            "url": url,
            "vulnerabilities": [{
                "title": "API Not Reachable",
                "description": str(e),
                "fix": "Check if the URL is correct and the server is running.",
                "severity": "Critical",
                "reference": ""
            }]
        }
