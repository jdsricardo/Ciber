#!/usr/bin/env python3
"""Passive, non-destructive HTTP security checks. Standard library only."""
import argparse
import json
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection
from ipaddress import ip_address
from urllib.parse import urlparse

CATALOG = {
    "transport.https": ("Connection is not encrypted", "high", "Anyone on the network path may read or modify requests, including credentials.", "Redirect every HTTP request to HTTPS and configure a valid TLS certificate."),
    "headers.hsts": ("Browser can be downgraded to HTTP", "medium", "A first visit can still be intercepted before your HTTPS redirect runs.", "On HTTPS responses, add `Strict-Transport-Security: max-age=31536000; includeSubDomains` after validating all subdomains."),
    "headers.csp": ("Browser has no content execution policy", "high", "Injected scripts have fewer browser-level restrictions, increasing the impact of an XSS bug.", "Start with a report-only Content Security Policy, inventory required origins, then enforce a restrictive policy without `unsafe-inline`."),
    "headers.frame": ("Page can potentially be embedded in another site", "medium", "An attacker may overlay your page and trick users into clicking sensitive controls (clickjacking).", "Add `frame-ancestors 'none'` or trusted origins to Content-Security-Policy. `X-Frame-Options: DENY` is a legacy fallback."),
    "headers.nosniff": ("Browser may guess response content types", "low", "Content uploaded or served with the wrong type may be interpreted as executable content.", "Return the correct Content-Type and add `X-Content-Type-Options: nosniff`."),
    "headers.referrer": ("URLs may leak through the Referer header", "low", "Paths and query parameters can be disclosed when users follow external links.", "Add `Referrer-Policy: strict-origin-when-cross-origin` and never put secrets in URLs."),
    "headers.permissions": ("Browser capabilities are not explicitly restricted", "low", "Embedded or compromised content may request capabilities the application does not need.", "Add a Permissions-Policy that disables unused features, for example `camera=(), microphone=(), geolocation=()`."),
    "cookies.secure": ("Cookie can be sent over an unencrypted connection", "medium", "A session cookie without Secure may travel over HTTP and be captured.", "Set the `Secure` attribute on session and authentication cookies."),
    "cookies.httponly": ("JavaScript can read a cookie", "medium", "If an XSS issue exists, scripts can steal cookies that lack HttpOnly.", "Set `HttpOnly` on cookies that do not require JavaScript access."),
    "cookies.samesite": ("Cookie has no explicit cross-site policy", "medium", "The browser may include the cookie in cross-site requests, increasing CSRF exposure.", "Set `SameSite=Lax` or `Strict`; use `None; Secure` only when cross-site use is required."),
    "disclosure.server": ("Web server details are exposed", "low", "Version or product hints help attackers prioritize product-specific techniques.", "Remove version details from the Server header at the web server or reverse proxy."),
    "disclosure.powered": ("Application technology is exposed", "low", "Framework or runtime disclosure makes automated fingerprinting easier.", "Disable the X-Powered-By header (for PHP, set `expose_php = Off`)."),
    "tls.legacy": ("Legacy TLS protocol is in use", "high", "Older TLS versions contain design weaknesses and may violate current security baselines.", "Configure the server to allow TLS 1.2 and TLS 1.3 only."),
    "tls.certificate_expiry": ("TLS certificate expires soon", "medium", "An expired certificate causes browser warnings and can make the application unavailable to users and integrations.", "Automate certificate renewal and alert before the remaining lifetime reaches 30 days."),
    "headers.hsts_weak": ("HSTS policy is too short", "low", "A short max-age gives downgrade protection only briefly.", "After validating HTTPS coverage, increase HSTS max-age to at least 31536000 seconds."),
    "headers.csp_report_only": ("Content policy is report-only", "medium", "Violations may be reported, but the browser does not block unsafe content.", "Use reports to fix violations, then deploy the same policy in Content-Security-Policy."),
    "headers.csp_unsafe_inline": ("CSP permits inline script execution", "medium", "`unsafe-inline` weakens CSP protection against injected scripts.", "Replace inline scripts with external files or authorize them with nonces or hashes."),
    "headers.csp_unsafe_eval": ("CSP permits dynamic code evaluation", "medium", "`unsafe-eval` allows APIs such as eval(), increasing the impact of script injection.", "Remove eval-like APIs and delete `unsafe-eval` from script-src."),
    "headers.csp_wildcard": ("CSP trusts wildcard sources", "medium", "Broad source trust can allow content from an attacker-controlled host.", "Replace wildcard sources with the smallest explicit allowlist your application needs."),
    "headers.coop": ("Top-level window is not isolated", "low", "Without COOP, cross-origin windows may retain references that enable classes of side-channel or opener attacks.", "Add `Cross-Origin-Opener-Policy: same-origin` after testing integrations and sign-in popups."),
    "headers.corp": ("Resource loading policy is not explicit", "low", "Other origins may be able to embed resources unless application behavior prevents it.", "For non-public resources, set `Cross-Origin-Resource-Policy: same-origin` or `same-site`."),
    "cors.wildcard": ("CORS allows every origin", "medium", "Any website can read this response when the browser permits the request.", "Return Access-Control-Allow-Origin only for explicitly trusted origins and add `Vary: Origin`."),
    "cors.credentials_wildcard": ("CORS combines credentials with a wildcard origin", "high", "This is an unsafe and often broken cross-origin configuration that can expose authenticated data after proxy or framework changes.", "Never combine credentialed CORS with a wildcard. Validate the Origin against a strict allowlist."),
    "cache.sensitive": ("Potentially session-aware response lacks a no-store policy", "medium", "Shared browsers or intermediaries may retain a response associated with a user session.", "For sensitive authenticated pages, return `Cache-Control: no-store, private`."),
    "cookies.broad_domain": ("Cookie is shared with all subdomains", "low", "A compromised or less-trusted subdomain may influence a broadly scoped cookie.", "Prefer host-only cookies by omitting Domain; consider the `__Host-` prefix for session cookies."),
    "cookies.none_insecure": ("SameSite=None cookie is missing Secure", "medium", "Modern browsers may reject the cookie, and older clients could send it over HTTP.", "Whenever using `SameSite=None`, also set `Secure`."),
    "content.password_http": ("Password form is delivered without HTTPS", "critical", "Credentials and form markup can be intercepted or modified before submission.", "Serve the entire sign-in flow over HTTPS and redirect HTTP before rendering any form."),
    "content.mixed_content": ("HTTPS page references HTTP resources", "medium", "Unencrypted scripts, styles, images, or frames can be blocked or modified in transit.", "Change resource URLs to HTTPS or same-origin relative URLs and add CSP `upgrade-insecure-requests`."),
    "content.directory_listing": ("Directory listing appears to be enabled", "medium", "Visitors may enumerate backups, source files, logs, or other files that were not intended to be public.", "Disable automatic directory indexes and expose only explicitly routed resources."),
    "content.error_details": ("Detailed application error may be exposed", "medium", "Stack traces and runtime errors reveal code paths, queries, and implementation details useful for further attacks.", "Disable detailed errors outside development, log them server-side, and return a generic request identifier."),
    "content.source_map": ("Production response advertises a source map", "low", "Source maps can reveal original frontend source, internal names, comments, and endpoints.", "Do not publish production source maps publicly, or restrict access to your monitoring service."),
    "headers.content_type": ("HTML response has no explicit content type", "low", "Clients and proxies may interpret the response inconsistently.", "Return `Content-Type: text/html; charset=UTF-8` for HTML documents."),
}

def validate_target(parsed, allow_private):
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Use an absolute HTTP or HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not allowed")
    addresses = {item[4][0].split("%")[0] for item in socket.getaddrinfo(parsed.hostname, None)}
    if not allow_private and any(not ip_address(value).is_global for value in addresses):
        raise ValueError("Private, loopback, link-local, and reserved targets are blocked")

def make_finding(check_id, evidence, url):
    title, severity, impact, fix = CATALOG[check_id]
    return {"fingerprint": check_id, "title": title, "severity": severity,
            "evidence": evidence[:1000], "developer_impact": impact,
            "remediation": fix, "affected_url": url}

def scan(url, allow_private=False):
    parsed = urlparse(url)
    validate_target(parsed, allow_private)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    connection_type = HTTPSConnection if parsed.scheme == "https" else HTTPConnection
    options = {"timeout": 10}
    if parsed.scheme == "https":
        options["context"] = ssl.create_default_context()
    connection = connection_type(parsed.hostname, parsed.port, **options)
    started = time.monotonic()
    connection.request("GET", path, headers={"User-Agent": "SentinelScope/1.0 authorized-passive-scan", "Accept": "text/html,*/*;q=0.8"})
    response = connection.getresponse()
    tls_info = None
    if parsed.scheme == "https" and connection.sock:
        tls_info = (connection.sock.version(), connection.sock.getpeercert())
    body_bytes = response.read(262144)
    duration = round((time.monotonic() - started) * 1000)
    pairs = response.getheaders()
    headers = {key.lower(): value for key, value in pairs}
    cookies = [value for key, value in pairs if key.lower() == "set-cookie"]
    content_type = headers.get("content-type", "")
    looks_textual = "text" in content_type or "html" in content_type or body_bytes.lstrip().startswith((b"<", b"{"))
    body = body_bytes.decode("utf-8", errors="replace") if looks_textual else ""
    body_lower = body.lower()
    findings = []
    def check(check_id, failed, evidence):
        if failed:
            findings.append(make_finding(check_id, evidence, url))
    check("transport.https", parsed.scheme != "https", "The submitted URL uses HTTP.")
    check("headers.hsts", parsed.scheme == "https" and "strict-transport-security" not in headers, "Strict-Transport-Security is missing from the HTTPS response.")
    check("headers.csp", "content-security-policy" not in headers, "Content-Security-Policy is missing.")
    check("headers.frame", "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""), "Neither CSP frame-ancestors nor X-Frame-Options was returned.")
    check("headers.nosniff", headers.get("x-content-type-options", "").lower() != "nosniff", "X-Content-Type-Options is missing or is not `nosniff`.")
    check("headers.referrer", "referrer-policy" not in headers, "Referrer-Policy is missing.")
    check("headers.permissions", "permissions-policy" not in headers, "Permissions-Policy is missing.")
    check("cookies.secure", any("secure" not in item.lower() for item in cookies), "At least one Set-Cookie header lacks Secure.")
    check("cookies.httponly", any("httponly" not in item.lower() for item in cookies), "At least one Set-Cookie header lacks HttpOnly.")
    check("cookies.samesite", any("samesite=" not in item.lower() for item in cookies), "At least one Set-Cookie header lacks SameSite.")
    check("disclosure.server", bool(headers.get("server")), "Server header: " + headers.get("server", ""))
    check("disclosure.powered", bool(headers.get("x-powered-by")), "X-Powered-By header: " + headers.get("x-powered-by", ""))
    if tls_info:
        protocol, certificate = tls_info
        check("tls.legacy", protocol in ("TLSv1", "TLSv1.1"), "Negotiated protocol: " + str(protocol))
        if certificate.get("notAfter"):
            expires = ssl.cert_time_to_seconds(certificate["notAfter"])
            remaining = round((expires - time.time()) / 86400)
            check("tls.certificate_expiry", remaining < 30, f"Certificate lifetime remaining: {remaining} days.")
    hsts=headers.get("strict-transport-security","")
    match=re.search(r"max-age\s*=\s*(\d+)",hsts,re.I)
    check("headers.hsts_weak", bool(hsts) and (not match or int(match.group(1))<31536000), "HSTS value: " + hsts)
    csp=headers.get("content-security-policy","").lower()
    check("headers.csp_report_only", "content-security-policy-report-only" in headers and not csp, "Only Content-Security-Policy-Report-Only was returned.")
    check("headers.csp_unsafe_inline", "unsafe-inline" in csp, "The enforced CSP contains `unsafe-inline`.")
    check("headers.csp_unsafe_eval", "unsafe-eval" in csp, "The enforced CSP contains `unsafe-eval`.")
    check("headers.csp_wildcard", bool(re.search(r"(?:^|\s)\*(?:\s|;|$)",csp)), "The enforced CSP contains a wildcard source.")
    check("headers.coop", "cross-origin-opener-policy" not in headers, "Cross-Origin-Opener-Policy is missing.")
    check("headers.corp", "cross-origin-resource-policy" not in headers, "Cross-Origin-Resource-Policy is missing.")
    origin=headers.get("access-control-allow-origin","").strip()
    credentials=headers.get("access-control-allow-credentials","").lower()=="true"
    check("cors.wildcard", origin=="*", "Access-Control-Allow-Origin: *")
    check("cors.credentials_wildcard", origin=="*" and credentials, "Wildcard origin and Access-Control-Allow-Credentials: true were both returned.")
    session_aware=bool(cookies) or "authorization" in headers.get("vary","").lower()
    check("cache.sensitive", session_aware and "no-store" not in headers.get("cache-control","").lower(), "The response sets cookies but Cache-Control does not contain no-store.")
    check("cookies.broad_domain", any(re.search(r"(?:^|;)\s*domain=",c,re.I) for c in cookies), "At least one Set-Cookie header includes Domain.")
    check("cookies.none_insecure", any("samesite=none" in c.lower() and "secure" not in c.lower() for c in cookies), "A SameSite=None cookie does not include Secure.")
    check("content.password_http", parsed.scheme=="http" and bool(re.search(r'<input[^>]+type=["\']?password',body,re.I)), "The HTTP response contains a password input.")
    mixed=parsed.scheme=="https" and bool(re.search(r'(?:src|href|action)\s*=\s*["\']http://',body,re.I))
    check("content.mixed_content", mixed, "The HTTPS document contains an absolute HTTP resource or form URL.")
    check("content.directory_listing", bool(re.search(r'<title>\s*index of\s*/|<h1>\s*index of\s*/',body,re.I)), "The page title or heading matches a common automatic directory index.")
    error_patterns=r"traceback \(most recent call last\)|fatal error:|uncaught (?:exception|error)|stack trace:|sqlstate\[|at [\w.$]+\([\w.]+:\d+\)"
    check("content.error_details", bool(re.search(error_patterns,body,re.I)), "The response matches a common stack trace, database, or runtime error pattern.")
    check("content.source_map", "sourcemap" in headers or "x-sourcemap" in headers or "sourceMappingURL=" in body, "A source-map header or sourceMappingURL reference is present.")
    check("headers.content_type", bool(body) and not content_type, "A response that appears textual was received without Content-Type.")
    connection.close()
    return {"ok": True, "status_code": response.status, "duration_ms": duration,
            "checks_run": len(CATALOG), "findings": findings,
            "scanned_at": datetime.now(timezone.utc).isoformat()}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--allow-private", action="store_true", help="Lab use only")
    args = parser.parse_args()
    try:
        print(json.dumps(scan(args.url, args.allow_private), ensure_ascii=False))
        return 0
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False))
        return 1

if __name__ == "__main__":
    sys.exit(main())
