import html
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

TIMEOUT = 8
TEST_ORIGIN = "https://untrusted-origin.invalid"

HEADERS = {
    "content-security-policy": (
        "Medium", "Consider a suitable Content-Security-Policy."
    ),
    "x-content-type-options": (
        "Medium", "Consider setting X-Content-Type-Options: nosniff."
    ),
    "referrer-policy": (
        "Low", "Choose an appropriate Referrer-Policy."
    ),
    "permissions-policy": (
        "Low", "Restrict browser features not needed by your site."
    ),
}

def request(url, origin=None):
    headers = {"User-Agent": "WebSecurityScanner/1.0"}
    if origin:
        headers["Origin"] = origin

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            return response.status, response.headers, response.geturl()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.geturl()

def add(findings, severity, title, evidence, recommendation):
    findings.append({
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    })

def scan(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")

    # Prevent redirects from taking the scan to another host.
    class SafeRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            old = urllib.parse.urlparse(req.full_url)
            new = urllib.parse.urlparse(newurl)
            if (new.scheme not in ("http", "https")
                    or new.hostname != old.hostname
                    or new.port != old.port):
                raise urllib.error.URLError(
                    "Redirect to a different host blocked"
                )
            return super().redirect_request(
                req, fp, code, msg, headers, newurl
            )

    opener = urllib.request.build_opener(SafeRedirect)

    def safe_request(target, origin=None):
        req_headers = {
            "User-Agent": "WebSecurityScanner/1.0"
        }
        if origin:
            req_headers["Origin"] = origin
        req = urllib.request.Request(target, headers=req_headers)
        try:
            with opener.open(req, timeout=TIMEOUT) as response:
                return response.status, response.headers, response.geturl()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.geturl()

    status, headers, final_url = safe_request(url)
    findings = []
    https = urllib.parse.urlparse(final_url).scheme == "https"

    for name, (severity, recommendation) in HEADERS.items():
        if name not in headers:
            add(findings, severity, "Missing " + name,
                "Header not present in the response.", recommendation)

    if https and "strict-transport-security" not in headers:
        add(findings, "Medium", "Missing HSTS",
            "HTTPS response did not include Strict-Transport-Security.",
            "Consider HSTS after confirming HTTPS works across the site.")
    elif not https:
        add(findings, "Info", "HTTP rather than HTTPS",
            "The tested URL does not use encrypted HTTPS transport.",
            "Use HTTPS for production websites.")

    csp = headers.get("content-security-policy", "").lower()
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        add(findings, "Medium", "Framing protection not detected",
            "X-Frame-Options and CSP frame-ancestors were not detected.",
            "Consider an appropriate frame-ancestors or X-Frame-Options policy.")

    for cookie in headers.get_all("Set-Cookie", []):
        lower = cookie.lower()
        for attr, title, recommendation in [
            ("secure", "Cookie missing Secure",
             "Use Secure for cookies that should only travel over HTTPS."),
            ("httponly", "Cookie missing HttpOnly",
             "Use HttpOnly for session cookies unless scripts need access."),
            ("samesite", "Cookie missing SameSite",
             "Choose a SameSite policy suitable for this cookie."),
        ]:
            # Match the attribute name, not a substring in its value.
            attributes = [part.strip().split("=", 1)[0].lower()
                          for part in lower.split(";")]
            if attr not in attributes and (attr != "secure" or https):
                add(findings, "Low", title,
                    "A Set-Cookie response may omit " + attr + ".",
                    recommendation)

    try:
        _, cors, _ = safe_request(url, TEST_ORIGIN)
        allow = cors.get("Access-Control-Allow-Origin", "").strip()
        credentials = cors.get(
            "Access-Control-Allow-Credentials", ""
        ).strip().lower() == "true"

        if allow == "*" and credentials:
            add(findings, "High", "Suspicious CORS headers",
                "Wildcard origin and credentials=true observed.",
                "Review CORS policy. Browsers reject this combination for credentialed access.")
        elif allow == TEST_ORIGIN and credentials:
            add(findings, "High", "Untrusted origin reflected with credentials",
                "Test origin was reflected and credentials were allowed.",
                "Allow only explicitly trusted origins.")
        elif allow == TEST_ORIGIN:
            add(findings, "Medium", "Test origin reflected",
                "The response reflected the untrusted test origin.",
                "Check that origins are validated against an allowlist.")
        else:
            add(findings, "Info", "No tested CORS reflection detected",
                "The test origin was not reflected in the response header.",
                "Compare the result with the application's intended CORS policy.")
    except Exception as exc:
        add(findings, "Info", "CORS check incomplete", str(exc),
            "Check connectivity and review CORS manually.")

    return {
        "url": url,
        "final_url": final_url,
        "status": status,
        "findings": findings,
    }

def build_report_html(result):
    rows = []
    for item in result["findings"]:
        severity = str(item["severity"])
        cells = [severity, item["title"], item["evidence"], item["recommendation"]]
        row_class = "sev-" + severity.lower()
        rows.append('<tr class="' + html.escape(row_class) + '">' + "".join(
            "<td>" + html.escape(str(cell)) + "</td>" for cell in cells
        ) + "</tr>")

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    status = int(result["status"])
    status_label = "Success" if 200 <= status < 300 else (
        "Redirect / Other" if 300 <= status < 400 else "HTTP Error"
    )
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web Security Scan Report</title>
<style>
:root{color-scheme:light;--ink:#172033;--muted:#64748b;--line:#e2e8f0;--blue:#3157d5}
*{box-sizing:border-box}body{font-family:Inter,Segoe UI,Arial,sans-serif;margin:0;background:#f4f7fb;color:var(--ink);line-height:1.55}
main{max-width:1180px;margin:34px auto;padding:0 22px}.hero{background:linear-gradient(120deg,#172554,#3157d5);color:white;padding:30px;border-radius:20px}
h1{margin:0 0 6px;font-size:30px}.hero p{margin:0;color:#dbeafe}.summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin:18px 0}
.card{background:white;border:1px solid var(--line);border-radius:14px;padding:18px;min-width:0}.label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}.value{font-size:18px;font-weight:700;overflow-wrap:anywhere;margin-top:6px}
.panel{background:white;border:1px solid var(--line);border-radius:14px;padding:20px;margin-top:16px}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;min-width:800px}th{background:#f1f5f9;color:#475569;font-size:12px;text-transform:uppercase;letter-spacing:.05em}th,td{border-bottom:1px solid var(--line);padding:13px 14px;text-align:left;vertical-align:top}td{overflow-wrap:anywhere}tr:last-child td{border-bottom:0}
.sev-high td:first-child{color:#b91c1c;font-weight:800}.sev-medium td:first-child{color:#b45309;font-weight:800}.sev-low td:first-child{color:#475569;font-weight:800}.sev-info td:first-child{color:#2563eb;font-weight:800}
.note{color:var(--muted);font-size:13px;margin-top:18px}@media(max-width:650px){main{margin:16px auto;padding:0 12px}.summary{grid-template-columns:1fr}.hero{padding:22px}h1{font-size:24px}}
</style></head><body><main>
<section class="hero"><h1>Web Security Scan Report</h1><p>Preliminary checks of response headers, cookies, transport security, and CORS.</p></section>
<section class="summary">
<div class="card"><div class="label">Generated</div><div class="value">""" + html.escape(generated) + """</div></div>
<div class="card"><div class="label">HTTP status</div><div class="value">""" + str(status) + " · " + html.escape(status_label) + """</div></div>
<div class="card"><div class="label">Total findings</div><div class="value">""" + str(len(result["findings"])) + """</div></div>
</section>
<section class="panel"><div class="label">Target URL</div><div class="value">""" + html.escape(result["url"]) + """</div><div class="label" style="margin-top:16px">Final URL</div><div class="value">""" + html.escape(result["final_url"]) + """</div></section>
<section class="panel"><h2>Findings</h2><div class="table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>""" + "".join(rows) + """</tbody></table></div>
<p class="note">Educational preliminary checks only. Findings may be false positives or false negatives. Validate manually; this report is not proof that a website is secure.</p></section>
</main></body></html>"""

def write_report(result, filename="security_report.html"):
    page = build_report_html(result)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(page)
    print("Report saved:", filename)
    print("HTTP status:", result["status"])
    print("Findings:", len(result["findings"]))
    for item in result["findings"]:
        print("[{}] {}".format(item["severity"], item["title"]))

def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner.py http://127.0.0.1:8000")
        raise SystemExit(2)
    try:
        write_report(scan(sys.argv[1]))
    except (ValueError, urllib.error.URLError, TimeoutError, OSError) as exc:
        print("Scan failed:", exc)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
