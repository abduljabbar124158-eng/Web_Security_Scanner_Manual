"""Simple standard-library web dashboard for the Web Security Scanner."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import html
import json
import urllib.error
import scanner

HOST = "127.0.0.1"
PORT = 8080
LATEST_RESULT = None

CSS = """
:root{--bg:#f3f6fb;--ink:#172033;--muted:#667085;--line:#e3e8f0;--primary:#3157d5;--navy:#172554}
*{box-sizing:border-box}body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--ink)}
.topbar{background:#fff;border-bottom:1px solid var(--line);padding:17px 26px;display:flex;align-items:center;justify-content:space-between;gap:12px}
.brand{display:flex;align-items:center;gap:12px;font-weight:800;font-size:18px}.logo{width:38px;height:38px;border-radius:12px;background:linear-gradient(135deg,#3157d5,#6d8cff);display:grid;place-items:center;color:#fff;font-size:19px}
.pill{background:#ecfdf3;color:#027a48;border-radius:999px;padding:7px 11px;font-size:12px;font-weight:800}
main{max-width:1180px;margin:34px auto;padding:0 22px}.hero{background:linear-gradient(120deg,#172554,#3157d5);color:#fff;padding:32px;border-radius:22px;box-shadow:0 14px 30px #233a801c}
.eyebrow{font-size:12px;letter-spacing:.13em;text-transform:uppercase;color:#c7d7ff;font-weight:800}h1{font-size:clamp(27px,4vw,38px);margin:9px 0}.hero p{color:#e0e7ff;margin:0;max-width:700px;line-height:1.6}
.grid{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(260px,.8fr);gap:18px;margin-top:20px}.panel{background:#fff;border:1px solid var(--line);border-radius:17px;padding:24px;box-shadow:0 5px 16px #18284a08}
h2{font-size:19px;margin:0 0 7px}.muted{color:var(--muted);font-size:14px;line-height:1.6}.field{margin-top:22px}label{display:block;font-size:13px;font-weight:800;margin-bottom:9px}
input[type=url]{width:100%;padding:14px 15px;border:1px solid #cbd5e1;border-radius:11px;font:inherit;outline:none}input[type=url]:focus{border-color:var(--primary);box-shadow:0 0 0 3px #3157d51c}
button,.button{border:0;background:var(--primary);color:#fff;padding:13px 18px;border-radius:11px;font-weight:800;font-size:14px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;margin-top:14px}
button:hover,.button:hover{background:#2446ba}.secondary{background:#eef2ff;color:#3048a8}.secondary:hover{background:#e0e7ff}
.feature{display:flex;gap:12px;margin-top:19px}.icon{width:34px;height:34px;flex:0 0 34px;background:#eef2ff;color:#3157d5;border-radius:10px;display:grid;place-items:center;font-weight:900}.feature strong{display:block;font-size:14px}.feature span{display:block;color:var(--muted);font-size:13px;margin-top:3px;line-height:1.5}
.alert{padding:14px 16px;border-radius:12px;margin:18px 0;font-size:14px}.error{background:#fef3f2;color:#b42318;border:1px solid #fecdca}.success{background:#ecfdf3;color:#027a48;border:1px solid #abefc6}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin:18px 0}.stat{background:white;border:1px solid var(--line);border-radius:14px;padding:17px;min-width:0}.stat .k{color:var(--muted);font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.06em}.stat .v{font-size:25px;font-weight:850;margin-top:6px;overflow-wrap:anywhere}.status{display:inline-block;border-radius:999px;padding:5px 10px;font-size:12px;font-weight:800}.status.good{background:#dcfce7;color:#166534}.status.warn{background:#fef3c7;color:#92400e}.status.bad{background:#fee2e2;color:#991b1b}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px;margin-top:16px}table{border-collapse:collapse;width:100%;min-width:800px}th{background:#f8fafc;color:#475569;font-size:11px;letter-spacing:.07em;text-transform:uppercase}th,td{padding:14px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);line-height:1.5}td{font-size:13px;overflow-wrap:anywhere}tr:last-child td{border-bottom:0}.sev{display:inline-block;padding:4px 8px;border-radius:7px;font-weight:850;font-size:11px}.high{background:#fee2e2;color:#991b1b}.medium{background:#ffedd5;color:#9a3412}.low{background:#e2e8f0;color:#334155}.info{background:#dbeafe;color:#1d4ed8}
.footer{padding:24px 0 10px;color:var(--muted);font-size:12px;text-align:center}.url{overflow-wrap:anywhere;font-weight:700}.sectionhead{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
@media(max-width:800px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}main{margin:18px auto;padding:0 13px}.topbar{padding:13px 15px}.hero{padding:24px}.panel{padding:18px}}
@media(max-width:420px){.stats{grid-template-columns:1fr 1fr}.brand{font-size:15px}}
"""

def page(title, body):
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>""" + html.escape(title) + """ · Web Security Scanner</title>
<style>""" + CSS + """</style></head><body>
<header class="topbar"><div class="brand"><div class="logo">✓</div><span>Web Security Scanner</span></div><span class="pill">● Scanner ready</span></header>
<main>""" + body + """<div class="footer">Educational security checks · Scan only websites you own or have permission to test.</div></main></body></html>"""

def home(message="", url=""):
    alert = ('<div class="alert error">' + html.escape(message) + '</div>') if message else ""
    body = """
<section class="hero"><div class="eyebrow">Website security overview</div><h1>Know your website’s security posture.</h1>
<p>Run a quick review of important HTTP security headers, cookie attributes, HTTPS transport, and basic CORS behavior from one clean dashboard.</p></section>
""" + alert + """
<div class="grid"><section class="panel"><h2>Start a security scan</h2><p class="muted">Enter the full website address, including https:// or http://. Use this tool only on websites you own or are authorized to assess.</p>
<form method="post" action="/scan"><div class="field"><label for="url">Website URL</label><input id="url" name="url" type="url" placeholder="https://example.com" value=""" + json.dumps(url) + """ required></div>
<button type="submit">⌕ &nbsp; Scan website</button></form></section>
<section class="panel"><h2>What gets checked?</h2><p class="muted">A lightweight first-pass review. It is not a full vulnerability assessment.</p>
<div class="feature"><div class="icon">↗</div><div><strong>Transport & response</strong><span>HTTPS use, HTTP status, and important security headers.</span></div></div>
<div class="feature"><div class="icon">◈</div><div><strong>Cookie settings</strong><span>Checks for Secure, HttpOnly, and SameSite attributes.</span></div></div>
<div class="feature"><div class="icon">⇄</div><div><strong>CORS behavior</strong><span>Looks for basic reflection of a test origin in response headers.</span></div></div></section></div>"""
    return page("Dashboard", body)

def result_page(result):
    status = int(result["status"])
    if 200 <= status < 300:
        status_text, status_class = "Reachable · Success", "good"
    elif 300 <= status < 400:
        status_text, status_class = "Reachable · Redirect", "warn"
    else:
        status_text, status_class = "HTTP response · Review", "bad"
    findings = result["findings"]
    counts = {x: sum(1 for f in findings if f["severity"].lower() == x) for x in ("high","medium","low","info")}
    rows = []
    for item in findings:
        sev = item["severity"].lower()
        css = sev if sev in ("high","medium","low","info") else "info"
        rows.append('<tr><td><span class="sev ' + css + '">' + html.escape(item["severity"]) + '</span></td><td><strong>' + html.escape(item["title"]) + '</strong></td><td>' + html.escape(item["evidence"]) + '</td><td>' + html.escape(item["recommendation"]) + '</td></tr>')
    if not rows:
        rows.append('<tr><td colspan="4">No findings were returned by the current checks.</td></tr>')
    body = """
<section class="hero"><div class="eyebrow">Scan complete</div><h1>Security scan results</h1><p>Review the response status and findings below. Missing headers are indicators to investigate, not proof of an exploitable vulnerability.</p></section>
<div class="stats">
<div class="stat"><div class="k">Website status</div><div class="v" style="font-size:16px;margin-top:12px"><span class="status """ + status_class + """">""" + status_text + """</span></div></div>
<div class="stat"><div class="k">HTTP code</div><div class="v">""" + str(status) + """</div></div>
<div class="stat"><div class="k">Total findings</div><div class="v">""" + str(len(findings)) + """</div></div>
<div class="stat"><div class="k">High severity</div><div class="v">""" + str(counts["high"]) + """</div></div>
</div>
<section class="panel"><div class="sectionhead"><div><h2>Website details</h2><p class="muted">Requested and final response addresses</p></div><a class="button secondary" href="/">← New scan</a></div>
<div class="field"><div class="label">Target URL</div><div class="url">""" + html.escape(result["url"]) + """</div></div>
<div class="field"><div class="label">Final URL</div><div class="url">""" + html.escape(result["final_url"]) + """</div></div>
<div class="field"><div class="label">Severity breakdown</div><p><span class="sev high">High """ + str(counts["high"]) + """</span> &nbsp; <span class="sev medium">Medium """ + str(counts["medium"]) + """</span> &nbsp; <span class="sev low">Low """ + str(counts["low"]) + """</span> &nbsp; <span class="sev info">Info """ + str(counts["info"]) + """</span></p></div>
<a class="button" href="/report">⬇ &nbsp; Download HTML report</a>
</section>
<section class="panel" style="margin-top:18px"><div class="sectionhead"><div><h2>Findings table</h2><p class="muted">Each result includes evidence and a recommended next step.</p></div><span class="pill">""" + str(len(findings)) + """ findings</span></div>
<div class="tablewrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>""" + "".join(rows) + """</tbody></table></div>
<p class="muted" style="margin-top:16px">Note: This educational scanner checks a limited set of signals. Validate findings manually and use a dedicated assessment for comprehensive coverage.</p></section>"""
    return page("Scan results", body)

class Handler(BaseHTTPRequestHandler):
    def send_html(self, content, status=200, headers=None):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        global LATEST_RESULT
        path = urlparse(self.path).path
        if path == "/":
            self.send_html(home())
        elif path == "/report":
            if not LATEST_RESULT:
                self.send_html(home("Run a scan first to generate a report."), 400)
                return
            report = scanner.build_report_html(LATEST_RESULT)
            self.send_html(report, headers={"Content-Disposition": 'attachment; filename="security_report.html"'})
        elif path == "/health":
            self.send_html(page("Status", '<section class="panel"><h2>Dashboard is running</h2><p class="muted">The local scanner web interface is ready.</p></section>'))
        else:
            self.send_html(home("Page not found."), 404)

    def do_POST(self):
        global LATEST_RESULT
        if urlparse(self.path).path != "/scan":
            self.send_html(home("Page not found."), 404)
            return
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 10000)
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            url = form.get("url", [""])[0].strip()
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                self.send_html(home("Enter a valid website URL beginning with http:// or https://.", url), 400)
                return
            # Keep dashboard scans limited to ordinary public hostnames or loopback demo.
            host = (parsed.hostname or "").lower()
            if host in ("localhost",) or host.endswith(".local"):
                self.send_html(home("Local hostnames are blocked in the dashboard. Use the included local demo instructions if you are testing locally.", url), 400)
                return
            LATEST_RESULT = scanner.scan(url)
            self.send_html(result_page(LATEST_RESULT))
        except (ValueError, urllib.error.URLError, TimeoutError, OSError, Exception) as exc:
            self.send_html(home("Scan failed: " + str(exc), locals().get("url", "")), 400)

    def log_message(self, fmt, *args):
        print("[Web UI] " + fmt % args)

if __name__ == "__main__":
    print(f"Web Security Scanner dashboard: http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
