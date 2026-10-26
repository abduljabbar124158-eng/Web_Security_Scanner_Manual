from http.server import BaseHTTPRequestHandler, HTTPServer

class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header(
            "Set-Cookie", "demo_session=sample123; Path=/"
        )
        self.end_headers()
        self.wfile.write(b"""
        <!doctype html>
        <html><head><title>Security Demo</title></head>
        <body><h1>Local Security Test Page</h1>
        <p>Educational test website.</p></body></html>
        """)

    def log_message(self, fmt, *args):
        print("Demo:", fmt % args)

if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8000), DemoHandler)
    print("Demo server: http://127.0.0.1:8000")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        print("\nServer stopped.")
