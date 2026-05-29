# IMPORTANT: This script was created used ChatGPT. Use at your own risk.

# warning_server.py
from http.server import HTTPServer, SimpleHTTPRequestHandler

HTML = b"""
<html>
<head><title>Blocked</title></head>
<body style="font-family:sans-serif;text-align:center;padding-top:50px">
<h1>Website Blocked</h1>
<p>This website is not allowed.</p>
</body>
</html>
"""

class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(HTML)))
        self.end_headers()
        self.wfile.write(HTML)

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
