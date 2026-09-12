from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = b'{"status":"ok"}'
        elif self.path == "/price":
            body = json.dumps({
                "sku": "SKU-10001",
                "currency": "EUR",
                "price": 24.90
            }).encode()
        else:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    print("pricing api starting", flush=True)
    print("pricing api ready", flush=True)
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
