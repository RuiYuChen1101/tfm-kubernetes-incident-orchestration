from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading

catalog = []

def load_catalog():
    for i in range(45000):
        catalog.append({
            "sku": f"SKU-{i:08d}",
            "name": f"Catalog product {i}",
            "category": f"category-{i % 50}",
            "price": round(10.0 + (i % 5000) / 100.0, 2),
            "metadata": (f"product-metadata-{i:08d}-" + "x" * 1800)
        })

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/catalog":
            payload = json.dumps({
                "service": "catalog-service",
                "products": len(catalog)
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    print("catalog service starting", flush=True)
    load_catalog()
    print(f"catalog cache ready: {len(catalog)} products", flush=True)
    print("catalog service ready", flush=True)
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
