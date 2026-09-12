import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

cache = []


def warm_catalog():
    time.sleep(15)

    while len(cache) < 10:
        block = bytearray(12 * 1024 * 1024)

        for offset in range(0, len(block), 4096):
            block[offset] = 1

        cache.append(block)
        time.sleep(10)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            body = b"ok\n"
            self.send_response(200)
        else:
            body = b"inventory service\n"
            self.send_response(200)

        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


threading.Thread(target=warm_catalog, daemon=True).start()

print("inventory service ready", flush=True)

server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
server.serve_forever()
