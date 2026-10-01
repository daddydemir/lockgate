import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from lockgate_client import LockGateClient, LockGateError

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        self.server.instance_key = self.headers.get("Idempotency-Key")
        self.send_response(202); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"status":"waiting_approval","request_id":"request_1","retry_after":0}).encode())
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"status":"approved","secrets":{"apps/test/production":{"DB_USER":"postgres"}}}).encode())

class RedirectTarget(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        self.server.leaked = self.headers.get("Authorization") is not None
        self.send_response(200); self.end_headers(); self.wfile.write(b"{}")

class RedirectSource(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        self.send_response(307)
        self.send_header("Location", f"http://127.0.0.1:{self.server.target_port}/leak")
        self.end_headers()

class ClientTest(unittest.TestCase):
    def test_waits_and_returns_config(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            config = LockGateClient(f"http://127.0.0.1:{server.server_port}", "lg_app_test").get_config(10)
            self.assertEqual(config["DB_USER"], "postgres")
            self.assertTrue(server.instance_key)
        finally: server.shutdown(); server.server_close()

    def test_does_not_forward_token_through_redirects(self):
        target = ThreadingHTTPServer(("127.0.0.1", 0), RedirectTarget); target.leaked = False
        source = ThreadingHTTPServer(("127.0.0.1", 0), RedirectSource); source.target_port = target.server_port
        threading.Thread(target=target.serve_forever, daemon=True).start()
        threading.Thread(target=source.serve_forever, daemon=True).start()
        try:
            with self.assertRaises(LockGateError):
                LockGateClient(f"http://127.0.0.1:{source.server_port}", "lg_app_secret").get_config(2)
            self.assertFalse(target.leaked)
        finally:
            source.shutdown(); target.shutdown(); source.server_close(); target.server_close()

if __name__ == "__main__": unittest.main()
