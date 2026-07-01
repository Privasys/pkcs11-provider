#!/usr/bin/env python3
"""A stand-in for `privasys vault serve` used by the ABI/consumer tests: it
serves the same localhost REST surface (GET /keys, POST /keys/{n}/sign|unwrapKey,
DELETE /keys/{n}) with canned values, so the module can be exercised end-to-end
without a live vault. Listens on 127.0.0.1:8210."""
import base64
import http.server
import json


class H(http.server.BaseHTTPRequestHandler):
    def _j(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        # Matches `privasys vault serve` GET /keys: {"value":[{name, keyType}]}.
        if self.path == "/keys":
            self._j(200, {"value": [
                {"name": "tls-key", "keyType": "P256SigningKey"},
                {"name": "data-key", "keyType": "Aes256GcmKey"},
            ]})
        elif self.path == "/keys/tls-key":
            # Matches GET /keys/{name}: {"key": <JWK>, "kid": ...}. A fixed
            # valid P-256 point (the NIST P-256 generator), backing CKA_EC_POINT.
            gx = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
            gy = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
            b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
            self._j(200, {"key": {"kty": "EC", "crv": "P-256", "x": b64(gx), "y": b64(gy)},
                          "kid": "tls-key"})
        else:
            self._j(404, {"error": "not found"})

    def do_POST(self):
        if self.path.endswith("/sign"):
            sig = base64.urlsafe_b64encode(bytes(range(64))).rstrip(b"=").decode()
            self._j(200, {"kid": "tls-key", "alg": "ES256", "value": sig})
        elif self.path.endswith("/unwrapKey"):
            pt = base64.urlsafe_b64encode(b"decrypted-plaintext").rstrip(b"=").decode()
            self._j(200, {"kid": "data-key", "value": pt})
        else:
            self._j(404, {"error": "not found"})

    def do_DELETE(self):
        self._j(200, {"kid": "x", "name": self.path.rsplit("/", 1)[-1]})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.HTTPServer(("127.0.0.1", 8210), H).serve_forever()
