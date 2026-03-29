from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os

hostName = "localhost"
serverPort = 8080
DB_FILE = "totally_not_my_privateKeys.db"


# ──────────────────────────────────────────────
# Database helpers
# ──────────────────────────────────────────────

def get_db_connection():
    """Open (or create) the SQLite database and return a connection."""
    conn = sqlite3.connect(DB_FILE)
    return conn


def init_db():
    """
    Create the keys table if it does not already exist, then seed it with:
      • one key that expires in 1 hour  (valid)
      • one key that expired 1 hour ago (expired)
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create table – matches the required schema exactly
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    conn.commit()

    # Seed only if the table is empty so we don't keep adding keys on restart
    cursor.execute("SELECT COUNT(*) FROM keys")
    if cursor.fetchone()[0] == 0:
        _seed_keys(cursor)
        conn.commit()

    conn.close()


def _generate_pem() -> bytes:
    """Generate a fresh 2048-bit RSA private key and return it as PEM bytes."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem


def _seed_keys(cursor):
    """Insert one valid and one expired key into the DB."""
    now = datetime.datetime.now(datetime.timezone.utc)

    # Valid key – expires 1 hour from now
    valid_exp = int((now + datetime.timedelta(hours=1)).timestamp())
    valid_pem = _generate_pem()
    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",  # parameterised – no SQL injection
        (valid_pem, valid_exp),
    )

    # Expired key – expired 1 hour ago
    expired_exp = int((now - datetime.timedelta(hours=1)).timestamp())
    expired_pem = _generate_pem()
    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (expired_pem, expired_exp),
    )


# ──────────────────────────────────────────────
# Key retrieval helpers
# ──────────────────────────────────────────────

def get_valid_key():
    """
    Return (kid, pem_bytes) for an unexpired key.
    Returns (None, None) if no valid key is found.
    """
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    conn = get_db_connection()
    cursor = conn.cursor()
    # Parameterised query prevents SQL injection
    cursor.execute(
        "SELECT kid, key FROM keys WHERE exp > ? LIMIT 1",
        (now,),
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0], row[1]
    return None, None


def get_expired_key():
    """
    Return (kid, pem_bytes) for an expired key.
    Returns (None, None) if none exists.
    """
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1",
        (now,),
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0], row[1]
    return None, None


def get_all_valid_keys():
    """
    Return a list of (kid, pem_bytes) for every unexpired key.
    Used to build the JWKS response.
    """
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT kid, key FROM keys WHERE exp > ?",
        (now,),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows  # list of (kid, pem_bytes)


# ──────────────────────────────────────────────
# Encoding helper
# ──────────────────────────────────────────────

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string (no padding)."""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def pem_to_public_numbers(pem_bytes):
    """Load a PEM private key and return its public numbers (n, e)."""
    private_key = serialization.load_pem_private_key(pem_bytes, password=None)
    return private_key.public_key().public_numbers()


# ──────────────────────────────────────────────
# HTTP request handler
# ──────────────────────────────────────────────

class MyServer(BaseHTTPRequestHandler):

    # ── Unsupported methods ──────────────────

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    # ── POST /auth ───────────────────────────

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            # Decide which key to use based on the "expired" query parameter
            if 'expired' in params:
                kid, pem_bytes = get_expired_key()
                token_exp = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
            else:
                kid, pem_bytes = get_valid_key()
                token_exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)

            if pem_bytes is None:
                # No suitable key found in the DB
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"No suitable key available")
                return

            # Sign the JWT with the key read from the DB
            headers = {"kid": str(kid)}
            token_payload = {
                "user": "username",
                "exp": token_exp,
            }
            encoded_jwt = jwt.encode(
                token_payload,
                pem_bytes,
                algorithm="RS256",
                headers=headers,
            )

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    # ── GET /.well-known/jwks.json ───────────

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            rows = get_all_valid_keys()

            jwks_keys = []
            for kid, pem_bytes in rows:
                numbers = pem_to_public_numbers(pem_bytes)
                jwks_keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e),
                })

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps({"keys": jwks_keys}), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def log_message(self, format, *args):
        """Suppress default access log output (keeps terminal clean)."""
        pass


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    init_db()  # Create DB / table and seed keys if needed
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started at http://{hostName}:{serverPort}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
    print("Server stopped.")