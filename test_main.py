"""
test_main.py – Test suite for the Project 2 JWKS server.

Run with:
    pip install pytest pytest-cov cryptography pyjwt
    pytest --cov=main --cov-report=term-missing test_main.py

Coverage target: > 80 %
"""

import datetime
import importlib
import json
import os
import sqlite3
import threading
import time
import unittest
from http.client import HTTPConnection
from unittest.mock import patch

# ── Use a throw-away DB so tests don't pollute the real one
TEST_DB = "test_keys.db"

import main  # import after setting the override below


def setUpModule():
    """Point main.DB_FILE at the test database before any test runs."""
    main.DB_FILE = TEST_DB


def tearDownModule():
    """Remove the test DB after all tests finish."""
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)



# Helper


def _fresh_db():
    """Delete and recreate the test DB."""
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    main.init_db()



# Unit tests – database layer


class TestInitDb(unittest.TestCase):

    def setUp(self):
        _fresh_db()

    def test_table_exists(self):
        """keys table should exist after init_db()."""
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'")
        self.assertIsNotNone(cursor.fetchone())
        conn.close()

    def test_seeds_two_keys(self):
        """init_db() seeds exactly two keys on first run."""
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        conn.close()
        self.assertEqual(count, 2)

    def test_idempotent_seeding(self):
        """Calling init_db() a second time should NOT add more keys."""
        main.init_db()
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        conn.close()
        self.assertEqual(count, 2)

    def test_has_valid_key(self):
        """At least one unexpired key must be present after seeding."""
        kid, pem = main.get_valid_key()
        self.assertIsNotNone(kid)
        self.assertIsNotNone(pem)

    def test_has_expired_key(self):
        """At least one expired key must be present after seeding."""
        kid, pem = main.get_expired_key()
        self.assertIsNotNone(kid)
        self.assertIsNotNone(pem)


class TestGetAllValidKeys(unittest.TestCase):

    def setUp(self):
        _fresh_db()

    def test_returns_only_valid_keys(self):
        """get_all_valid_keys() must not return expired keys."""
        rows = main.get_all_valid_keys()
        self.assertGreater(len(rows), 0)
        now = int(datetime.datetime.utcnow().timestamp())
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()
        for kid, _ in rows:
            cursor.execute("SELECT exp FROM keys WHERE kid = ?", (kid,))
            exp = cursor.fetchone()[0]
            self.assertGreater(exp, now)
        conn.close()


class TestPemToPublicNumbers(unittest.TestCase):

    def setUp(self):
        _fresh_db()

    def test_returns_public_numbers(self):
        """pem_to_public_numbers should return an object with n and e."""
        _, pem = main.get_valid_key()
        numbers = main.pem_to_public_numbers(pem)
        self.assertIsNotNone(numbers.n)
        self.assertIsNotNone(numbers.e)
        self.assertGreater(numbers.n, 0)
        self.assertEqual(numbers.e, 65537)


class TestIntToBase64(unittest.TestCase):

    def test_known_value(self):
        """int_to_base64(1) == 'AQ'."""
        self.assertEqual(main.int_to_base64(1), "AQ")

    def test_output_is_string(self):
        result = main.int_to_base64(65537)
        self.assertIsInstance(result, str)

    def test_no_padding(self):
        """Base64URL output must not contain '='."""
        result = main.int_to_base64(65537)
        self.assertNotIn("=", result)



# Integration tests – HTTP endpoints


class TestHTTPEndpoints(unittest.TestCase):
    """Spin up the real HTTPServer in a background thread and hit it."""

    @classmethod
    def setUpClass(cls):
        _fresh_db()
        from http.server import HTTPServer
        cls.server = HTTPServer(("localhost", 8081), main.MyServer)
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        time.sleep(0.2)   # give the server a moment to start
        cls.conn = HTTPConnection("localhost", 8081)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=2)

    def _get(self, path):
        self.conn.request("GET", path)
        return self.conn.getresponse()

    def _post(self, path):
        self.conn.request("POST", path)
        return self.conn.getresponse()

    # ── GET /.well-known/jwks.json 

    def test_jwks_returns_200(self):
        resp = self._get("/.well-known/jwks.json")
        self.assertEqual(resp.status, 200)
        resp.read()

    def test_jwks_content_type(self):
        resp = self._get("/.well-known/jwks.json")
        self.assertIn("application/json", resp.getheader("Content-type"))
        resp.read()

    def test_jwks_has_keys_field(self):
        resp = self._get("/.well-known/jwks.json")
        body = json.loads(resp.read())
        self.assertIn("keys", body)

    def test_jwks_keys_are_valid(self):
        resp = self._get("/.well-known/jwks.json")
        body = json.loads(resp.read())
        for key in body["keys"]:
            self.assertIn("kty", key)
            self.assertIn("kid", key)
            self.assertIn("n", key)
            self.assertIn("e", key)
            self.assertEqual(key["kty"], "RSA")

    def test_jwks_no_expired_keys(self):
        """JWKS must not expose expired keys."""
        resp = self._get("/.well-known/jwks.json")
        body = json.loads(resp.read())
        # Get the kid of the expired key from the DB
        _, _ = main.get_expired_key()
        expired_kid, _ = main.get_expired_key()
        kids_in_response = [k["kid"] for k in body["keys"]]
        self.assertNotIn(str(expired_kid), kids_in_response)

    def test_get_unknown_path_returns_405(self):
        resp = self._get("/unknown")
        self.assertEqual(resp.status, 405)
        resp.read()

    # ── POST /auth 

    def test_auth_returns_200(self):
        resp = self._post("/auth")
        self.assertEqual(resp.status, 200)
        resp.read()

    def test_auth_returns_jwt(self):
        """Response body should be a decodable JWT."""
        import jwt as pyjwt
        resp = self._post("/auth")
        token = resp.read().decode()
        # Decode header without verifying signature
        header = pyjwt.get_unverified_header(token)
        self.assertEqual(header["alg"], "RS256")
        self.assertIn("kid", header)

    def test_auth_valid_jwt_not_expired(self):
        """A normal /auth token should have a future expiry."""
        import jwt as pyjwt
        resp = self._post("/auth")
        token = resp.read().decode()
        _, pem = main.get_valid_key()
        pub_key = main.serialization.load_pem_private_key(pem, password=None).public_key()
        decoded = pyjwt.decode(token, pub_key, algorithms=["RS256"])
        self.assertGreater(decoded["exp"], int(datetime.datetime.utcnow().timestamp()))

    def test_auth_expired_query_param(self):
        """POST /auth?expired should return an already-expired JWT."""
        import jwt as pyjwt
        resp = self._post("/auth?expired=true")
        token = resp.read().decode()
        header = pyjwt.get_unverified_header(token)
        # Decode without verifying expiry
        _, pem = main.get_expired_key()
        pub_key = main.serialization.load_pem_private_key(pem, password=None).public_key()
        decoded = pyjwt.decode(
            token, pub_key, algorithms=["RS256"],
            options={"verify_exp": False}
        )
        self.assertLess(decoded["exp"], int(datetime.datetime.utcnow().timestamp()))

    def test_post_unknown_path_returns_405(self):
        resp = self._post("/unknown")
        self.assertEqual(resp.status, 405)
        resp.read()

    # ── Unsupported methods 

    def _send(self, method, path="/"):
        self.conn.request(method, path)
        return self.conn.getresponse()

    def test_put_returns_405(self):
        resp = self._send("PUT")
        self.assertEqual(resp.status, 405)
        resp.read()

    def test_patch_returns_405(self):
        resp = self._send("PATCH")
        self.assertEqual(resp.status, 405)
        resp.read()

    def test_delete_returns_405(self):
        resp = self._send("DELETE")
        self.assertEqual(resp.status, 405)
        resp.read()

    def test_head_returns_405(self):
        resp = self._send("HEAD")
        self.assertEqual(resp.status, 405)
        resp.read()

    # ── Edge case: no valid key in DB 

    def test_auth_no_valid_key_returns_500(self):
        """If no valid key exists, /auth should respond 500."""
        with patch("main.get_valid_key", return_value=(None, None)):
            resp = self._post("/auth")
            self.assertEqual(resp.status, 500)
            resp.read()


if __name__ == "__main__":
    unittest.main()