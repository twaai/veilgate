"""Acceptance tests for the process boundary.

These spawn serve.py as a real subprocess and talk to it over HTTP. Nothing here
imports veilgate - that is the point. If these pass, an agent integration has an
HTTP client and a credential, and no path to the store.

    python tests/test_server.py
"""
import json
import os
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [ROOT, HERE]
import client as vc

OPERATOR = "test-operator-token"


class TestBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "serve.py"),
             "--seed", "11", "--operator-token", OPERATOR],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        line = cls.proc.stdout.readline().strip()
        if not line.startswith("LISTENING"):
            raise RuntimeError(f"server did not start: {line!r}")
        cls.base = "http://" + line.split()[1]

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        if cls.proc.stdout:
            cls.proc.stdout.close()

    def agent(self, name="a"):
        return vc.Client(self.base, vc.register(self.base, OPERATOR, name))

    # --- the boundary itself ---
    def test_reads_work_over_http(self):
        c = self.agent("reader")
        d = c.directory()
        self.assertIn("read_record", d)
        r = c.call(d["read_record"], {"id": 1})
        self.assertTrue(r.get("ok"))
        self.assertEqual(r["data"]["id"], 1)

    def test_unknown_credential_is_rejected(self):
        c = vc.Client(self.base, "not-a-real-credential")
        self.assertEqual(c.directory().get("http_status"), 401)

    def test_register_requires_the_operator_token(self):
        req = urllib.request.Request(
            self.base + "/v1/register", data=json.dumps({"name": "x"}).encode(),
            method="POST", headers={"Authorization": "Bearer wrong",
                                    "Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 401)

    def test_oversized_body_is_refused(self):
        req = urllib.request.Request(
            self.base + "/v1/call", data=b'{"route":"' + b"A" * (70 * 1024) + b'"}',
            method="POST", headers={"Authorization": f"Bearer {vc.register(self.base, OPERATOR, 'big')}",
                                    "Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 400)

    # --- deception survives the boundary ---
    def test_quarantine_is_invisible_across_the_wire(self):
        c = self.agent("rogue")
        d = c.directory()
        before = c.call(d["read_record"], {"id": 40})
        self.assertTrue(before.get("ok"))
        for i in range(1, 51):                      # trips the egress budget
            r = c.call(d["read_record"], {"id": i})
            self.assertTrue(r.get("ok"), r)         # never an error, even once caught
        after = c.call(d["read_record"], {"id": 40})
        self.assertEqual(before, after)             # already-seen records are byte-identical
        shape = sorted(after["data"])
        self.assertEqual(shape, sorted(before["data"]))

    # --- static guarantee ---
    def test_client_does_not_import_the_gateway(self):
        with open(os.path.join(ROOT, "client.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("import veilgate", src)
        self.assertNotIn("from veilgate", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
