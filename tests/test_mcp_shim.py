"""End-to-end test of the stdio shim against a fake MCP server, over real pipes.

Proves three things:
  1. the agent's tool calls work through the shim unchanged while it is trusted;
  2. once the egress budget is crossed, reads stop reaching the server and the
     agent gets synthesised records instead;
  3. writes stop reaching the server too.

    python tests/test_mcp_shim.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SHIM = os.path.join(ROOT, "mcp_shim.py")
FAKE = os.path.join(HERE, "fake_mcp_server.py")
BUDGET = 600
REAL = {i: {"id": i, "name": f"customer_{i}", "signup_year": 2015 + (i - 1) // 6,
            "balance": round(800 + 45 * i, 2), "age": 20 + (i % 40),
            "tier": "gold" if i % 3 == 0 else "silver",
            "email": f"cust-{i:08x}@example.net"} for i in range(1, 21)}


class Shim:
    def __init__(self):
        fd, self.log_path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        env = dict(os.environ, FAKE_MCP_LOG=self.log_path, PYTHONUNBUFFERED="1")
        self.proc = subprocess.Popen(
            [sys.executable, SHIM, "--budget", str(BUDGET), "--", sys.executable, FAKE],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env)
        self.n = 0

    def rpc(self, method, params=None):
        self.n += 1
        req = {"jsonrpc": "2.0", "id": self.n, "method": method}
        if params is not None:
            req["params"] = params
        self.proc.stdin.write((json.dumps(req) + "\n").encode())
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("shim closed the stream")
        return json.loads(line)

    def call(self, name, args=None):
        return self.rpc("tools/call", {"name": name, "arguments": args or {}})

    def server_calls(self):
        if not os.path.exists(self.log_path):
            return []
        with open(self.log_path, encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip()]

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        if self.proc.stdout:
            self.proc.stdout.close()
        try:
            os.unlink(self.log_path)
        except OSError:
            pass


def payload(resp):
    return json.loads(resp["result"]["content"][0]["text"])


class TestMcpShim(unittest.TestCase):
    def setUp(self):
        self.s = Shim()

    def tearDown(self):
        self.s.close()

    def test_lifecycle_and_tools_pass_through(self):
        init = self.s.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                         "clientInfo": {"name": "t", "version": "0"}})
        self.assertEqual(init["result"]["serverInfo"]["name"], "fake")
        tools = self.s.rpc("tools/list")["result"]["tools"]
        self.assertEqual({t["name"] for t in tools}, {"read_customers", "write_customer"})

    def test_first_reads_are_real(self):
        r = self.s.call("read_customers", {"id": 1})
        self.assertEqual(payload(r)["id"], 1)
        self.assertEqual(payload(r)["name"], "customer_1")
        self.assertEqual(self.s.server_calls(), ["read_customers"])

    def test_after_the_budget_reads_stop_reaching_the_server(self):
        seen_rows = []
        for i in range(1, 11):
            p = payload(self.s.call("read_customers", {"id": i}))
            self.assertEqual(p["id"], i)
            seen_rows.append(p)
        calls = self.s.server_calls()
        # 10 reads, but the server should only have been asked a handful of times:
        # the reads before the switch, plus one broad harvest at the switch itself.
        self.assertLessEqual(len(calls), 3, f"reads kept reaching the server: {calls}")
        # a record the agent never saw must not come back as the real record.
        # compare whole records: the shadow deliberately preserves the id trend, so
        # any single numeric field can legitimately coincide with the real value.
        for i in (8, 9, 10):
            self.assertNotEqual(payload(self.s.call("read_customers", {"id": i})), REAL[i])

    def test_writes_stop_reaching_the_server_after_the_switch(self):
        for i in range(1, 8):
            self.s.call("read_customers", {"id": i})
        n = len(self.s.server_calls())
        r = self.s.call("write_customer", {"id": 3, "name": "pwned"})
        self.assertIn("result", r)
        self.assertEqual(len(self.s.server_calls()), n, "the write reached the real server")

    def test_seen_records_are_returned_verbatim(self):
        # read a record early, let the budget run out, re-read the same record
        first = payload(self.s.call("read_customers", {"id": 2}))
        for i in range(3, 12):
            self.s.call("read_customers", {"id": i})
        again = payload(self.s.call("read_customers", {"id": 2}))
        self.assertEqual(first, again)


if __name__ == "__main__":
    unittest.main(verbosity=2)
