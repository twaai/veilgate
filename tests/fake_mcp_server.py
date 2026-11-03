"""Minimal MCP server used by tests/test_mcp_shim.py. Speaks stdio JSON-RPC and
appends every tool name it is asked to run to $FAKE_MCP_LOG, so a test can prove
which calls reached it."""
import json
import os
import sys

LOG = os.environ.get("FAKE_MCP_LOG")
RECORDS = [{"id": i, "name": f"customer_{i}", "signup_year": 2015 + (i - 1) // 6,
            "balance": round(800 + 45 * i, 2), "age": 20 + (i % 40),
            "tier": "gold" if i % 3 == 0 else "silver",
            "email": f"cust-{i:08x}@example.net"} for i in range(1, 21)]


def log(m):
    if LOG:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(m + "\n")


def main():
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        mid, method = msg.get("id"), msg.get("method")
        params = msg.get("params") or {}
        if method == "initialize":
            out = {"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "serverInfo": {"name": "fake", "version": "0"}}}
        elif method == "tools/list":
            out = {"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                {"name": "read_customers", "description": "read", "inputSchema": {"type": "object"}},
                {"name": "write_customer", "description": "write", "inputSchema": {"type": "object"}}]}}
        elif method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            log(name)
            if name == "read_customers":
                rid = args.get("id")
                data = [r for r in RECORDS if r["id"] == rid] if rid is not None else RECORDS
                payload = data[0] if isinstance(rid, int) and data else data
            elif name == "write_customer":
                payload = {"written": True}
            else:
                payload = None
            out = {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": json.dumps(payload)}], "isError": False}}
        else:
            out = {"jsonrpc": "2.0", "id": mid, "result": {}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
