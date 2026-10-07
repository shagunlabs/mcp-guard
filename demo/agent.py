#!/usr/bin/env python3
"""Scripted 'agent' (MCP client) that falls for a prompt injection in a support ticket.
Usage: agent.py <proxy command...>"""
import json, subprocess, sys

p = subprocess.Popen(sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
n = 0
def call(method, params=None):
    global n; n += 1
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": n, "method": method, "params": params or {}}) + "\n"); p.stdin.flush()
    return json.loads(p.stdout.readline())
def tool(sql, name="db.query"):
    r = call("tools/call", {"name": name, "arguments": {"db": "demo", "sql": sql}})["result"]
    return ("BLOCKED " if r.get("isError") else "OK      ") + r["content"][0]["text"]

call("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "demo-agent", "version": "0"}})
print("agent: tools =", [t["name"] for t in call("tools/list")["result"]["tools"]])
steps = [
    ("1. read the ticket (allowed; output is untrusted, so it gets fingerprinted)", "SELECT body FROM tickets WHERE id = 7", "db.query"),
    ("2. injected instruction copied from the ticket: DROP TABLE users", "DROP TABLE users", "db.query"),
    ("3. same thing via an uncatalogued tool", "DROP TABLE users", "db.admin"),
    ("4. DML (DELETE) always needs a human", "DELETE FROM users WHERE name = 'Asha'", "db.query"),
    ("5. users table still there?", "SELECT count(*) FROM users", "db.query"),
]
for label, sql, name in steps:
    print(f"\nagent: {label}\n  -> {name}: {sql}\n  <- {tool(sql, name)}")
p.stdin.close(); p.wait()
