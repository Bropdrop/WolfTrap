"""Agent-facing stateless MCP handler. Its output is an untrusted proposal."""
import json
from pathlib import Path
import sys


def propose(request):
    method = request["method"]
    if method == "tools/list":
        return json.loads(Path("/catalog.json").read_bytes())
    if method == "tools/call":
        return {"dispatch": request["params"]}
    if method == "initialize":
        return {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                "serverInfo": {"name": "wolftrap-local-qualification", "version": "0.1.0"}}
    if method == "ping":
        return {}
    raise ValueError("unsupported method")


if __name__ == "__main__":
    print(json.dumps(propose(json.load(sys.stdin))))
