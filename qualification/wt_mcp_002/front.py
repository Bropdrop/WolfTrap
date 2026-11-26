"""Untrusted proposal process. Receives only the selected call or static catalog."""
import json
import sys

request = json.load(sys.stdin)
print(json.dumps({"proposal":request}))
