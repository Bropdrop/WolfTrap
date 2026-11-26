"""Operator-side stdio reference monitor. Run only from a reviewed, immutable install."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
import subprocess
import tempfile

# Isolated Python ignores the script directory. This is the trusted installation.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import isolation
from configuration import configuration, encoded, sha
from isolation import HERE, ROOT

CAP = "wolftrap_capabilities"
SCAN = "wolftrap_scan_authorized_local"
VERIFY = "wolftrap_verify_evidence"
TOOLS = (CAP, SCAN, VERIFY)
FILES = {"geotrace.json", "geotrace.md", "geotrace.sarif", "manifest.json"}
LIMIT = 262144


class Denied(ValueError):
    pass


def require(condition):
    if not condition:
        raise Denied()


def unique(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs))
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: require(False))


def read(path, limit=LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit)
        raw = f.read(limit + 1)
        require(len(raw) == info.st_size and os.fstat(fd).st_ctime_ns == info.st_ctime_ns)
        return raw


def private_directory(path):
    s = path.lstat()
    require(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(s.st_mode)
            and s.st_uid == os.getuid() and s.st_mode & 0o077 == 0)


def check_bundle(directory, expected):
    private_directory(directory)
    require(set(os.listdir(directory)) == set(expected) == FILES)
    actual = {name: sha(read(directory / name)) for name in sorted(FILES)}
    require(actual == expected)
    return actual


def catalog():
    return decode(read(HERE / "catalog.json"))


def frontend(frame):
    code, raw = isolation.run(HERE / "frontend.py", [
        ("--ro-bind", HERE / "catalog.json", "/catalog.json")], payload=encoded(frame))
    require(code == 0 and len(raw) <= 65536)
    return decode(raw)


def result(status, **information):
    return {"content": [{"type": "text", "text": status}],
            "structuredContent": {"status": status, **information}, "isError": status in ("DENIED", "HOLD")}


class Host:
    def __init__(self, state, policy_pin, qualified_config, model, harness):
        private_directory(state)
        require(not state.is_relative_to(ROOT) and not ROOT.is_relative_to(state))
        self.state = state
        self.policy_pin = policy_pin
        self.pin = qualified_config
        self.model = model
        self.harness = harness
        self.initialized = False
        self.ready = False
        self.policy = self.current_policy()
        self.check_configuration()

    def current_policy(self):
        raw = read(self.state / "control/policy.json")
        require(sha(raw) == self.policy_pin)
        return decode(raw)

    def check_configuration(self):
        values = configuration(self.policy_pin, self.model, self.harness)
        require(sha(encoded(values)) == self.pin)

    def witness(self, event, **fields):
        path = self.state / "witness.jsonl"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as out:
            info = os.fstat(out.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            out.write(encoded({"event": event, "configuration": self.pin, **fields}) + b"\n")
            out.flush()
            os.fsync(out.fileno())

    def authorize(self, params):
        require(isinstance(params, dict) and set(params) == {"name", "arguments"})
        name = params["name"]
        require(isinstance(name, str) and name in TOOLS)
        grant = self.current_policy()["grants"].get(name)
        require(isinstance(grant, dict) and params["arguments"] == grant)
        return name, grant

    def dispatch(self, frame):
        params = frame.get("params")
        # MCP reserves _meta for transport metadata. Discard it before either decision maker.
        if isinstance(params, dict) and isinstance(params.get("_meta"), dict):
            params = {key: value for key, value in params.items() if key != "_meta"}
        frame = {"method": "tools/call", "params": params}
        # Hash untrusted input for correlation. Keep free text and claimed identities off the ledger.
        request_id = sha(encoded(params))
        try:
            self.check_configuration()
            name, grant = self.authorize(params)
            self.witness("policy-allow", request=request_id, tool=name, scope=grant)
            proposal = frontend(frame)
            require(proposal == {"dispatch": params})
        except (OSError, KeyError, TypeError, ValueError, subprocess.TimeoutExpired):
            self.witness("policy-deny", request=request_id)
            return result("DENIED")
        self.witness("dispatch", tool=name, request=request_id)
        if name == CAP:
            return result("AVAILABLE", tools=[t for t in TOOLS if t in self.policy["grants"]])
        try:
            return self.evidence(name, request_id)
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
            self.witness("hold", request=request_id)
            return result("HOLD")

    def evidence(self, name, request_id):
        dest = self.state / "bundle"
        expected = self.policy["expected_bundle"]
        with tempfile.TemporaryDirectory(dir=self.state) as work:
            work = Path(work)
            for filename, key in (("sample.json", "source_sha256"), ("geo.json", "geo_policy_sha256")):
                raw = read(self.state / filename)
                require(sha(raw) == self.policy[key])
                (work / filename).write_bytes(raw)
            self.witness("source-selected", request=request_id, sha256=self.policy["source_sha256"],
                         policy=self.policy["geo_policy_sha256"])
            stage = work / "stage"
            stage.mkdir(mode=0o700)
            if name == SCAN:
                require(not os.path.lexists(dest))
                code, _ = isolation.engine(True, work, stage, self.policy)
                require(code in (0, 1, 2))
            else:
                check_bundle(dest, expected)
                (stage / "bundle").mkdir(mode=0o700)
                for filename in FILES:
                    (stage / "bundle" / filename).write_bytes(read(dest / filename))
            observed = check_bundle(stage / "bundle", expected)
            code, reply = isolation.engine(False, work, stage, self.policy)
            require(code == 0 and reply == b"VERIFIED_EVIDENCE: NO_PATTERN_MATCH\n")
            self.witness("evidence-checked", request=request_id, hashes=observed, replay_exit=code)
            self.check_configuration()
            self.current_policy()
            if name == SCAN:
                # The host lock serializes writers to this private, owner-selected slot.
                require(not os.path.lexists(dest))
                self.witness("commit-intent", request=request_id)
                self.current_policy()
                os.rename(stage / "bundle", dest)
                fd = os.open(self.state, os.O_DIRECTORY | os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            check_bundle(dest, expected)
            self.witness("committed" if name == SCAN else "verified", request=request_id)
            return result("COMMITTED" if name == SCAN else "VERIFIED", hashes=observed)

    def handle(self, frame):
        require(isinstance(frame, dict) and frame.get("jsonrpc") == "2.0")
        method = frame.get("method")
        if "id" not in frame:
            if method == "notifications/initialized" and self.initialized:
                self.ready = True
            return None
        require(type(frame["id"]) in (int, str) and set(frame) <= {"id", "jsonrpc", "method", "params"})
        if method == "initialize" and not self.initialized:
            value = frontend({"method": method})
            expected = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                        "serverInfo": {"name": "wolftrap-local-qualification", "version": "0.1.0"}}
            require(value == expected)
            self.initialized = True
        elif self.ready and method == "tools/call":
            value = self.dispatch(frame)
        elif self.ready and method == "tools/list":
            self.check_configuration()
            require(CAP in self.current_policy()["grants"])
            value = frontend({"method": method})
            require(value == catalog())
            value = {"tools": [tool for tool in value["tools"] if tool["name"] in self.current_policy()["grants"]]}
        elif self.initialized and method == "ping":
            value = {}
        else:
            raise Denied()
        return {"jsonrpc": "2.0", "id": frame["id"], "result": value}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("inventory", "serve"))
    parser.add_argument("--state", required=True, type=Path)
    for key in ("policy-pin", "model", "harness"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--qualified-config")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.mode == "inventory":
            inventory = configuration(args.policy_pin, args.model, args.harness)
            print(json.dumps({"components": inventory, "digest": sha(encoded(inventory))}, sort_keys=True))
            return 0
        host = Host(args.state, args.policy_pin, args.qualified_config, args.model, args.harness)
        lock = os.open(args.state / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        while line := sys.stdin.buffer.readline(65537):
            if len(line) > 65536 or not line.endswith(b"\n"):
                return 2
            frame = {}
            try:
                frame = decode(line)
                message = host.handle(frame)
            except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.TimeoutExpired):
                identifier = frame.get("id") if isinstance(frame, dict) else None
                message = {"jsonrpc": "2.0", "id": identifier if type(identifier) in (int, str) else None,
                           "error": {"code": -32600, "message": "Request rejected"}}
            if message is not None:
                print(json.dumps(message, allow_nan=False), flush=True)
        return 0
    except (OSError, ValueError, KeyError):
        print("BLOCKED: host profile or qualification unavailable", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
