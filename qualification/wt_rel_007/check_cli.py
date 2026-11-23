"""Run the existing static-mode fixture tests against the installed public CLI."""

import argparse
import errno
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest


ENGINE = "ec6c3c1b2a50d702d202bd9b4e40842ba6e395f2"
ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "plugins/wolftrap-security/tests/test_integration.py"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="pinned public CLI fixture checkout")
    parser.add_argument("prefix", type=Path, help="trusted pip --target installation")
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    prefix = args.prefix.resolve(strict=True)
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip() != ENGINE:
        raise SystemExit("unexpected fixture source commit")
    try:
        with socket.socket():
            pass
    except OSError as exc:
        if exc.errno != errno.EPERM:
            raise
    else:
        raise SystemExit("offline fixture guard failed")
    spec = importlib.util.spec_from_file_location("plugin_fixtures", TESTS)
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    fixtures.REPO = source
    fixtures.FIXTURES = source / "tests" / "fixtures"
    env = {"PATH": os.defpath, "PYTHONPATH": str(prefix), "PYTHONNOUSERSITE": "1",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"}

    def run_cli(*arguments):
        return subprocess.run([prefix / "bin" / "wolftrap", *(str(arg) for arg in arguments)],
                              cwd=prefix, env=env, text=True, capture_output=True, timeout=30, check=False)

    fixtures.run_cli = run_cli
    for command in ("scan-build", "scan-agent", "scan-effects", "scan-prompts", "scan-go-authority",
                    "verify-effects", "verify-prompts", "verify-go-authority"):
        if run_cli(command, "--help").returncode:
            raise SystemExit(f"unavailable command {command}")
    names = unittest.defaultTestLoader.getTestCaseNames(fixtures.PluginOfflineIntegration)
    suite = unittest.TestSuite(fixtures.PluginOfflineIntegration(name)
                               for name in names if name != "test_geotrace_candidate_scan_and_replay")
    return int(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())


if __name__ == "__main__":
    sys.exit(main())
