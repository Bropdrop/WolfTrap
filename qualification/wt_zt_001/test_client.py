"""Install into a disposable Codex CLI home. All network socket calls are intercepted."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

from package import BASE, FILES, ZIP, build, git


@unittest.skipUnless(shutil.which("strace") and shutil.which("codex"), "requires Linux strace and Codex CLI")
class CleanClient(unittest.TestCase):
    def test_local_install_and_reinstall(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            market = home / "market"
            catalog = market / ".agents/plugins/marketplace.json"
            catalog.parent.mkdir(parents=True)
            catalog.write_bytes(git("cat-file", "blob", BASE + ":.agents/plugins/marketplace.json"))
            plugin = market / "plugins/wolftrap-security"
            first = build()
            second = build()
            self.assertEqual(first, second)
            receipt = json.loads(first["package-receipt.json"])
            with zipfile.ZipFile(io.BytesIO(first[ZIP])) as archive:
                self.assertEqual(sorted(archive.namelist()), sorted(FILES))
                archive.extractall(plugin)
            expected_inventory = receipt["members"]

            def client(*args):
                log = home / "calls"
                cmd = ["strace", "-f", "-qq", "-o", str(log), "-e", "trace=socket,connect,io_uring_setup",
                       "-e", "inject=socket:error=EPERM", "-e", "inject=connect:error=EPERM",
                       "-e", "inject=io_uring_setup:error=EPERM", "codex", *args, "--json"]
                proc = subprocess.run(cmd, cwd=tmp, env={"HOME":tmp, "PATH":os.environ["PATH"]},
                                      capture_output=True, text=True, timeout=30)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertFalse(any(x in log.read_text() for x in ("socket(", "connect(", "io_uring_setup(")))
                return json.loads(proc.stdout)

            self.assertEqual(client("plugin", "marketplace", "add", str(market))["marketplaceName"], "wolftrap-local")
            for attempt in range(2):
                installed = client("plugin", "add", "wolftrap-security@wolftrap-local")
                destination = Path(installed["installedPath"])
                self.assertTrue(destination.is_relative_to(home / ".codex"))
                self.assertEqual(installed["version"], "0.1.0")
                actual = {}
                for p in destination.rglob("*"):
                    self.assertFalse(p.is_symlink())
                    if p.is_file():
                        blob = p.read_bytes()
                        actual[p.relative_to(destination).as_posix()] = {
                            "bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}
                self.assertEqual(actual, expected_inventory)
                if attempt == 0:
                    client("plugin", "remove", "wolftrap-security@wolftrap-local")
                    self.assertFalse(destination.exists())
