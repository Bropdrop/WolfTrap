"""Operator entry point for the Linux stdio host and its nested worker profiles."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host import private_directory, require
from isolation import BWRAP, FILTER, HERE, HOST_LIBS, LIBDIR, LIBS, LOADER, PYTHON, ROOT



def command(state):
    private_directory(state)
    require(not state.is_relative_to(ROOT) and not ROOT.is_relative_to(state))
    # Dedicated owner directory. No user home, credentials, client sockets or repository mounts.
    inputs = ("sample.json", "geo.json")
    require(set(os.listdir(state)) <= {*inputs, "control", "bundle", "lock", "witness.jsonl"})
    private_directory(state / "control")
    require(set(os.listdir(state / "control")) == {"policy.json"})
    for name in (*inputs, "control/policy.json"):
        p = state / name
        require(p.is_file() and not p.is_symlink() and p.stat().st_nlink == 1)
    cmd = [BWRAP, "--unshare-all", "--unshare-user", "--die-with-parent", "--new-session",
           "--clearenv", "--cap-drop", "ALL", "--tmpfs", "/tmp", "--proc", "/proc", "--dev", "/dev"]
    for path in (BWRAP, PYTHON, LOADER, "/usr/lib/python3.13"):
        cmd.extend(("--ro-bind", path, path))
    for lib in LIBS + HOST_LIBS:
        cmd.extend(("--ro-bind", str(Path(LIBDIR) / lib), LIBDIR + "/" + lib))
    cmd.extend(("--symlink", "usr/lib", "/lib"))
    published = json.loads((HERE / "install-files.json").read_bytes())
    trees = (ROOT / "src/wolftrap", ROOT / "plugins/wolftrap-security")
    actual = {str(p.relative_to(ROOT)) for tree in trees for p in tree.rglob("*")
              if (p.is_symlink() or p.is_file()) and "__pycache__" not in p.parts and p.suffix != ".pyc"}
    require(set(published) == actual)
    entry_files = ("catalog.json", "install-files.json", "isolation.py", "host.py", "launch.py",
                   "configuration.py", "frontend.py", "engine_entry.py", "test_profile.py",
                   "qualify.py", "qualify_mutations.py", "codex_client.py", "packet.py")
    selected = [ROOT / rel for rel in published] + [HERE / name for name in entry_files]
    selected.extend((FILTER, ROOT / "pyproject.toml", ROOT / ".agents/plugins/marketplace.json"))
    for path in selected:
        require(path.resolve() == path and path.is_file())
        cmd.extend(("--ro-bind", str(path), "/app/" + str(path.relative_to(ROOT))))
    cmd.extend(("--bind", str(state), "/selected"))
    for name in inputs:
        cmd.extend(("--ro-bind", str(state / name), "/selected/" + name))
    cmd.extend(("--ro-bind", str(state / "control"), "/selected/control", "--remount-ro", "/"))
    return cmd


if __name__ == "__main__":
    # Fixed positional state, followed by the host parser's closed set of arguments.
    try:
        state = Path(sys.argv[1])
        args = sys.argv[2:]
        require(args and args[0] in ("serve", "inventory") and
                all(a != "--state" and not a.startswith("--state=") for a in args))
        cmd = command(state) + ["--", PYTHON, "-IBS", "/app/qualification/wt_mcp_001/host.py",
                                *args, "--state", "/selected"]
        os.execve(BWRAP, cmd, {})
    except (ValueError, OSError, IndexError):
        sys.exit("BLOCKED: selected launch profile unavailable")
