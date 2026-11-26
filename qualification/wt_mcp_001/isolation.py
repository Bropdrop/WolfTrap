"""Linux x86-64 qualification profile. The host alone constructs these mounts."""
from pathlib import Path
import resource
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PYTHON = "/usr/bin/python3.13"
BWRAP = "/usr/bin/bwrap"
FILTER = ROOT / "qualification/wt_zt_001/offline.py"
LIBDIR = "/usr/lib/x86_64-linux-gnu"
LIBS = ("libc.so.6", "libm.so.6", "libexpat.so.1", "libz.so.1", "libffi.so.8",
        "libseccomp.so.2", "libcrypto.so.3", "liblzma.so.5", "libbz2.so.1.0")
HOST_LIBS = ("libselinux.so.1", "libcap.so.2", "libpcre2-8.so.0")
LOADER = "/lib64/ld-linux-x86-64.so.2"
ENGINE = ("__init__.py", "agent_scan.py", "agent_rules.py", "geotrace.py",
          "geotrace_cli.py", "_geotrace_v1.py")


def limits():
    for key, size in ((resource.RLIMIT_CPU, 6), (resource.RLIMIT_FSIZE, 1024 * 1024),
                      (resource.RLIMIT_NOFILE, 128), (resource.RLIMIT_AS, 256 << 20),
                      (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(key, (size, size))


def run(entry, mounts=(), args=(), payload=b""):
    command = [BWRAP, "--unshare-all", "--unshare-user", "--die-with-parent", "--new-session",
               "--disable-userns", "--clearenv", "--cap-drop", "ALL"]
    runtime = [(PYTHON, PYTHON), (LOADER, LOADER), ("/usr/lib/python3.13", "/usr/lib/python3.13"),
               (FILTER, "/offline.py"), (entry, "/entry.py")]
    runtime.extend((Path(LIBDIR) / lib, "/lib/x86_64-linux-gnu/" + lib) for lib in LIBS)
    for src, dest in runtime:
        command.extend(("--ro-bind", str(src), dest))
    for mode, src, dest in mounts:
        command.extend((mode, str(src), dest))
    command.extend(("--remount-ro", "/", "--", PYTHON, "-IBS", "/offline.py", PYTHON,
                    "-IBS", "/entry.py", *args))
    with tempfile.TemporaryFile() as output:
        proc = subprocess.run(command, input=payload, stdout=output, stderr=subprocess.DEVNULL,
                              timeout=12, env={}, close_fds=True, preexec_fn=limits)
        output.seek(0)
        return proc.returncode, output.read(65537)


def engine_mounts(scan, inputs, output):
    mounts = [("--ro-bind", ROOT / "src/wolftrap" / f, "/opt/engine/src/wolftrap/" + f)
              for f in ENGINE]
    mounts.extend([("--ro-bind", inputs / "sample.json", "/capture/sample.json"),
                   ("--ro-bind", inputs / "geo.json", "/geo.json"),
                   ("--bind" if scan else "--ro-bind", output, "/output")])
    return mounts


def engine(scan, inputs, output, policy):
    return run(HERE / "engine_entry.py", engine_mounts(scan, inputs, output), [
        "scan-geotrace" if scan else "verify-geotrace", "--root", "/capture",
        "--file", "sample.json", "--policy", "/geo.json", "--policy-sha256",
        policy["geo_policy_sha256"], "--as-of", policy["as_of"],
        "--output-dir" if scan else "--evidence-dir", "/output/bundle"])
