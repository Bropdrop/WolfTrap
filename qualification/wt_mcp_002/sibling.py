"""Trusted fixed-role spawner. No job field selects a command, mount path, or host destination."""
from contextlib import contextmanager
import os
import resource
import subprocess
import selectors
import signal
import time

from job_wire import INPUTS, NAMES, OUTPUT_LIMIT, get, put
from reference_pin import ENGINE, LIBS

Q = "qualification/wt_mcp_002/"
PYTHON = "/usr/bin/python3.13"
BWRAP = "/usr/bin/bwrap"


def base(broker):
    cmd = [BWRAP, "--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent",
           "--new-session", "--clearenv", "--cap-drop", "ALL"]
    for path in (PYTHON, "/lib64/ld-linux-x86-64.so.2", "/usr/lib/python3.13"):
        cmd.extend(("--ro-bind", path, path))
    for lib in LIBS if broker else LIBS[:9]:
        path = "/usr/lib/x86_64-linux-gnu/" + lib
        cmd.extend(("--ro-bind", path, path))
    cmd.extend(("--symlink", "usr/lib", "/lib"))
    return cmd


def limits():
    for kind, bound in ((resource.RLIMIT_CPU, 6), (resource.RLIMIT_FSIZE, 1 << 20),
                        (resource.RLIMIT_NOFILE, 128), (resource.RLIMIT_AS, 256 << 20),
                        (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(kind, (bound, bound))


def run_job(role, parts, contents, add_file, fds):
    cmd = base(False)
    def mount(data, path):
        add_file(cmd, fds, data, path)
    mount(contents["qualification/wt_zt_001/offline.py"], "/offline.py")
    mount(contents[Q + "locked_worker.py"], "/entry.py")
    if role == b"F":
        mount(contents[Q + "front.py"], "/role.py")
        argv, stdin = [], parts[0]
    else:
        mount(contents[Q + "engine_role.py"], "/role.py")
        mount(contents[Q + "job_wire.py"], "/job_wire.py")
        mount(contents["qualification/wt_mcp_001/engine_entry.py"], "/scanner.py")
        for name in ENGINE:
            mount(contents["src/wolftrap/" + name], "/opt/engine/src/wolftrap/" + name)
        for path, data in zip(("/capture/sample.json", "/geo.json", "/date", "/digest"), parts[:4]):
            mount(data, path)
        if role == b"S":
            cmd.extend(("--size", "16777216", "--tmpfs", "/output"))
        else:
            for name, data in zip(NAMES, parts[4:], strict=True):
                mount(data, "/output/bundle/" + name)
        argv, stdin = ["scan" if role == b"S" else "verify"], b""
    cmd.extend(("--remount-ro", "/", "--", PYTHON, "-IBS", "/offline.py", PYTHON, "-IBS", "/entry.py", *argv))
    # The worker inherits pipes only. The supervisor bounds output while the worker runs.
    with subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env={}, pass_fds=tuple(fds), preexec_fn=limits, bufsize=0) as worker:
        try:
            return exchange(worker, stdin)
        finally:
            if worker.poll() is None:
                worker.kill()


def exchange(worker, data):
    output = bytearray()
    deadline = time.monotonic() + 12
    with selectors.DefaultSelector() as poll:
        poll.register(worker.stdout, selectors.EVENT_READ)
        if data:
            poll.register(worker.stdin, selectors.EVENT_WRITE)
        else:
            worker.stdin.close()
        while poll.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("worker deadline")
            for key, _ in poll.select(remaining):
                if key.fileobj is worker.stdin:
                    try:
                        written = os.write(key.fd, data[:4096])
                        data = data[written:]
                    except BrokenPipeError:
                        data = b""
                    if not data:
                        poll.unregister(key.fd)
                        worker.stdin.close()
                else:
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        poll.unregister(key.fd)
                    elif len(output) + len(chunk) > OUTPUT_LIMIT:
                        raise ValueError("worker output exceeds profile")
                    else:
                        output.extend(chunk)
    return worker.wait(timeout=max(0, deadline - time.monotonic())), bytes(output)


@contextmanager
def transfer_deadline():
    def expired(*_):
        raise TimeoutError("private channel deadline")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(12)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def serve(reader, writer, contents, add_file):
    for _ in range(4096):
        role = reader.read(1)
        if not role:
            return
        if role not in INPUTS:
            raise ValueError("unknown worker role")
        with transfer_deadline():
            parts = [get(reader, limit) for limit in INPUTS[role]]
        fds = []
        try:
            code, data = run_job(role, parts, contents, add_file, fds)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            code, data = 2, b""
        finally:
            for fd in fds:
                os.close(fd)
        with transfer_deadline():
            writer.write(bytes([code if 0 <= code <= 255 else 2]))
            put(writer, data, OUTPUT_LIMIT)
            writer.flush()
    raise ValueError("worker budget exhausted")
