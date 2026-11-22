"""Owner-held supervisor for independently namespaced broker and single-use sibling workers."""
import argparse
import contextlib
import fcntl
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from reference_pin import application_bytes, expected_configuration
from sibling import BWRAP, PYTHON, base, serve


def private(path):
    if (not path.is_absolute() or path != path.resolve(strict=True) or not path.is_dir() or
            path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077):
        raise ValueError("private directory required")


def add_file(cmd, fds, data, destination):
    fd = os.memfd_create("wolftrap-reviewed-member", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    fds.append(fd)
    with os.fdopen(os.dup(fd), "wb") as out:
        out.write(data)
    os.lseek(fd, 0, os.SEEK_SET)
    fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
    cmd.extend(("--file", str(fd), destination))


def launch(state, install, owner, pin, session, client):
    private(state)
    if state.is_relative_to(install) or install.is_relative_to(state) or install.resolve(strict=True) != install:
        raise ValueError("overlapping or noncanonical selection")
    contents = application_bytes(install)
    if expected_configuration(install/"qualification/wt_mcp_002",client,contents) != pin:
        raise ValueError("configuration changed")
    for name in ("launch.py", "reference_pin.py", "sibling.py", "job_wire.py"):
        if contents["qualification/wt_mcp_002/" + name] != Path(__file__).with_name(name).read_bytes():
            raise ValueError("supervisor and installation differ")
    cmd = base(True)
    cmd.extend(("--size","16777216","--tmpfs","/tmp","--proc","/proc","--dev","/dev",
                "--ro-bind",BWRAP,BWRAP))
    fds = []
    with contextlib.ExitStack() as stack:
        requests, request_out = os.pipe()
        stack.callback(os.close, requests)
        fds.append(request_out)
        reply_in, replies = os.pipe()
        stack.callback(os.close, replies)
        fds.append(reply_in)
        try:
            for name, data in contents.items():
                add_file(cmd, fds, data, "/app/"+name)
            for name in ("control","sources","effects"):
                path=state/name
                private(path)
                fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                fds.append(fd)
                cmd.extend(("--bind-fd" if name=="effects" else "--ro-bind-fd",str(fd),"/"+name))
            cmd.extend(("--remount-ro","/","--",PYTHON,"-IBS","/app/qualification/wt_mcp_002/broker.py",
                        owner,pin,session,client,str(request_out),str(reply_in)))
            broker=subprocess.Popen(cmd,pass_fds=tuple(fds),env={})
        finally:
            for fd in fds:
                os.close(fd)
        try:
            with os.fdopen(requests,"rb",closefd=False) as reader, os.fdopen(replies,"wb",closefd=False) as writer:
                serve(reader,writer,contents,add_file)
            return broker.wait(timeout=12)
        finally:
            if broker.poll() is None:
                broker.kill()
            broker.wait()


if __name__=="__main__":
    os.closerange(3,os.sysconf("SC_OPEN_MAX"))
    p=argparse.ArgumentParser(allow_abbrev=False)
    p.add_argument("state",type=Path)
    p.add_argument("--install",type=Path,required=True)
    for name in ("owner-pin","qualified-pin","session","client"):
        p.add_argument("--"+name,required=True)
    a=p.parse_args()
    try:
        sys.exit(launch(a.state,a.install,a.owner_pin,a.qualified_pin,a.session,a.client))
    except (ValueError,OSError,EOFError,subprocess.TimeoutExpired):
        sys.exit("BLOCKED: owner launch profile unavailable")
