"""Trusted supervisor. Keep this file and reference_pin.py in an owner-controlled location."""
import argparse
import fcntl
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from reference_pin import LIBS, application_bytes, expected_configuration


def private(path):
    if (not path.is_absolute() or path!=path.resolve(strict=True) or not path.is_dir() or
            path.stat().st_uid!=os.getuid() or path.stat().st_mode & 0o077):
        raise ValueError("private directory required")


def sealed(data):
    fd=os.memfd_create("wolftrap-reviewed-member",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    with os.fdopen(os.dup(fd),"wb") as out:
        out.write(data)
    os.lseek(fd,0,os.SEEK_SET)
    fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
    os.set_inheritable(fd,True)
    return str(fd)


def command(state,install,client,pin):
    private(state)
    if (state.is_relative_to(install) or install.is_relative_to(state) or
            install.resolve(strict=True)!=install):
        raise ValueError("overlapping or noncanonical selection")
    contents=application_bytes(install)
    if expected_configuration(install/"qualification/wt_mcp_002",client,contents)!=pin:
        raise ValueError("configuration changed")
    cmd=["/usr/bin/bwrap","--unshare-all","--unshare-user","--die-with-parent","--new-session",
         "--clearenv","--cap-drop","ALL","--size","16777216","--tmpfs","/tmp","--proc","/proc","--dev","/dev"]
    for path in ("/usr/bin/bwrap","/usr/bin/python3.13","/lib64/ld-linux-x86-64.so.2","/usr/lib/python3.13"):
        cmd.extend(("--ro-bind",path,path))
    for lib in LIBS:
        path="/usr/lib/x86_64-linux-gnu/"+lib
        cmd.extend(("--ro-bind",path,path))
    cmd.extend(("--symlink","usr/lib","/lib"))
    for name,data in contents.items():
        cmd.extend(("--file",sealed(data),"/app/"+name))
    for name in ("control","sources","effects"):
        path=state/name
        private(path)
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        os.set_inheritable(fd,True)
        cmd.extend(("--bind-fd" if name=="effects" else "--ro-bind-fd",str(fd),"/"+name))
    return cmd+["--remount-ro","/","--","/usr/bin/python3.13","-IBS","/app/qualification/wt_mcp_002/broker.py"]


if __name__=="__main__":
    os.closerange(3,os.sysconf("SC_OPEN_MAX"))
    p=argparse.ArgumentParser(allow_abbrev=False)
    p.add_argument("state",type=Path)
    p.add_argument("--install",type=Path,required=True)
    for name in ("owner-pin","qualified-pin","session","client"):
        p.add_argument("--"+name,required=True)
    a=p.parse_args()
    try:
        cmd=command(a.state,a.install,a.client,a.qualified_pin)+[a.owner_pin,a.qualified_pin,a.session,a.client]
        os.execve(cmd[0],cmd,{})
    except (ValueError,OSError):
        sys.exit("BLOCKED: owner launch profile unavailable")
