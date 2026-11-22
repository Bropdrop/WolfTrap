"""Owner entry point. The caller cannot change this profile through MCP."""
import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from profile import HERE, HOST_LIBS, MEMBERS, ROOT, directory, isolation, measurement, require


def command(state):
    directory(state)
    require(not state.is_relative_to(ROOT) and not ROOT.is_relative_to(state))
    require(set(os.listdir(state)) == {"control","sources","effects"})
    for name in ("control","sources","effects"):
        directory(state/name)
    require(set(os.listdir(state/"control")) == {"owner.json","generation","gate","geo.json"})
    require(1 <= len(os.listdir(state/"sources")) <= 8)
    cmd = [isolation.BWRAP,"--unshare-all","--unshare-user","--die-with-parent","--new-session",
           "--clearenv","--cap-drop","ALL","--size","16777216","--tmpfs","/tmp","--proc","/proc","--dev","/dev"]
    def mount(src,dest,flag="--ro-bind"):
        cmd.extend((flag,str(src),str(dest)))
    for path in (isolation.BWRAP,isolation.PYTHON,isolation.LOADER,"/usr/lib/python3.13"):
        mount(path,path)
    for lib in isolation.LIBS + HOST_LIBS:
        path = Path(isolation.LIBDIR)/lib
        mount(path,path)
    cmd.extend(("--symlink","usr/lib","/lib"))
    for path in MEMBERS:
        require(path.resolve(strict=True) == path and path.is_file())
        mount(path,"/app/"+str(path.relative_to(ROOT)))
    mount(state/"control","/control")
    mount(state/"sources","/sources")
    mount(state/"effects","/effects","--bind")
    return cmd + ["--remount-ro","/","--",isolation.PYTHON,"-IBS","/app/qualification/wt_mcp_002/broker.py"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("state",type=Path)
    for name in ("owner-pin","qualified-pin","session","client"):
        parser.add_argument("--"+name,required=True)
    args = parser.parse_args()
    try:
        require(measurement(args.client) == args.qualified_pin)
        cmd = command(args.state) + [args.owner_pin,args.qualified_pin,args.session,args.client]
        os.execve(isolation.BWRAP,cmd,{})
    except (ValueError,OSError):
        sys.exit("BLOCKED: owner launch profile unavailable")
