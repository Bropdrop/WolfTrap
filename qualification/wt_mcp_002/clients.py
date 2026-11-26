"""Direct calls via actual offline clients. This harness never requests a model turn."""
import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import time

from confinement import run as probes
from fixtures import REF,arguments,provision
from profile import CAP,HERE,ROOT,SCAN,VERIFY,measurement
from trials import check,command,observe


def calls(owner):
    alpha=arguments(owner,SCAN,"alpha")
    return [(CAP,arguments(owner,CAP,"alpha"),"AVAILABLE"),
            (SCAN,{**alpha,"task":"unrelated"},"DENIED"),(SCAN,alpha,"COMMITTED"),
            (SCAN,alpha,"ALREADY_COMMITTED"),(VERIFY,arguments(owner,VERIFY,"alpha"),"VERIFIED")]


async def sdk(cmd,owner):
    from mcp import ClientSession,StdioServerParameters
    from mcp.client.stdio import stdio_client
    params=StdioServerParameters(command=cmd[0],args=cmd[1:],env={})
    outcomes=[]
    async with stdio_client(params) as (r,w), ClientSession(r,w) as session:
        await session.initialize()
        check({t.name for t in (await session.list_tools()).tools}=={CAP,SCAN,VERIFY},"SDK discovery")
        for name,args,status in calls(owner):
            reply=await session.call_tool(name,args)
            outcomes.append(reply.structuredContent["status"])
            check(outcomes[-1]==status,"SDK "+status)
    return outcomes


def codex(binary,cmd,owner):
    with tempfile.TemporaryDirectory() as tmp:
        env={"HOME":tmp,"CODEX_HOME":tmp,"TMPDIR":tmp,"PATH":os.defpath}
        def cli(*args):
            return subprocess.check_output([binary,"mcp",*args],cwd=tmp,env=env,stderr=subprocess.DEVNULL)
        for _ in range(2):
            cli("add","wolftrap","--",*cmd)
            listing=json.loads(cli("list","--json"))
            check(any(row["name"]=="wolftrap" for row in listing),"CLI registration")
            cli("remove","wolftrap")
            check(not json.loads(cli("list","--json")),"CLI removal")
        cli("add","wolftrap","--",*cmd)
        with subprocess.Popen([binary,"app-server"],env=env,cwd=tmp,bufsize=0,stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,stderr=subprocess.DEVNULL) as proc:
            seq=0
            def rpc(method,params):
                nonlocal seq
                seq+=1
                proc.stdin.write(json.dumps({"id":seq,"method":method,"params":params}).encode()+b"\n")
                deadline=time.monotonic()+40
                while time.monotonic()<deadline:
                    check(select.select([proc.stdout],[],[],max(0,deadline-time.monotonic()))[0],"Codex timeout")
                    msg=json.loads(proc.stdout.readline())
                    if msg.get("id")==seq:
                        check("result" in msg,"Codex rejected "+method)
                        return msg["result"]
                raise TimeoutError(method)
            try:
                rpc("initialize",{"clientInfo":{"name":"wolftrap_fixture","version":"2"},
                                  "capabilities":{"experimentalApi":True}})
                proc.stdin.write(b'{"method":"initialized"}\n')
                thread=rpc("thread/start",{"cwd":tmp,"ephemeral":True,"approvalPolicy":"never"})["thread"]["id"]
                observed=[]
                for name,args,expected in calls(owner):
                    result=rpc("mcpServer/tool/call",{"server":"wolftrap","threadId":thread,"tool":name,"arguments":args})
                    observed.append(result["structuredContent"]["status"])
                    check(observed[-1]==expected,"Codex "+expected)
            finally:
                proc.terminate()
                proc.wait(timeout=10)
        return observed


def trace_check(path):
    filters={}
    executing=set()
    for line in path.read_text().splitlines():
        pid=line.split(maxsplit=1)[0]
        if "seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=" in line and line.endswith("= 0"):
            filters[pid]=filters.get(pid,0)+1
        if 'openat(AT_FDCWD, "/role.py"' in line and " = -1" not in line:
            check(filters.get(pid,0)>=2,"role opened before both seccomp filters")
            executing.add(pid)
    check(len(executing)>=5,"incomplete client process trace")
    return {"filtered_roles_observed":len(executing),"minimum_filters_before_role":min(filters[p] for p in executing)}


def run(out, install=HERE):
    result={"os_probes":probes()}
    for kind in ("sdk","codex"):
        state=out/kind
        owner=provision(state)
        if kind=="sdk":
            version=importlib.metadata.version("mcp")
            # Measure the same installed dependency closure used by WT-MCP-001.
            from qualify import sdk_identity
            client="mcp-sdk-"+version+"-"+sdk_identity()
        else:
            binary=shutil.which("codex")
            version=subprocess.check_output([binary,"--version"],text=True).strip()
            with open(binary,"rb") as file:
                client="codex-"+hashlib.file_digest(file,"sha256").hexdigest()
        from recovery import pin_for
        pin=pin_for(install,client)
        cmd=command(state,owner,pin,client,install)
        trace=out/(kind+".strace")
        cmd=["/usr/bin/strace","-f","-qq","-s","100","-o",str(trace),"-e",
             "trace=seccomp,execve,clone,unshare,mount,openat",*cmd]
        statuses=asyncio.run(sdk(cmd,owner)) if kind=="sdk" else codex(binary,cmd,owner)
        observed=observe(state,"alpha")
        check({n:v["sha256"] for n,v in observed["files"].items()}==REF["alpha"]["expected"],"independent bytes")
        check([r[1] for r in observed["journal"]]==["DISPATCH","LISTED","DISPATCH","COMMITTED","DISPATCH","VERIFIED"],
              "independent history")
        result[kind]={"version":version,"client":client,"configuration":pin,"status":statuses,
                      "os":trace_check(trace),"observed":observed}
    return result


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--install",type=Path,default=HERE)
    args=p.parse_args()
    out=args.output.absolute()
    check(out==out.resolve() and not out.is_relative_to(ROOT),"external output")
    out.mkdir(mode=0o700)
    report=run(out,args.install.resolve())
    (out/"clients.json").write_text(json.dumps(report,indent=2)+"\n")
    print("SDK and Codex direct calls passed; three OS profiles verified")
