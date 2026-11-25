"""Build and install a private candidate wheel; invoke the installed CLI outside its source checkout."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

source, work, reports, venv, launcher, model, standalone = [Path(v).absolute() for v in sys.argv[1:]]
reports.mkdir(exist_ok=False, parents=True)
work.mkdir(exist_ok=False, parents=True)
shutil.copytree(source, work/'source')
for d, _, files in os.walk(work/'source'):
    Path(d).chmod(0o700)
    for name in files:
        p = Path(d)/name
        p.chmod(p.stat().st_mode | 0o200)
wheel_dir=work/'wheels'
wheel_dir.mkdir()
python=venv/'bin/python'
cli=venv/'bin/wolftrap-neuralscope'
events=[]

def run(name, args, cwd):
    cmd=[sys.executable, '-B', str(launcher), '--', *map(str,args)]
    with (reports/(name+'.log')).open('w') as f:
        proc=subprocess.run(cmd, cwd=cwd, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT)
    events.append({'command':cmd,'cwd':str(cwd),'exit':proc.returncode,'log':name+'.log'})
    (reports/'commands.json').write_text(json.dumps(events,indent=2)+'\n')
    proc.check_returncode()

run('build-wheel',[python,'-m','pip','--isolated','wheel','--disable-pip-version-check','--no-index','--no-deps','--no-build-isolation','-w',wheel_dir,'.'],work/'source')
whl,=wheel_dir.glob('*.whl')
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
run('install-wheel',[python,'-m','pip','--isolated','install','--disable-pip-version-check','--no-index','--no-deps',whl],work)
run('check-installed',[python,'-m','pip','--isolated','check'],work)
run('import-installed',[python,'-c',"import sys, importlib.metadata, neuralscope.neuron_run as m; from pathlib import Path; print(importlib.metadata.version('wolftrap-neuralscope'), m.__file__); assert Path(m.__file__).is_relative_to(sys.prefix)"],work)
run('cli-help',[cli,'--help'],work)
run('neuron-help',[cli,'neuron','--help'],work)
cli_out=reports/'installed-neuron-run'
run('cli-neuron',[cli,'neuron','--model-dir',model,'--out',cli_out],work)
actual_receipt=sha(cli_out/'manifest.json')
cli_log=(reports/'cli-neuron.log').read_text()
assert actual_receipt in cli_log
run('verify-cli-receipt',[cli, 'verify', cli_out, '--manifest-sha256',actual_receipt],work)
manifest=json.loads((cli_out/'manifest.json').read_text())
source_identity={p.name:sha(p) for p in (source/'neuralscope').glob('*.py')}
assert manifest['context']['source_files']=={k:{'sha256':v,'bytes':(source/'neuralscope'/k).stat().st_size} for k,v in source_identity.items()}
keys=('protocol.json', 'discovery.json', 'selection.json','results.json')
matched={k:{'standalone_sha256':sha(standalone/k),'installed_sha256':sha(cli_out/k)} for k in keys}
status=json.loads((cli_out/'results.json').read_text())['status']
summary={'wheel':whl.name,'size':whl.stat().st_size,'sha256':sha(whl),'runtime':str(python),'study_status':status,'compared':matched,'byte_identical':all(v['standalone_sha256']==v['installed_sha256'] for v in matched.values()),'wheel_retained_at':str(whl),'manifest_sha256':actual_receipt,'package_py_files_matched_to_candidate':len(source_identity)}
(reports/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
if status!='MEASURED' or not summary['byte_identical']: sys.exit(1)
