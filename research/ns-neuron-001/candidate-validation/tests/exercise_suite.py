"""Test a fresh disposable source copy and record one line per standard unittest case."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

source, copy, output, python, launcher = map(Path, sys.argv[1:])
source, copy, output, python, launcher = [p.absolute() for p in (source, copy, output, python, launcher)]
output.mkdir(parents=True, exist_ok=False)
shutil.copytree(source, copy)
for root, dirs, files in os.walk(copy):
    os.chmod(root, 0o700)
    for name in files:
        path = Path(root) / name
        path.chmod(path.stat().st_mode | 0o200)

def snapshot(path):
    return {s.relative_to(path).as_posix(): hashlib.sha256(s.read_bytes()).hexdigest()
            for s in sorted(path.rglob('*')) if s.is_file()}

before = snapshot(copy)
assert before == snapshot(source)
(output / 'initial-source.json').write_text(json.dumps(before, indent=2) + '\n')
cmd = [sys.executable, '-B', str(launcher), '--', str(python), '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-v']
with (output / 'unittest.log').open('w') as log:
    result = subprocess.run(cmd, cwd=copy, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
after = snapshot(copy)
assert before == snapshot(source)
text = (output / 'unittest.log').read_text()
cases = []
for section in re.split(r'(?=^test\w+ \()', text, flags=re.M):
    line = ' '.join(section.splitlines()[:2]) if ' ... ' not in section.split('\n', 1)[0] else section.split('\n', 1)[0]
    m = re.match(r'(test\w+) \(([^)]+)\).*? \.\.\. (ok|FAIL|ERROR|expected failure|unexpected success|skipped .+)$', line)
    if m: cases.append({'name': m[1], 'qualified': m[2], 'outcome': m[3]})
run_match = re.search(r'^Ran (\d+) tests? in ([0-9.]+)s$', text, flags=re.M)
outcomes = {}
for case in cases:
    status = case['outcome'].split(' ')[0]
    outcomes[status] = outcomes.get(status, 0) + 1
summary = {'source':str(source), 'working_copy':str(copy), 'command':cmd, 'exit':result.returncode,
           'reported_count': int(run_match[1]) if run_match else None, 'per_case_count':len(cases),
           'cases_by_outcome':outcomes, 'elapsed_seconds':float(run_match[2]) if run_match else None,
           'changes_in_copy':sorted(k for k in set(before)|set(after) if before.get(k) != after.get(k)),
           'source_verified_against_initial_snapshot': True}
(output / 'per-case.json').write_text(json.dumps(cases, indent=2) + '\n')
(output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
sys.exit(result.returncode or int(summary['reported_count'] != len(cases)))
