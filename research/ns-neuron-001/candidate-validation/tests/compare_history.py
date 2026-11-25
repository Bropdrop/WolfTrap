"""Verify recovered source and compare every historical ZIP member with the candidate."""
import hashlib
import json
from pathlib import Path
import sys
import zipfile

archive, recovered, candidate, out = map(Path, sys.argv[1:])
expected = '392dcc885ac32688d803d841335a29f2e545db9ccb99f86e42841e1c0f77121a'
actual = hashlib.sha256(archive.read_bytes()).hexdigest()
assert actual == expected, (actual, expected)
rows = []
with zipfile.ZipFile(archive) as z:
    for name in sorted(z.namelist()):
        if name.endswith('/'): continue
        path = Path(name)
        rel=Path(*path.parts[1:]); assert path.parts[0] == 'wolftrap-neuralscope'
        hash0=hashlib.sha256(z.read(name)).hexdigest()
        assert hashlib.sha256((recovered/rel).read_bytes()).hexdigest()==hash0, str(rel)
        new_rel=Path('historical/v0.3.0a1-bundle-inventory.json') if rel.as_posix() == 'bundle-inventory.json' else rel
        copy=candidate/new_rel
        hash1=hashlib.sha256(copy.read_bytes()).hexdigest() if copy.is_file() else None
        is_evidence = rel.parts[0] in {'attention-summary','pretrained-summary','example-run','example-api-dry-run','validation.json','bundle-inventory.json'}
        rows.append({'path':rel.as_posix(),'candidate_location':new_rel.as_posix(),'original_sha256':hash0,'candidate_sha256':hash1,'same':hash0==hash1,'historical_evidence':is_evidence})
result={'original_zip_sha256':actual,'members':len(rows),'recovered_members_all_byte_exact':True,
        'historical_evidence_members':sum(r['historical_evidence'] for r in rows),
        'matching_historical_evidence_members':sum(r['historical_evidence'] and r['same'] for r in rows),
        'candidate_inherited_files_matching':sum(r['same'] for r in rows),
        'changed_or_absent':[r['path'] for r in rows if not r['same']],'rows':rows}
out.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2))
assert result['historical_evidence_members'] == result['matching_historical_evidence_members']
