"""Check the actual installed environment against the recovered package-version snapshot."""
import hashlib
import json
import platform
import sys
from importlib import metadata
from pathlib import Path

from packaging.utils import canonicalize_name
import numpy
import safetensors
import tokenizers
import torch
import transformers
from transformers import GPT2LMHeadModel
from transformers.models.gpt2 import modeling_gpt2
from transformers.pytorch_utils import Conv1D
import inspect

reference = Path(sys.argv[1])
requested = dict((canonicalize_name(pkg), ver) for pkg, ver in
                 (l.split('==', 1) for l in reference.read_text().splitlines() if l and not l.startswith('#')))
installed = {canonicalize_name(d.metadata['Name']): d.version for d in metadata.distributions()}
differences = {n: {'wanted': requested.get(n), 'actual': installed.get(n)}
               for n in sorted(set(installed) | set(requested)) if installed.get(n) != requested.get(n)}
paths = {'Python executable': Path(sys.executable).resolve(),
         'GPT2 model implementation': Path(modeling_gpt2.__file__),
         'Conv1D implementation': Path(inspect.getsourcefile(Conv1D)),
         'reference lock': reference.resolve()}
def receipt(path):
    with path.open('rb') as handle:
        return {'file': (str(path).split('/site-packages/')[-1] if '/site-packages/' in str(path) else path.name), 'sha256': hashlib.file_digest(handle, 'sha256').hexdigest()}

print(json.dumps({'python':sys.version, 'platform':platform.platform(), 'torch':torch.__version__,
                  'torch_cuda_build':torch.version.cuda, 'transformers':transformers.__version__,
                  'tokenizers':tokenizers.__version__, 'safetensors':safetensors.__version__,
                  'numpy':numpy.__version__, 'gpt2_model_import':GPT2LMHeadModel.__module__,
                  'files':{k:receipt(v) for k,v in paths.items()},
                  'reference_distributions':len(requested), 'installed_distributions':len(installed),
                  'differences':differences}, indent=2))
if differences or sys.version_info[:3] != (3, 12, 14) or torch.version.cuda is not None:
    sys.exit(1)
