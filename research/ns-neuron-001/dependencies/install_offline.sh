#!/bin/sh
# Arguments: verified wheelhouse, path of new environment.
set -eu
wheels=$(realpath "$1")
envdir=$(realpath -m "$2")
evidence=$(dirname "$(realpath "$0")")
if [ -e "$envdir" ]; then
    echo 'Provide a new directory for this venv.' >&2
    exit 2
fi
python -c 'import sys; assert sys.version_info[:3] == (3, 12, 14), sys.version'
python -m venv "$envdir"
"$envdir/bin/python" -m pip --isolated install --disable-pip-version-check --no-index --find-links="$wheels" --require-hashes -r "$evidence/reference/requirements.lock"
"$envdir/bin/python" -m pip --isolated check
