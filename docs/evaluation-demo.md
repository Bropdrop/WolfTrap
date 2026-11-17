# Reproduce the offline authority demo

This demo uses Python 3.11 or newer, Git, a clean WolfTrap checkout and two deterministic authority suites. Once you have the checkout, the demo needs no downloads, API keys, models, tenant records, or network. You can run the whole sequence in a network-disabled environment.

On Linux systems with user and network namespaces enabled, start an isolated
shell with `unshare --user --map-root-user --net -- sh`. Run both blocks from
that shell and record the isolation method with the evidence.

## Run both suites and preserve the revision

From the root of the reviewed checkout:

```sh
set -eu
test -z "$(git status --porcelain)"
export PYTHONPATH="$PWD/src"
evidence="$(mktemp -d)"
{
  printf 'commit %s\n' "$(git rev-parse HEAD)"
  printf 'tree %s\n' "$(git rev-parse 'HEAD^{tree}')"
  python3 --version
  uname -smr
} > "$evidence/environment.txt"

python3 -m wolftrap challenge-cloud-authority --output-dir "$evidence/cloud"
python3 -m wolftrap verify-cloud-authority --evidence-dir "$evidence/cloud"
python3 -m wolftrap challenge-authority-funnel --output-dir "$evidence/funnel"
python3 -m wolftrap verify-authority-funnel --evidence-dir "$evidence/funnel"
test -z "$(git status --porcelain)"
printf 'Evidence directory %s\n' "$evidence"
```

Open `cloud/cloud-authority-challenge.json` and `funnel/authority-funnel-challenge.json` alongside each suite's Markdown and completion manifest. Check that cloud and funnel evidence each match their reviewed revision's counts and schemas. The original baseline on `main` at commit `892b822d842456ddfb1ea33db338d4ffe85c0491` and tree `ce7c1ebc7e336efb1e5f9085bf2b77152d09988b` has 1,920 cloud-authority checks and 3,019 authority-funnel proposals. Both suites require zero expectation mismatches. The cloud suite additionally requires zero oracle failures. The funnel has a thousand-proposal case with exactly one effect and an unregistered-grant flood with none.

## Check one tamper control

Run this in the same shell with the evidence directory variable from above. It changes only a copy of the generated output.

```sh
cp -R "$evidence/funnel" "$evidence/funnel-altered"
printf '\n' >> "$evidence/funnel-altered/authority-funnel-challenge.json"
if python3 -m wolftrap verify-authority-funnel --evidence-dir "$evidence/funnel-altered"; then
  printf '%s\n' 'Unexpected verification success' >&2
  exit 1
else
  status=$?
  test "$status" -eq 2
fi
```

A reproduced pass supports `SYNTHETICALLY VERIFIED` for the exercised conditions. Preserve the revision record, state the network isolation used, and apply the [evidence guide](evidence-guide.md) when sharing results.

For the repository-wide qualification, start with the optional build-scan
dependency already installed in the test environment. Use a fresh output
path outside the checkout.

```bash
PYTHONPATH=src python3 scripts/qualify-research.py --output-dir /tmp/wolftrap-qualification
```

See the [public baseline and evaluation priorities](qualification-baseline.md).
