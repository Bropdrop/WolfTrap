# Contributing to WolfTrap

Thanks for helping make CI trust-boundary analysis easier to understand.

## Test first

```bash
python3 -m pip install -e '.[build-scan]'
python3 -m unittest discover -s tests -v
wolftrap scan-go-authority --root /path/to/your-own-go-repo \
  --file path/to/selected.go --output-dir /tmp/wolftrap-go-review
wolftrap verify-go-authority --evidence-dir /tmp/wolftrap-go-review
wolftrap challenge-build --seed 20261115 --cases 128 --output-dir /tmp/wolftrap-contrib
wolftrap challenge-agent --seed 20261115 --output-dir /tmp/wolftrap-contrib-agent
wolftrap verify-agent-challenge --evidence-dir /tmp/wolftrap-contrib-agent
```

Every new detection rule should include at least one positive, one negative,
one ambiguous/fail-closed case, an honest limitation, and deterministic
evidence. Agent rules also need a saved-input replay control. Avoid turning
lexical matches into `CONFIRMED_EXPLOIT` claims.

## Scope

- Keep test inputs synthetic and local. Do not submit live intrusion payloads,
  credentials, exploit traffic or proprietary source code.
- No network access, target subprocess execution, unbounded traversal or
  default write-capable GitHub tokens in the scanner.
- Avoid adding a model dependency or external effect to a core detection.
- Preserve compatibility for existing rule IDs and stable report schemas, or
  document explicit versioned migrations.
- Favor precise, explainable trust chains and verified negative controls over
  noisy threat-keyword matching.

Include the actual source commit/tree and test results when filing a PR.
Maintainers separately review sensitive changes; green unit tests are not an
independent security audit.

**License:** WolfTrap is distributed under the [Apache License, Version 2.0](LICENSE).
Submitting a contribution does not bypass the project's security review or
claim verification of real-world vulnerabilities.
