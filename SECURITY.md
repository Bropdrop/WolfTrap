# WolfTrap security and responsible disclosure

WolfTrap produces **conditional static review signals**, not verified
exploitation claims. Never publish a CVE, accuse a project of compromise,
or claim FBI/MITRE endorsement based solely on a WolfTrap report.

If you believe you found a vulnerability **in WolfTrap itself**:

1. Use the GitHub repository's private vulnerability-reporting feature if it
   is enabled under its Security tab.
2. If private reporting is unavailable, open a minimal public issue asking
   maintainers for a private contact method **without exploit details or
   credentials**.
3. Include a sanitized, reproducible synthetic case, affected commit SHA,
   supported Python version, expected and observed result, and impact.
4. Allow maintainers time to investigate and coordinate any disclosure.

For an issue in somebody else's repository, follow **their** disclosure
policy. WolfTrap's synthetic findings alone do not demonstrate compromise.

The scanner does not execute target files, use provider keys, deploy agents,
scan network services or authorize effects in HERCULES, Ground Truth, MobiPute
or TruthPute. No on-chain or financial operation is part of WolfTrap.

Unknown input, ambiguous provenance or invalid evidence must fail closed.
