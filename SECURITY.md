# WolfTrap security and responsible disclosure

WolfTrap reports conditional static review signals and results from bounded
synthetic experiments. Treat suspected real-world compromise as a separate
investigation. See the [evidence guide](docs/evidence-guide.md).

If you believe you found a vulnerability **in WolfTrap itself**:

1. Use the repository's private vulnerability reporting if it is available.
   [WolfTrap Security tab](https://github.com/GovernableIntelligence/WolfTrap/security).
2. If private reporting is unavailable, open a minimal public issue asking
   maintainers for a private contact method **without exploit details or
   credentials**. [WolfTrap issues](https://github.com/GovernableIntelligence/WolfTrap/issues).
3. In the private channel, include the affected commit and tree, Python
   version, a sanitized synthetic reproduction, expected and observed result,
   impact and any manifest integrity result you observed. Keep credentials,
   tenant records, personal data and proprietary material in their authorized
   environment.
4. Allow maintainers time to investigate and coordinate any disclosure.

For an issue in somebody else's repository, follow **their** disclosure
policy. WolfTrap's synthetic findings alone do not demonstrate compromise.

WolfTrap scanners read bounded local inputs without executing them. Public
experiments use synthetic authority and synthetic effect records. Authority over
any private service, repository or protected effect remains with its owner.

Unknown input, unsupported syntax, ambiguous provenance or invalid evidence
must fail closed. A mock/demo callback name is only a static context cue; it
does not waive manual review of an unconditional authentication result.
