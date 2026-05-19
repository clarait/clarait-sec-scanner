# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.1.x   | ✅ Yes — active |
| < 2.1   | ❌ No (pre-public) |

## Reporting a vulnerability in nyx-sec-scanner

If you find a security issue **in the scanner itself** (not in something the scanner reports about your system), please report it privately:

1. **GitHub Private Vulnerability Disclosure** (preferred) — open at <https://github.com/nyxCore-Systems/nyx-sec-scanner/security/advisories/new>.
2. Or email the maintainers via the address listed on the org's public profile.

Please include:

- Affected version (`./sec-scan.sh --help` shows it)
- A reproducer or attack scenario
- Suggested fix if you have one

## Disclosure SLA

- **Acknowledgement**: within 5 business days.
- **Triage decision** (accept / decline / need-more-info): within 14 days.
- **Coordinated disclosure window**: typically 90 days from acknowledgement, negotiable for complex fixes or coordinated industry advisories.

We will credit reporters in the changelog unless they request otherwise.

## Out of scope

- Vulnerabilities in **transitively scanned tools** (npm, git, openssh) — report those to their respective projects.
- Issues found by the scanner running against your own systems — those are your operational findings, not vulnerabilities in the scanner.
- "The scanner cannot detect X" — that's a feature request, not a vulnerability. Open a regular issue.
- IOC list completeness — open a PR adding the missing IOC.

## Threat model

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full threat model documenting what the scanner does and does not defend against.
