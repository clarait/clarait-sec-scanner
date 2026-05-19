# Compliance Mapping

`nyx-sec-scanner` produces evidence mapped to four frameworks:

1. **ISO 27001:2022 Annex A** — Information security controls
2. **GDPR / DSGVO** — EU 2016/679
3. **BSI IT-Grundschutz** — Bausteine ORP / OPS / CON / DER
4. **NIS2 Directive** — EU 2022/2555

> **Disclaimer.** This document maps script *capabilities* to framework *controls*. It does NOT assert that running the script alone makes any organisation compliant. Compliance is operationalised by the organisation: escalation, ticketing, retention review, periodic audit packaging, and DPIA where required.

---

## Quick reference — capability × framework

| Capability | ISO 27001:2022 | GDPR | BSI IT-Grundschutz | NIS2 |
|---|---|---|---|---|
| Worm IOC scan + active-process detection | A.5.7, A.12.6, A.16.1 | — | OPS.1.1.5 | Art. 21(2)(g) |
| Permission hardening (.env, ssh, npmrc) | A.8.12, A.8.24 | Art. 32(1)(b) | ORP.4.A11 | Art. 21(2)(d) |
| Report tamper-evidence (SHA-256) | A.8.15, A.12.4 | Art. 32(1)(b) | OPS.1.1.5 | Art. 21(2)(g) |
| Report confidentiality (mode 600, dir 700) | A.8.24 | Art. 32(2) | ORP.4.A11 | Art. 21(2)(d) |
| Retention enforcement (90-day default) | A.8.10 | Art. 5(1)(e) | CON.6 | — |
| PII minimisation (pseudonymised IDs, redacted paths) | A.8.12 | Art. 5(1)(c), Art. 25 | CON.6 | — |
| Privacy notice + lawful basis in report | — | Art. 13/14, Art. 6(1)(f) | — | — |
| Right-to-erasure command (`--purge`) | A.8.10 | Art. 17 | — | — |
| JSON SIEM sidecar | A.8.15, A.16.1 | Art. 32(1)(b) | OPS.1.1.5 | Art. 23 |
| Live IOC feed HTTPS-only + SHA-256 integrity | A.8.20, A.5.7 | — | OPS.1.1.5 | Art. 21(2)(g) |
| Registry hijack abort | A.5.7, A.8.20 | — | OPS.1.1.5 | Art. 21(2)(g) |
| Incident-notification email (optional) | A.6.8, A.16.1 | — | DER.2.1 | Art. 23 |
| Git hook persistence detection (per-repo + global) | A.8.12, A.12.6 | — | OPS.1.1.5 | Art. 21(2)(g) |

---

## 1 · ISO 27001:2022 — Annex A

Selected controls relevant to this scanner. Numbering follows ISO/IEC 27001:2022.

| Control | Title | How the scanner addresses it |
|---|---|---|
| A.5.7 | Threat intelligence | Static IOC array + optional live feed (`SEC_SCAN_IOC_URL`), pinned by SHA-256 when `SEC_SCAN_IOC_SHA256` set. |
| A.5.37 | Documented operating procedures | This document + `README.md` form the SOP. Operators MUST link them in their ISMS. |
| A.6.8 | Information security event reporting | JSON sidecar + optional email notification on worm hits. |
| A.8.8 | Management of technical vulnerabilities | `npm audit` integration, IOC cross-check, auto-fix gated behind registry verification. |
| A.8.9 | Configuration management | Verifies npm registry default, `.npmrc` token scopes, `core.hooksPath`. |
| A.8.10 | Information deletion | 90-day retention auto-purge on report dir + quarantine dir. `--purge` for explicit erasure. |
| A.8.12 | Data leakage prevention | Crontab + shell-rc content NOT logged verbatim; only redacted matching lines. SSH-key filenames suppressed by default. |
| A.8.15 | Logging | Markdown + JSON sidecar; SHA-256 fingerprint for log integrity. |
| A.8.20 | Network security | IOC feed enforces HTTPS + TLS 1.2; registry hijack abort. |
| A.8.24 | Use of cryptography | Report files mode 600; dir mode 700; SHA-256 for fingerprints. SSH key permission baseline. |
| A.12.4 | Logging and monitoring | JSON sidecar machine-readable for SIEM; SHA-256 ensures log integrity. |
| A.12.6 | Management of technical vulnerabilities | IOC + npm audit + git hook tampering check. |
| A.16.1 | Incident management | Exit code 2 on worm hit; optional notify-email; JSON sidecar carries scan ID for ticketing. |

---

## 2 · GDPR / DSGVO (EU 2016/679)

| Article | Topic | How the scanner addresses it |
|---|---|---|
| Art. 5(1)(c) | Data minimisation | Pseudonymised `MACHINE_ID` (SHA-256 of hostname+user, 16-char truncated); paths relativised to `~/`; crontab logged as count + redacted matches only; SSH key filenames suppressed by default. |
| Art. 5(1)(e) | Storage limitation | 90-day auto-purge (configurable via `SEC_SCAN_RETENTION_DAYS`). |
| Art. 6(1)(f) | Lawful basis — legitimate interest | Documented inline in every report header. Operator runs scanner on own workstation; controller is the operator's organisation. |
| Art. 13 / 14 | Information obligations | Privacy notice block in report header + `--help` references GDPR. |
| Art. 17 | Right to erasure | `./sec-scan.sh --purge` with confirmation prompt. |
| Art. 25 | Privacy by design + by default | Default mode: pseudonymised IDs, suppressed identifiers. `--include-identity` is opt-in. |
| Art. 32(1)(b) | Integrity of processing | SHA-256 fingerprint appended inline + sidecar; tamper-evident. |
| Art. 32(2) | Confidentiality | `install -d -m 700` + `chmod 600` on all artifacts. |

### DPIA threshold (Art. 35)

A DPIA is **not** mandatory for the current local-only data flow (no central aggregation, no profiling, no large-scale processing). If the scanner is ever extended with centralised report upload, **a DPIA becomes mandatory** under Art. 35(1)(c) (systematic monitoring of employees). The optional `--notify-email` sends a summary, not a full report, and is not in itself a trigger — but operators MUST confirm their org's DPIA policy before enabling org-wide email automation.

### Personal data inventory

| Category | Default behaviour | `--include-identity` |
|---|---|---|
| Hostname | Pseudonymised (SHA-256 truncated) | Raw value in report |
| Username | Suppressed | Raw value in report |
| File paths | Relativised to `~/` | Absolute path |
| SSH key filenames | "private key #N" (sequential label) | Raw filename |
| Email destination (notify) | Set by operator via flag/env; never hardcoded | (same) |

---

## 3 · BSI IT-Grundschutz

Selected Bausteine from the 2023+ edition.

| Baustein | Title | How the scanner addresses it |
|---|---|---|
| ORP.4 (A11) | Identitäts- und Berechtigungsmanagement — Permissions | Enforces `600/700` on `.env`, `~/.ssh`, `~/.npmrc`, report dir. |
| OPS.1.1.2 | Ordnungsgemäße IT-Administration | SOP + audit-ready report. |
| OPS.1.1.5 | Protokollierung | Markdown + JSON + SHA-256 fingerprint. |
| OPS.1.2.5 | Fernwartung — supply chain | IOC scan + registry hijack abort. |
| CON.6 | Löschen und Vernichten von Daten | 90-day auto-purge + `--purge`. |
| DER.2.1 | Behandlung von Sicherheitsvorfällen | Exit code 2 + notify-email + structured JSON for incident ticketing. |

---

## 4 · NIS2 Directive (EU 2022/2555)

Risk management measures (Art. 21) and incident reporting (Art. 23).

| Article | Topic | How the scanner addresses it |
|---|---|---|
| Art. 21(2)(a) | Risk analysis + information system security policies | Workstation-level risk evidence per scan. |
| Art. 21(2)(b) | Incident handling | Structured JSON output + optional email notification. |
| Art. 21(2)(d) | Supply chain security between an entity and direct suppliers | Permission hardening + registry verification. |
| Art. 21(2)(g) | Policies regarding the use of cryptography | SHA-256 integrity hashes on every report. |
| Art. 23 | Reporting obligations | JSON sidecar with `scanId`, `timestamp`, `wormHits` enables 24-h early-warning + 72-h notification workflow. |

**Note**: NIS2 applies to "essential" and "important" entities (Annex I/II). If your org falls under NIS2 scope, the scanner's output is one input into your overall risk-management programme — not the programme itself.

---

## How to use this evidence in an audit

1. **Schedule the scan** (cron / pre-commit hook) and document the cadence in your ISMS.
2. **Archive reports** to your evidence-collection tool (Drata, Vanta, OneTrust, Confluence, etc.) with the `.sha256` sidecar — proves integrity.
3. **Ingest JSON sidecars** into your SIEM. Map `scanId` + `machineId` + `wormHits` to your existing alert pipeline.
4. **On worm-hit**: trigger your IR runbook. The report's "manual actions" section is the starting checklist.
5. **Retain audit packages** per your data-retention policy. The scanner's 90-day local retention is for the operator's convenience; SIEM/evidence-store retention is governed by your org's policy.

---

## Limitations

The scanner does **not**:

- Replace endpoint EDR or anti-malware
- Replace a SBOM (Software Bill of Materials) tool — it only scans `package-lock.json` against a known-bad list
- Implement automated remediation beyond permission fixes + `npm audit fix --omit=dev`
- Aggregate cross-machine data — each scan stays local unless `--notify-email` is configured
- Sign reports cryptographically (only hashes them) — GPG signing is a roadmap item

For SBOM: Syft / CycloneDX / Snyk. For EDR: Falcon / SentinelOne / Microsoft Defender. For SIEM: Splunk / Elastic / Wazuh / Sentinel.

---

_Last reviewed: 2026-05-19 — applicable to nyx-sec-scanner v2.1.0._
