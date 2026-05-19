# IOC Feed Specification

`nyx-sec-scanner` ships with a static array of known-compromised npm packages baked into the script (`COMPROMISED[]`). For organisations that want a fresher list, the scanner can fetch IOCs from a remote feed at scan time.

## Configuration

| Variable | Purpose | Required |
|---|---|---|
| `SEC_SCAN_IOC_URL` | HTTPS URL returning the IOC list | Yes (to enable live fetch) |
| `SEC_SCAN_IOC_SHA256` | Expected SHA-256 of the response body — content rejected if mismatch | No (strongly recommended) |

If `SEC_SCAN_IOC_URL` is set, the scanner merges the fetched entries with its static list. If the fetch fails (offline, 4xx, timeout), it falls back to the static list and proceeds — the static list is the floor, not the ceiling.

## Feed format

Plain text. One IOC per line. UTF-8. Comments (`#`) and blank lines ignored.

```
# nyx-sec-scanner IOC feed v1
# Generated 2026-05-19 from canonical sources.

# Shai-Hulud Sep 2025 wave
@ctrl/tinycolor@4.1.1
@ctrl/tinycolor@4.1.2

# Wildcard match (every version of a confirmed-malicious package)
gauntletjs@*

# Scoped package with specific version
@nx/core@21.5.0

# Plain package
chalk@5.6.1
debug@4.4.2
```

### Format rules

- `<name>@<version>` — package name + version selector
- Name may be scoped (`@scope/pkg`) or unscoped (`pkg`)
- Version may be exact (`4.1.1`) or wildcard (`*` — every version)
- One IOC per line; malformed entries are skipped with a warning (no script abort)
- Format validation regex: `^@?[a-zA-Z0-9_./-]+@([0-9.*+~^x]|[0-9]+\.[0-9.*x-]+|\*)$`

## Integrity verification

Pin the SHA-256 of your feed:

```bash
# At feed-publish time:
shasum -a 256 iocs.txt
#  abc123def456...  iocs.txt

# At scan time:
SEC_SCAN_IOC_URL=https://your.feed/iocs.txt \
SEC_SCAN_IOC_SHA256=abc123def456... \
  ./sec-scan.sh
```

If the actual SHA-256 doesn't match, the scanner refuses the feed, falls back to the static list, increments `WORM_HITS`, and writes a finding line. Without `SEC_SCAN_IOC_SHA256` the feed is accepted on TLS trust alone — fine for trusted internal mirrors, NOT recommended for arbitrary public feeds.

## Recommended sources

The scanner does not ship a default `SEC_SCAN_IOC_URL` — pick a source you trust and pin the hash.

| Source | Notes |
|---|---|
| **Socket.dev** | <https://socket.dev/> — supply-chain research team. |
| **OpenSSF Package Analysis** | <https://github.com/ossf/package-analysis> — daily JSON dumps. |
| **npm Security Advisories** | <https://www.npmjs.com/advisories> — official npm advisories. |
| **Your own mirror** | Generate from any of the above, host internally, pin the SHA. |

## Hosting your own feed

Minimal example: host a static `iocs.txt` on any web server with HTTPS. Pin the SHA-256 of the file. Rotate weekly.

For higher cadence, run a small ETL that pulls from Socket.dev / OpenSSF and writes a normalised `iocs.txt` daily.

## Format extensibility

The current `name@version` format is intentionally minimal. Future extensions (severity, source URL, expiry date) will use a structured format (JSON) and a new env variable to keep backward compatibility.

If you have a richer threat-intel feed format you'd like supported (STIX, MISP, OpenIoC), open a feature-request issue with a sample payload.
