# Changelog

All notable changes to ReconLens are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `dns` reports DS and DNSKEY, with an info finding when neither is published.
- `email-auth` fetches the MTA-STS policy file when a `v=STSv1` TXT exists and
  flags SPF records with more than 10 DNS-based mechanisms.
- `diff` also reports findings whose detail text changed. `batch` exits 2 when
  no valid targets parse and rejects files over 1000 lines. An unreachable
  MTA-STS host now yields a low finding instead of failing `email-auth`.
- `crtsh` adds up to 10 issuer findings with name counts.
- `ripestat` source: keyless prefix and ASN lookup for public IPs through the
  RIPEstat network-info endpoint. Private addresses are not sent.
- `--output csv` (one row per finding) and `--output jsonl` (one finding object
  per line, with `target` and `target_type`) report formats, also accepted by
  `reconlens report`.

## [0.1.0] - 2026-11-22

### Added

- Passive CLI for domains, IP addresses, email addresses, and usernames.
- Plugin entry points so third-party sources load beside the built-in ones.
- Keyless sources: DNS, RDAP, crt.sh, TLS certificate inspection, HTTP security
  headers, robots.txt, security.txt, ipwho.is geolocation, Wayback CDX, a small
  username catalog, MX/SPF/DMARC (plus BIMI, MTA-STS, and TLS-RPT records), and
  Gravatar.
- Optional keyed sources, disabled until an environment variable or config value
  is set: VirusTotal, AbuseIPDB, urlscan (search only), Shodan (lookup only),
  and Have I Been Pwned.
- Markdown, self-contained HTML, and JSON reports. JSON schema 1.x is documented
  in `docs/report.schema.json`.
- Optional on-disk cache, rate limits, an identifying User-Agent, and a
  public-host guard on outbound HTTP.

[Unreleased]: https://github.com/codedbyasim/reconlens/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/codedbyasim/reconlens/releases/tag/v0.1.0
