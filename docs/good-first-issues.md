# Good first issues

These are written so a maintainer can paste each one into GitHub. Suggested
labels are on the first line of each issue. Creating the issues from this file
was not possible from the automation that added the file; the text is the
backlog.

Every task is passive. Do not add port scans, name brute force, login attempts,
or "submit this URL to be scanned" behavior.

---

## 1. RIPEstat network lookup

**Title:** Add a keyless RIPEstat source for IP network info

**Labels:** good first issue, help wanted, new-source

### Summary

Add `ripestat`, a keyless source that GETs one RIPEstat endpoint for an IP and
returns network name and prefix.

### Scope

- New module `src/reconlens/plugins/ripestat.py`.
- `target_types` is IP only.
- One HTTPS GET to `https://stat.ripe.net/data/network-info/data.json` with the
  IP as the `resource` query parameter.
- Findings: prefix, ASN if present, holder name. Cap the text.
- `source_url` is the public RIPEstat page, not an internal API host if a
  stable public URL exists; otherwise the data URL without extra parameters.
- Entry point plus `BUILTIN_PATHS`.
- respx test. README table row.

### Out of scope

Other RIPEstat endpoints. No prefix enumeration.

### Done when

- [ ] `reconlens ip 1.1.1.1 --sources ripestat` works against the mock.
- [ ] A private IP is not sent to RIPEstat.
- [ ] `make ci` passes.

---

## 2. AlienVault OTX passive DNS

**Title:** Add an AlienVault OTX passive-DNS source

**Labels:** good first issue, help wanted, new-source

### Summary

Optional keyed source. Lookup only.

### Scope

- Module `src/reconlens/plugins/otx.py`.
- Env `OTX_API_KEY`. Skipped when unset.
- Domain target. One GET of the documented OTX passive DNS endpoint.
- Header for the key. Do not put the key in the URL.
- Return up to 50 hostnames as findings, plus a truncation finding.
- Tests assert the key is absent from findings and from a 401 error string.
- Document the variable in `config.example.toml`, the README, and
  `docs/configuration.md`.

### Out of scope

OTX URL lists, malware samples, or pulses that are not passive DNS.

### Done when

- [ ] Missing key skips the source.
- [ ] Mocked 200 response becomes findings.
- [ ] `make ci` passes.

---

## 3. SecurityTrails passive DNS

**Title:** Add a SecurityTrails passive-DNS source

**Labels:** good first issue, help wanted, new-source

### Summary

Same shape as OTX, for SecurityTrails' passive DNS domain endpoint.

### Scope

- Module `src/reconlens/plugins/securitytrails.py`.
- Env `SECURITYTRAILS_API_KEY`.
- Domain only. One documented lookup. No scrolling through every historical
  page in v1: request a single page and cap at 50 names.
- Key in a header.

### Out of scope

IP history that fans out into more queries, and any "associated domains" crawl.

### Done when

- [ ] Tests cover 200, 401, and a missing key.
- [ ] README and config example mention the variable.
- [ ] `make ci` passes.

---

## 4. DNSSEC presence check

**Title:** Report DS and DNSKEY records from the DNS source

**Labels:** good first issue, help wanted

### Summary

Extend `dns` with DS and DNSKEY. This is two more passive queries, not a
validator that walks the chain yet.

### Scope

- Add `DS` and `DNSKEY` to `RECORD_TYPES`.
- If either type returns records, emit them.
- If both are `noanswer`, emit one info finding "No DNSSEC records".
- Do not treat a missing DS as a vulnerability headline. Say the records were
  not published.
- Unit-test `findings_from_dns` with fake `DnsAnswer`s. No live resolver.

### Out of scope

Full chain validation and trust-anchor fetching. That can be a later issue.

### Done when

- [ ] Both the present and absent cases have tests.
- [ ] `make ci` passes.

---

## 5. Fetch the MTA-STS policy

**Title:** Read the MTA-STS policy file when the DNS record exists

**Labels:** good first issue, help wanted

### Summary

`email-auth` already reports the `_mta-sts` TXT record and says the policy URL
was not fetched. Fetch it.

### Scope

- When a `v=STSv1` TXT exists, GET `https://mta-sts.<domain>/.well-known/mta-sts.txt`
  through `ctx.get_public`.
- Parse `mode`, `mx`, and `max_age`. One finding per field, values clipped.
- 404 is a finding, not a failed source.
- Do not fetch the URL when the TXT record is absent.

### Out of scope

Enforcing the policy or connecting to the MX hosts.

### Done when

- [ ] respx covers 200 and 404.
- [ ] The "policy URL was not fetched" detail is updated.
- [ ] `make ci` passes.

---

## 6. CSV report

**Title:** Add a CSV report format

**Labels:** good first issue, help wanted

### Summary

`--output csv` writes one row per finding.

### Scope

- Columns, in order: `source,category,severity,title,value,detail,source_url,timestamp,id`.
- `csv` module. Quote fields. UTF-8. Trailing newline.
- `reconlens report --output csv` accepts it.
- A test renders a two-finding report and checks the header and a value that
  contains a comma and a quote.
- Document the format in `docs/reports.md` and the README.

### Out of scope

JSON Lines. That is a separate issue. Do not change the JSON schema.

### Done when

- [ ] `reconlens domain example.com --output csv` is accepted by the CLI tests
  via a mocked run or a saved report.
- [ ] `make ci` passes.

---

## 7. JSON Lines report

**Title:** Add a JSON Lines report format

**Labels:** good first issue, help wanted

### Summary

`--output jsonl` writes one finding object per line, using the same finding
fields as schema 1.x, plus `target` and `target_type` on each line.

### Scope

- No pretty-printing. One JSON object, then `\n`.
- A line must parse with `json.loads`.
- Document it next to CSV.

### Out of scope

Streaming the CLI before sources finish. Buffer the report, then write lines.

### Done when

- [ ] Round-trip test: two findings, two lines, stable keys.
- [ ] `make ci` passes.

---

## 8. Batch file

**Title:** Add reconlens batch for a file of targets

**Labels:** good first issue, help wanted

### Summary

`reconlens batch targets.txt --type domain` runs the domain sources for each
non-empty, non-comment line.

### Scope

- One target per line. `#` comments and blank lines ignored.
- `--type domain|ip|email|username` is required.
- A bad line is recorded and the file continues.
- Default delay of 1 second between targets, flag `--delay`.
- JSON output is a list of report objects. Say so in `docs/reports.md` as a
  batch document, not a change to schema 1.x for a single report.
- Cap is not required, but print how many targets will run before starting.

### Out of scope

Mixing types in one file. Parallel targets. The per-target sources stay
parallel, as they are today.

### Done when

- [ ] A three-line file with one comment and one invalid line produces two
  reports and one notice, against mocks.
- [ ] `make ci` passes.

---

## 9. Report diff

**Title:** Add reconlens diff for two JSON reports

**Labels:** good first issue, help wanted

### Summary

`reconlens diff --before a.json --after b.json` prints findings whose ids
appeared, disappeared, or changed severity.

### Scope

- Both files must be schema 1.x and the same target value.
- Match on finding `id`.
- Text output: three sections, Added, Removed, Severity changed.
- `--output json` writes `{added, removed, severity_changed}`.
- Exit 0 when the files parse, even if they differ. Exit 2 when the targets
  differ or the JSON is unreadable.

### Out of scope

A human-readable HTML diff.

### Done when

- [ ] Tests cover an added finding, a removed finding, and a target mismatch.
- [ ] `make ci` passes.

---

## 10. SourceHut in the username catalog

**Title:** Add SourceHut to the username site list

**Labels:** good first issue, help wanted

### Summary

Add one object to `src/reconlens/data/username_sites.json` for
`https://sr.ht/~{username}` if a missing account returns a stable 404.

### Scope

- Confirm the status codes with a browser, not a login.
- If 200 and 404 are not reliable, use `missing_body_contains` or skip the site
  and say why in the pull request.
- Extend the catalog test only if the expected count is asserted as an exact
  number. Prefer `>=`.

### Out of scope

A new Python module. Mastodon instances (they need an instance flag; that is
issue 11's neighbor, not this one).

### Done when

- [ ] The JSON still loads and every template passes `build_site_url` in a test.
- [ ] `make ci` passes.

---

## 11. Extra username sites file

**Title:** Allow an additional username sites file

**Labels:** good first issue, help wanted

### Summary

`reconlens username NAME --sites extra.json` appends to the packaged catalog.

### Scope

- Same object shape as the packaged file.
- Invalid objects are skipped with a finding, as they are today.
- The same URL rules apply: one `{username}`, path or query only, `https`,
  public host.
- A missing file is a usage error (exit 2).
- Tests: one extra site is requested, a `javascript:` template is skipped.

### Out of scope

Replacing the packaged catalog. Remote site lists.

### Done when

- [ ] respx shows the extra URL was called and a bad template was not.
- [ ] `make ci` passes.

---

## 12. HTML report filters

**Title:** Add self-contained severity and source filters to the HTML report

**Labels:** good first issue, help wanted

### Summary

The HTML report is one file with no remote assets. Add a tiny inline script
that shows and hides findings by severity and source.

### Scope

- Checkboxes generated from the severities and source names in the report.
- No network, no libraries, no build step.
- The report must still be readable with JavaScript disabled: the script only
  hides, and the default is everything visible.
- A test asserts the script is inline and that a finding value of
  `<script>` is still escaped.

### Out of scope

A framework, a chart library, or remote fonts.

### Done when

- [ ] `tests/test_reports.py` covers the escaped value and the presence of the
  controls.
- [ ] `make ci` passes.

---

## 13. crt.sh issuer summary

**Title:** Summarize crt.sh issuers in addition to names

**Labels:** good first issue, help wanted

### Summary

`crtsh` lists hostnames. Also emit up to 10 issuer findings with a count.

### Scope

- Read `issuer_name` from each row that contributed a hostname.
- One finding per issuer: title `Issuer`, value the issuer, detail `N names`.
- Keep the existing name findings and the 200-name cap.
- Unit-test `findings_from_ct` with three rows and two issuers.

### Out of scope

Downloading the certificates themselves.

### Done when

- [ ] Counts are correct in the test.
- [ ] `make ci` passes.

---

## 14. reconlens doctor

**Title:** Add reconlens doctor to check config without printing secrets

**Labels:** good first issue, help wanted

### Summary

`reconlens doctor` prints the config path it would read, whether the cache
directory is writable, and which key variables are set. Values stay hidden.

### Scope

- Exit 0 when config parses.
- Exit 2 when `RECONLENS_CONFIG` points at a missing or invalid file.
- A test sets `VIRUSTOTAL_API_KEY` to a long dummy and asserts the dummy is
  absent from stdout and stderr, while `key set` is present.
- Mention the command in the README.

### Out of scope

Network calls. Doctor does not contact the providers.

### Done when

- [ ] The secret-leak test is in `tests/test_cli.py`.
- [ ] `make ci` passes.

---

## 15. SPF mechanism count

**Title:** Note when an SPF record has many DNS-looking mechanisms

**Labels:** good first issue, help wanted

### Summary

RFC 7208 limits DNS-based mechanisms. Parse the SPF string and, when it
contains more than 10 of `include`, `a`, `mx`, `ptr`, `exists`, or `redirect`,
add a low finding. Do not resolve those names.

### Scope

- A function `count_spf_dns_mechanisms(record: str) -> int` in `email_auth.py`.
- The finding is in addition to the existing SPF interpretation.
- Tests: a record with 2 includes, a record with 11, and `+all` still classified
  as it is today.
- No extra DNS queries.

### Out of scope

Walking `include:` targets. That would multiply queries and is a different change.

### Done when

- [ ] The count is covered without a resolver.
- [ ] `make ci` passes.
