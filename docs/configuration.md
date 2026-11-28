# Configuration

ReconLens looks for settings in this order:

1. `RECONLENS_CONFIG`, if set. A missing file is an error.
2. `./reconlens.toml`
3. `$XDG_CONFIG_HOME/reconlens/config.toml`, or `~/.config/reconlens/config.toml`

Environment variables override the file. An empty string does not count as a
key. See [config.example.toml](../config.example.toml).

## Keys

| Variable | Source |
| --- | --- |
| `VIRUSTOTAL_API_KEY` | `virustotal` |
| `ABUSEIPDB_API_KEY` | `abuseipdb` |
| `URLSCAN_API_KEY` | `urlscan` |
| `SHODAN_API_KEY` | `shodan` |
| `HIBP_API_KEY` | `hibp` |

Unknown names under `[keys]` are a config error, so a typo does not look like a
missing key. The process environment uses the same names.

`reconlens sources` prints `key set` or `needs key`. It does not print the value.
`repr(config)` does not include the values either.

## Cache and HTTP

| Variable | Meaning |
| --- | --- |
| `RECONLENS_CACHE` | `true` or `false` |
| `RECONLENS_CACHE_TTL` | Seconds. `0` disables reads |
| `RECONLENS_CACHE_DIR` | Directory. Default `$XDG_CACHE_HOME/reconlens` or `~/.cache/reconlens` |
| `RECONLENS_TIMEOUT` | Seconds per source, 1 through 120. The `--timeout` flag wins |
| `RECONLENS_USER_AGENT` | Replaces the default identifying User-Agent |

`--cache` and `--no-cache` override the file for one run. Cache files are mode
`0600`. They store findings, not request headers.

The default User-Agent names ReconLens, this repository, and the passive-only
policy. Keep that spirit if you replace it. Some providers, including Have I
Been Pwned, reject clients that do not identify themselves.

## CLI flags that are not in the file

| Flag | Meaning |
| --- | --- |
| `--output text\|md\|html\|json` | Report format. `markdown` is accepted as `md` |
| `--out PATH` | Write md, html, json, csv, or jsonl. Not valid with `text` |
| `--sources a,b` | Only these sources. Unknown names are an error |
| `--exclude a,b` | Skip these sources |
| `--quiet` | Skip the terminal summary |
| `--fail-on-error` | Exit 1 if any source errors |
