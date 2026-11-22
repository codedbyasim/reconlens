# Plugin API

```python
from reconlens import Category, Severity, Source, TargetType, make_finding
```

## Source

Subclass `reconlens.plugins.base.Source`.

| Attribute | Required | Meaning |
| --- | --- | --- |
| `name` | yes | CLI id. Must match the entry-point name. Pattern: `^[a-z][a-z0-9-]{1,40}$` |
| `description` | yes | One sentence for `reconlens sources` |
| `target_types` | yes | Non-empty `frozenset` of `TargetType` |
| `requires_api_key` | no | Default `False`. When `True`, the runner skips the source if the key is missing |
| `api_key_env` | when keyed | Environment variable name, for example `VIRUSTOTAL_API_KEY` |
| `min_interval_seconds` | no | Minimum gap between this source's HTTP calls. The first call does not wait |
| `display_order` | no | Sort key. Lower is earlier. Default `100` |
| `homepage` | no | Docs or provider home page |
| `cache_version` | no | Bump when the finding shape changes so old cache files are ignored |

```python
async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
    ...
```

Raise `reconlens.errors.SourceError` with a message that does not contain the
API key. Any other exception is also contained, and its message is scrubbed.

Return findings, including an explicit negative ("No record") when silence
would look like a bug. Do not return `None`.

## Target

`target.value` is normalized:

- domains are lowercase ASCII (IDNA), with one trailing dot removed
- emails are lowercased, and the domain must be a hostname
- IPs are compressed with the standard library
- usernames are 1-32 characters: letters, digits, `.`, `_`, `-`, and may not contain `..`

`target.original` is the user's string, for the report only. Query `value`.

## RunContext

| Method | Use |
| --- | --- |
| `await ctx.get_public(url, source=self.name, min_interval=..., params=..., headers=...)` | GET, follow a few public HTTPS redirects |
| `await ctx.request(method, url, source=self.name, min_interval=...)` | One request, no redirects |
| `ctx.api_key(name)` | `str` or `None` |
| `ctx.require_api_key(name)` | `str`, or `SourceError` if unset |
| `ctx.timeout` | Per-source budget in seconds |
| `ctx.notices` | Rare, non-fatal notes for the report |

Do not construct your own `httpx.AsyncClient`. The shared client sets the
User-Agent and does not trust redirects on its own.

`params` values should be strings. Put secrets in headers when the provider
allows it. If a provider only accepts a query-string key, the error scrubber
rewrites `key=` and the known secret value. Still do not log the URL.

## Findings

```python
make_finding(
    source=self.name,
    category=Category.REPUTATION,  # or another short label
    title="Abuse confidence",
    value="0",
    detail="Optional sentence.",
    source_url="https://example.com/the-public-page",
    severity=Severity.INFO,  # info, low, medium, high
    data={"country_code": "AU"},  # strings only
)
```

`value` and `title` must be non-empty. The runner clips long text, scrubs
secrets, forces `source` to your plugin name, and recomputes `id` as the first
16 hex characters of SHA-256 over `source`, `category`, `title`, and `value`.
The timestamp is not part of the id, so the same observation stays stable.

`source_url` should be a page a human can open. Do not put an API URL that
contains a key.

Recommended categories: `dns`, `email`, `registration`, `certificate`, `http`,
`policy`, `archive`, `infrastructure`, `reputation`, `identity`, `breach`.
A new short label is allowed. Document it in the pull request.

## Entry point

```toml
[project.entry-points."reconlens.sources"]
my-source = "my_package.module:MySource"
```

The group name is `reconlens.sources`. The object must be the class, not an
instance. ReconLens constructs it with no arguments.

## Tests

Prefer a pure function (`findings_from_*(payload) -> list[Finding]`) for the
parsing, and a short async test that mocks HTTP. See `tests/test_plugins.py`.
