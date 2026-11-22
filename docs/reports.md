# Reports

Schema **1.0.0** is checked in as [report.schema.json](report.schema.json).
1.x readers accept any `1.*` document. A future `2.0.0` may break field names.

## Top level

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | `1.x.y` |
| `tool` | object | `name` is always `reconlens`, plus `version` |
| `target` | object | `value`, `type` (`domain`, `ip`, `email`, `username`), `original` |
| `started_at`, `finished_at` | string | UTC `YYYY-MM-DDTHH:MM:SSZ` |
| `elapsed_ms` | integer | Derived from the two timestamps |
| `summary` | object | `sources_ok`, `sources_skipped`, `sources_error`, `findings` |
| `notices` | string array | Loader or cache notes. Not findings |
| `sources` | array | One object per source that was selected |

## Source object

| Field | Type |
| --- | --- |
| `name` | string |
| `status` | `ok`, `error`, or `skipped` |
| `duration_ms` | integer |
| `cached` | boolean |
| `error` | string or null |
| `skip_reason` | string or null |
| `findings` | array |

Findings are nested under the source that produced them. Flatten with
`source["name"]` ignored in favor of each finding's own `source` field; they
match.

## Finding object

| Field | Type |
| --- | --- |
| `id` | 16 hex chars. Stable for the same source, category, title, and value |
| `source`, `category`, `title`, `value` | strings |
| `detail`, `source_url` | string or null |
| `severity` | `info`, `low`, `medium`, `high` |
| `timestamp` | UTC timestamp of the observation |
| `data` | object of strings |

`reconlens report --input report.json --output html --out report.html` renders
a saved document again. The terminal view truncates a source after 40 findings
and tells you to use JSON for the rest. The file formats keep every finding.

HTML is escaped. Links are emitted only for `http` and `https` URLs, so a
finding cannot become a `javascript:` link.
