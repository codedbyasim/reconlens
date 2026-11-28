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

## CSV and JSON Lines

`--output csv` writes one row per finding. The columns, in order, are
`source,category,severity,title,value,detail,source_url,timestamp,id`. Every
field is quoted, the file is UTF-8, and it ends with a newline. Cells that start with `=`, `+`, `-`, `@`, a tab, or a carriage return get a
leading single quote so spreadsheets do not run them as formulas. Missing `detail`
and `source_url` values are empty strings. The `data` object is not included;
use JSON for it.

`--output jsonl` writes one compact JSON object per line. Each object has the
finding fields from schema 1.x (`id`, `source`, `category`, `title`, `value`,
`detail`, `severity`, `source_url`, `timestamp`, `data`) preceded by `target`
and `target_type`. U+2028 and U+2029 are written as `\u2028` and `\u2029` escapes, so every line is
one physical line. Every line parses with `json.loads`. The report is buffered
and then written, so lines appear after all sources finish.

Neither format changes the JSON schema. `reconlens report --input report.json
--output csv` and `--output jsonl` convert a saved report.

HTML is escaped. Links are emitted only for `http` and `https` URLs, so a
finding cannot become a `javascript:` link.

## Batch document

`reconlens batch FILE --type domain|ip|email|username --output json` writes a
JSON **array** of report objects, one per valid target, in file order. Each
element is a normal schema 1.x report. The array itself is not a report and has
no schema version. Skipped lines are listed on stderr, not in the array.

## Diff document

`reconlens diff --before a.json --after b.json --output json` writes
`{"added": [...], "removed": [...], "severity_changed": [...]}`. Each entry has
`id`, `source`, `title`, `value`, and `severity`. Severity changes add `before`
and `after`. Findings are matched on `id`.
