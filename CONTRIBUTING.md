# Contributing to ReconLens

Thanks for looking. ReconLens stays useful if new sources are small, passive,
and tested without the network.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ground rules

- Passive only. No port scans, no wordlists, no login attempts, no authentication bypass.
- Do not submit a target to a service that will actively fetch or scan it.
  urlscan search is in bounds. `POST /api/v1/scan/` is not.
- One failing source must not fail the run. Raise `SourceError` for a problem
  that belongs to your source.
- Do not log API keys. Read them from the environment or config with
  `ctx.require_api_key`. The runner scrubs known secrets, and that is a backstop,
  not a design.
- Rate-limit yourself. Set `min_interval_seconds`. Talk to upstreams the way you
  would want a stranger's tool to talk to your API.
- Tests use `respx` (or a fake DNS resolver). CI has no live network.

## Set up

```bash
git clone https://github.com/codedbyasim/reconlens.git
cd reconlens
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
make ci
```

`make ci` is ruff, the format check, mypy, and pytest with a coverage floor.
Pre-commit is optional:

```bash
pip install pre-commit
pre-commit install
```

## Write your first plugin in 10 minutes

You will add a source that GETs one public HTTPS URL and returns one finding.

1. Copy the template.

   ```bash
   cp src/reconlens/plugins/_template.py src/reconlens/plugins/ipwho_asn.py
   ```

2. Rename the class and fill in the metadata. `name` is the CLI name: lowercase
   words and hyphens, two characters or more. `target_types` says which
   commands may run it. `min_interval_seconds` is the gap between this source's
   HTTP calls. `display_order` controls the report (lower comes first).

3. Implement `run`. Use `ctx.get_public` so redirects stay on public HTTPS
   hosts. Build the finding with `make_finding`. A negative result should still
   be a finding ("not found"), not an empty list, when the user needs to see
   that you looked.

4. Register it in two places that must stay in sync:

   `pyproject.toml`:

   ```toml
   [project.entry-points."reconlens.sources"]
   ipwho-asn = "reconlens.plugins.ipwho_asn:IpwhoAsnSource"
   ```

   `BUILTIN_PATHS` in `src/reconlens/plugins/registry.py` (the fallback used when
   the package is imported without being installed). The entry-point name and
   `Source.name` must match. A test fails if they drift.

   A third-party package only needs the entry point. It does not edit
   `BUILTIN_PATHS`.

5. Reinstall so the entry point is visible, then list it.

   ```bash
   python -m pip install -e . --no-deps
   reconlens sources
   ```

6. Add `tests/test_ipwho_asn.py`. Mock the URL with `respx`. Do not call the
   real host.

   ```python
   import httpx
   import pytest

   from reconlens.models import Target, TargetType
   from reconlens.plugins.ipwho_asn import IpwhoAsnSource

   async def test_ipwho_asn(ctx, mocked):
       mocked.get("https://example.com/api").mock(
           return_value=httpx.Response(200, json={"result": "AS1"})
       )
       findings = await IpwhoAsnSource().run(
           Target("example.com", TargetType.DOMAIN, "example.com"), ctx
       )
       assert findings[0].value == "AS1"
   ```

   The `ctx` fixture in `tests/conftest.py` is an HTTP client inside a mock that
   rejects unexpected requests.

7. Run `make ci`. Update the source table in `README.md` and, if the behavior
   is user-visible, `CHANGELOG.md` under Unreleased.

8. Open a pull request. The template asks you to confirm the change is passive.

That is the whole contract. The longer version is [docs/plugin-api.md](docs/plugin-api.md).

## Adding a username site

Edit `src/reconlens/data/username_sites.json`. `{username}` appears once, in the
path or query, on an `https` URL. Prefer a public page that returns 404 for a
missing account. Do not add a site that requires a login. Optional
`missing_body_contains` marks a 200 as absent when the body contains that text.

## Reports and docs

- JSON field changes need a schema bump discussion. 1.x may add fields; it may
  not rename or retype existing ones. Update `docs/report.schema.json` and
  `docs/reports.md`.
- `mkdocs serve` previews the docs. Install the `docs` extra first.

## Reviews

We will ask for a test when a source talks to the network, and we will ask you
to drop anything that is not passive. Small pull requests are easier to merge
than a plugin bundled with a new output format and a cache rewrite.
