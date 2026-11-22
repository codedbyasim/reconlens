# Releasing to PyPI

Publishing uses [PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/).
The workflow at `.github/workflows/release.yml` requests an OIDC token. It does
not read a `PYPI_API_TOKEN` secret, and you do not need to create one.

## One-time setup

1. Create the PyPI project `reconlens` (the name is unused on PyPI at the time
   of the first release).
2. On PyPI, add a trusted publisher:
   - Owner: `codedbyasim`
   - Repository: `reconlens`
   - Workflow: `release.yml`
   - Environment: `pypi`
3. On GitHub, create an environment named `pypi`. You can require a reviewer.
   Do not add secrets to it.

Until that environment exists, the release workflow will wait or fail at the
environment check. That is expected.

## Cutting a release

1. Set `__version__` in `src/reconlens/version.py`.
2. Move the notes in `CHANGELOG.md` from Unreleased to `## [x.y.z] - YYYY-MM-DD`.
3. Merge to `main`.
4. Tag the same commit and push the tag:

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

The tag must be `v` plus the version string in `version.py`. The workflow
checks that before it builds. It then runs `python -m build` and
`pypa/gh-action-pypi-publish`.

The workflow is not exercised by pull requests, and it does not publish on
pushes to `main`.
