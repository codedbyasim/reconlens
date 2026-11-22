# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/codedbyasim/reconlens/security/advisories/new).
Do not open a public issue for a security report, and do not include API keys,
access tokens, or data about targets you are not comfortable sharing.

We will acknowledge reports that we can reproduce, and we will coordinate a fix
before discussing the details in public.

## What this tool is

ReconLens is passive. It queries public records and read-only APIs. It does not
scan ports, brute-force names, bypass authentication, or attempt logins.

Using it against systems you do not own and are not authorized to assess can
still be unlawful. The maintainers are not your authorization.

## Secrets

API keys are read from the environment or a config file and are scrubbed from
errors and findings. Treat `reconlens.toml` like a password file (`chmod 600`).
If a key appears in a log, an issue, or a report you shared, rotate it.
