# Ethics

ReconLens is a reading tool. The records it asks for were published so that
other people could read them: DNS, RDAP, certificate transparency, a site's own
headers and policy files, a public profile URL, a reputation API you have a key
for.

## In bounds

- One DNS question per record type, with the resolver search list disabled.
- One HTTPS request (plus a few public redirects) to a URL the source named.
- One TLS handshake to port 443, to read the certificate.
- A keyed GET against the provider's documented lookup endpoint.
- A small, curated set of public profile URLs, requested slowly, with no login.

## Out of bounds

- Connecting to ports other than 443 (and that only for the certificate source).
- Subdomain brute force, directory brute force, or password guessing.
- Submitting a URL to be crawled or scanned by someone else.
- Following a redirect to a loopback, link-local, or private address.
- Putting an API key in a log, a finding, or the terminal.

Pull requests that cross that line will be closed.

## Your responsibility

Authorization is not a flag this tool can check. If you do not have permission
to investigate a target, do not point ReconLens at it. Username hits are
especially easy to over-read: HTTP 200 means a public URL responded, not that
you have found a person.

Be polite to free services. crt.sh, the Wayback Machine, and ipwho.is will
return errors if a tool hammers them. The built-in intervals are a floor, not
an invitation to wrap the CLI in a tight loop. A batch mode, if someone adds
one, needs a global delay.

## Data you did not mean to publish

Reports can contain email addresses and usernames you typed. Do not commit them,
and do not paste a JSON report into a public issue without reading it. If a
provider's response includes more than you need, prefer a short finding over a
dump of the raw document.
