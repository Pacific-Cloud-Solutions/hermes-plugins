# pcs-security-web-headers

Read-only audit of HTTP security headers declared in local web server
configuration. One tool: `web_headers`.

Part of the Pacific Cloud Solutions security suite. **Self-contained**: it bundles the
suite's finding contract and provenance/taint model in `_contract/`, so this one plugin
installs and runs on its own. The shared [`pcs-security-core`](../pcs-security-core)
plugin is used automatically when it is present, and is not required.

**This plugin installs clean.** It names no artifact the install scanner treats as
hostile vocabulary, so it needs no declared-audit-intent signal.

## What it checks

| ID | Check |
|---|---|
| `HDR-001` | HSTS not declared on a server that serves TLS (HIGH) |
| `HDR-002` | HSTS `max-age` below 180 days, or no `includeSubDomains` |
| `HDR-003` | No `Content-Security-Policy` |
| `HDR-004` | A CSP weakened by `unsafe-inline`, `unsafe-eval`, `*`, `data:` or `http:` |
| `HDR-005` | `X-Content-Type-Options` missing or not `nosniff` |
| `HDR-006` | Neither `X-Frame-Options` nor a CSP `frame-ancestors` (clickjacking) |
| `HDR-007` | `Referrer-Policy` missing or `unsafe-url` |
| `HDR-008` | Server advertises its version (`server_tokens on`, `ServerTokens Full`) |
| `HDR-009` | No `Permissions-Policy` (INFO, opt-in) |
| `HDR-010` | **A `location` block's own `add_header` silently discards every inherited header** (HIGH) |

## Install

```bash
hermes plugins install pcs-security-web-headers
```

That is the whole install. The contract the tool returns findings in travels inside the
plugin, so there is no dependency to install first and nothing to install in order.

If you install [`pcs-security-core`](../pcs-security-core) alongside it — which the
[pack](../../pcs-security-guard.yaml) does — the shared copy is used instead of the
bundled one, so the whole suite shares a single contract instance and one set of
host-level registrations. Either way the report is identical: `scripts/vendor_contract.py`
copies core's modules byte-for-byte into `_contract/`, and `--check` fails the build if
the two ever diverge. Bundled `__init__.py` included, because it carries the
prompt-section text and the redaction patterns — a hand-edit there would change
host-level behaviour without touching core.

## Usage

```
web_headers                   # audit the running host
web_headers root=/mnt/suspect  # audit a mounted filesystem
web_headers include_info=true  # also report the optional headers
```

## Why configuration, and not the live response

This reads **declared** configuration. It does not fetch a page, follow a proxy,
or open a socket.

That is not a shortcut — it is the better source for this job. Configuration
covers **every route** of every site on the host; a fetched response tells you
about exactly one URL of one site, at one moment, and requires a network
connection this suite does not make. It is also where a fix belongs: a finding
that cites `sites-enabled/example.conf line 12` is one the operator can act on
directly.

The tradeoff is stated in every report: a header added by **application code**
rather than by the web server is invisible here, and so is anything injected by a
CDN or edge layer.

## `HDR-010` is the reason this plugin parses blocks instead of lines

nginx's `add_header` **does not accumulate across levels**. A block that declares
*any* `add_header` of its own inherits **none** from its parents. So:

```nginx
server {
    listen 443 ssl;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    location /assets {
        add_header Cache-Control "public, max-age=3600";   # ← drops BOTH headers above
    }
}
```

Every header the site cares about is gone for `/assets`, and **every name-based
header scan still finds them in the `server` block and reports the site as
protected.** This is the most common way a site looks hardened and is not, and it
is invisible to any check that greps for a header's name. Finding it requires
parsing block structure — which is why this plugin does.

## Three more things that are easy to get wrong

**HSTS is only meaningful over TLS.** Reporting a missing HSTS header on a
plaintext listener is noise, so `HDR-001` is scoped to server blocks that
actually declare TLS (`listen … ssl`, `ssl_certificate`, `SSLEngine on`). A
plaintext server is recorded as a **skip with that reason**, not as a pass.

**`Header set` and `Header always set` are not the same.** Without `always`, the
header is not applied to error responses — so a 500 page is served without the
protections the rest of the site has. This is recorded as a coverage note rather
than silently treated as equivalent.

**A policy that names `unsafe-inline` is mostly decorative.** A CSP permitting
inline script still allows the injection it exists to prevent. Naming the
directive is not the same as enforcing it — and `*` in a `script-src` allows any
origin at all.

## Scope and limitations

Stated in `coverage.limitations` on every report:

- application-added headers are invisible (only web server configuration is read);
- `include` / proxy targets on other hosts are not followed;
- templating layers are not evaluated;
- single-line block syntax (`location / { add_header X Y; }`) is not decomposed;
- this does not test a URL, so it cannot prove a header is *actually sent*.

## Why nothing is `Provenance.LOCAL`

Every value read off disk is quarantined as `UNTRUSTED`, including header values
and server names. A `server_name` directive is attacker-influenced text on any
host that answers for arbitrary Host headers, and it lands in this tool's output.
The model is uniform by design: the boundary is "did this come from a file", not
"does it look trustworthy".