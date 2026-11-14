# jwt-audit

jwt-audit decodes JWTs (it does not verify signatures) and flags the mistakes that turn tokens into vulnerabilities: `alg: none`, `jku`, `x5u` and embedded `jwk` headers that let an attacker choose the verification key, suspicious `kid` values, tokens that never expire or live for weeks, missing audience and issuer, and sensitive data stored in the payload. Token values and claim values are never printed.

**Live demo:** https://jvch0512.github.io/jwt-audit/ (Tokens built from invented claims and a fake signature.)

Rust 2021, no dependencies. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
cargo build --release
./target/release/jwt-audit examples/tokens.txt --now 1763100000
./target/release/jwt-audit tokens.txt --tsv
grep -rhoE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' logs/ | ./target/release/jwt-audit - --fail-on high
```

One token per line, `-` reads standard input. `--now` takes a Unix time so reports are reproducible.

| Rule | Severity | What it catches |
|---|---|---|
| JWT001 | critical | `alg` is `none` (any case) or missing |
| JWT002 | high | `jku`, `x5u` or `jwk` header: the token chooses its own verification key |
| JWT003 | high | `kid` with path, SQL or shell characters (`../`, `/`, `'`, `;`, `\|`) |
| JWT004 | high | no `exp`, or lifetime above 30 days |
| JWT005 | medium | lifetime above 24 hours, or already expired at `--now` |
| JWT006 | medium | HMAC algorithm (HS256, HS384, HS512): shared secret, weak keys can be brute forced offline |
| JWT007 | medium | no `aud` or no `iss` claim |
| JWT008 | high | claim names that look like secrets: password, secret, api_key, token, ssn, card |
| JWT009 | info | token could not be decoded |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- Signatures are not checked. A clean report means the token is well formed, not that your verifier is correct.
- Lifetime needs `iat`. Without it, only the absence of `exp` and expiry at `--now` can be judged.
- Claim names are matched by substring. Values are never inspected, stored or printed.
- JSON is parsed by a small built-in parser with a depth limit; non-standard JSON is reported as undecodable.

## Where it fits

Appsec reviews, API pentest write-ups and token hygiene checks: a quick, safe way to triage tokens found in logs or captured in tests without leaking their contents.

## Tests

```bash
cargo test --release    # 16 integration tests
```

MIT.
