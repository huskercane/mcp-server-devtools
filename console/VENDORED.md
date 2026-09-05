# Vendored console assets

The console ships exactly one third-party file (ADR-007). It is embedded
into the binary with `rust-embed`; `tests/console_tests.rs` hashes the
embedded bytes against the digest recorded here, so a replacement that
was not reviewed and re-recorded fails CI.

| File | Project | Version | Source | SHA-256 |
|---|---|---|---|---|
| `static/htmx.min.js` | htmx (BSD-2-Clause, `https://github.com/bigskysoftware/htmx`) | 4.0.0 | `https://unpkg.com/htmx.org@4.0.0/dist/htmx.min.js`, fetched 2026-09-05 | `e484d9171a9db30a39c8f16e3d709d4137f3211c659f8e6125816635033d593f` |

Size: 36,716 bytes.

## What the build was checked for (2026-09-05)

- No `eval(` and no `Function(` anywhere in the file: htmx 4.0.0 has no
  code-evaluation path, so ADR-007's `htmx.config.allowEval = false` is
  satisfied by construction (the 4.x configuration has no such key; the
  test asserts the absence of both strings rather than a setting). The
  console uses no `hx-on:` attribute; the strict CSP (`script-src
  'self'`, no `'unsafe-eval'`) would refuse one at runtime regardless.
- No `localStorage` / `sessionStorage`: nothing the console renders is
  written to the browser's storage by the library. `history` is set to
  `false` in the embedded configuration anyway.
- Indicator styles: htmx 4 installs its `.htmx-indicator` rules through a
  constructed stylesheet unless `includeIndicatorCSS` is `false`; the
  console sets it `false` and carries those rules in `static/console.css`,
  so the page's `style-src 'self'` describes everything that styles it.
- Configuration is read from `<meta name="htmx-config">` in the base
  template; the console sets `{"includeIndicatorCSS":false,"history":false}`.

## Updating

1. Fetch the new build from the release (pin the exact version).
2. Re-check the list above against the new source.
3. Record the version, source, size, and `sha256sum` here, and update
   the plan's ADR-007 note if the major version changes.
4. `cargo test --features console` — the digest test is the gate.
