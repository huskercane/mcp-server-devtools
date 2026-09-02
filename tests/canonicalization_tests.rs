//! §3.5 canonicalization: the fuzz invariants on stable, in CI (WP A.6 /
//! A.10).
//!
//! `fuzz/fuzz_targets/canonicalize.rs` runs `policy::canonical::invariants`
//! under libFuzzer, which needs nightly. This test runs the **same** checker
//! over a seeded pseudo-random corpus built from the fragments an attacker
//! would reach for (dot segments in every encoding, doubled escapes, mixed
//! separators, control bytes, non-ASCII), plus a hand-written regression
//! table, so every CI run on the pinned stable toolchain exercises the
//! invariants too.

use mcp_server_devtools::policy::canonical::invariants;
use mcp_server_devtools::policy::{CanonicalPath, CanonicalTarget, CanonicalizeError};

/// Deterministic xorshift64* — no dependency, reproducible failures.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let index = usize::try_from(self.next() % items.len() as u64).unwrap_or(0);
        &items[index]
    }
}

const FRAGMENTS: &[&str] = &[
    "/",
    "//",
    ".",
    "..",
    "/./",
    "/../",
    "%2e",
    "%2E",
    "%2e%2e",
    "%2E%2E",
    "%2f",
    "%2F",
    "%252e",
    "%25",
    "%",
    "%2",
    "%zz",
    "%C3%A9",
    "\u{e9}",
    " ",
    "%20",
    "+",
    "?",
    "&",
    "=",
    "#",
    "@",
    ":",
    "~",
    "%7e",
    "a",
    "PLAT-1",
    "rest",
    "api",
    "3",
    "issue",
    "search",
    "jql",
    "\\",
    "\"",
    "<",
    "\u{0}",
    "\n",
    "\u{7f}",
    "http://",
    "https://evil",
    "//host",
    "x=1",
    "jql=project+%3D+A",
];

#[test]
fn seeded_corpus_satisfies_every_invariant() {
    let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
    let mut input = String::new();
    for _ in 0..40_000 {
        input.clear();
        let pieces = 1 + rng.next() % 12;
        for _ in 0..pieces {
            input.push_str(rng.pick(FRAGMENTS));
        }
        invariants::check(&input);
    }
}

#[test]
fn regression_table() {
    let cases: &[(&str, Result<&str, CanonicalizeError>)] = &[
        ("/rest/api/3/issue/PLAT-1", Ok("/rest/api/3/issue/PLAT-1")),
        ("rest/api/3/issue/PLAT-1/", Ok("/rest/api/3/issue/PLAT-1/")),
        ("rest/api/3/issue/PLAT-1//", Ok("/rest/api/3/issue/PLAT-1/")),
        ("/a/../../b", Ok("/b")),
        ("/a/b/..", Ok("/a/")),
        ("/a/%2e%2e/%2e%2e/b", Ok("/b")),
        ("/a/%2E%2E%2Fb", Ok("/a/..%2Fb")),
        ("/a/%252e%252e/b", Ok("/a/%252e%252e/b")),
        (
            "/refs/branches/feature%2fx",
            Ok("/refs/branches/feature%2Fx"),
        ),
        ("/caf\u{e9}", Ok("/caf%C3%A9")),
        ("/a b/c", Ok("/a%20b/c")),
        ("/a/b#frag", Ok("/a/b")),
        ("/a/b?x=1", Ok("/a/b")),
        ("/%7e/%41", Ok("/~/A")),
        (
            "https://evil.example/x",
            Err(CanonicalizeError::AbsoluteUrl),
        ),
        ("//evil.example/x", Ok("/evil.example/x")),
        ("/a/%zz", Err(CanonicalizeError::InvalidPercentEncoding)),
        ("/a/%2", Err(CanonicalizeError::InvalidPercentEncoding)),
        ("/a\u{0}", Err(CanonicalizeError::ControlCharacter)),
        ("/a\r\nHost: evil", Err(CanonicalizeError::ControlCharacter)),
    ];
    for (input, expected) in cases {
        let actual = CanonicalPath::parse(input).map(CanonicalPath::into_string);
        assert_eq!(
            actual.as_deref().map_err(|error| *error),
            *expected,
            "input {input:?}"
        );
        invariants::check(input);
    }
}

#[test]
fn query_pairs_are_decoded_sorted_and_reencoded_for_the_wire() {
    let target = CanonicalTarget::parse(
        "/rest/api/3/search/jql?maxResults=10&jql=project+%3D+PLAT+AND+text+~+%22a%26b%22&fields=summary",
    )
    .unwrap();
    assert_eq!(
        target.query_pairs(),
        vec![
            ("fields", "summary"),
            ("jql", "project = PLAT AND text ~ \"a&b\""),
            ("maxResults", "10"),
        ]
    );
    let wire = target.url_under("https://x.atlassian.net");
    assert_eq!(
        wire,
        "https://x.atlassian.net/rest/api/3/search/jql?fields=summary&jql=project+%3D+PLAT+AND+text+%7E+%22a%26b%22&maxResults=10"
    );
    // The wire form is itself canonical.
    let again = CanonicalTarget::parse(&wire["https://x.atlassian.net".len()..]).unwrap();
    assert_eq!(again, target);
}
