//! Locks the crate's outbound HTTP boundary: `reqwest` is named by exactly
//! one module, `src/transport/client.rs`. Everything else sees the
//! transport-owned `HttpClient` / `HttpResponse` / `HttpError` facade and
//! `http` types, so swapping the adapter (for hyper, say) is a change to
//! that one file rather than to fifty.
//!
//! An architectural test rather than a clippy `disallowed-types` entry
//! because the integration tests legitimately use `reqwest` as their
//! wiremock client, and `clippy.toml` cannot scope a ban to `src/`.

use std::fs;
use std::path::{Path, PathBuf};

const ADAPTER: &str = "src/transport/client.rs";

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("readable source directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// A `reqwest` mention that is not inside a `//` comment on its line. Prose
/// may explain history ("used to be a direct `reqwest` call"); code may not
/// name the crate.
fn names_reqwest_in_code(line: &str) -> bool {
    let Some(at) = line.find("reqwest") else {
        return false;
    };
    line.find("//").is_none_or(|comment| comment > at)
}

#[test]
fn reqwest_is_named_only_by_the_transport_adapter() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    rust_sources(&root.join("src"), &mut sources);
    assert!(
        sources.iter().any(|path| path.ends_with(ADAPTER)),
        "the adapter module {ADAPTER} must exist"
    );

    let mut leaks = Vec::new();
    for path in &sources {
        if path.ends_with(ADAPTER) {
            continue;
        }
        let text = fs::read_to_string(path).expect("readable source file");
        for (index, line) in text.lines().enumerate() {
            if names_reqwest_in_code(line) {
                let relative = path.strip_prefix(root).unwrap_or(path).display();
                leaks.push(format!("{relative}:{}: {}", index + 1, line.trim()));
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "`reqwest` reached code outside {ADAPTER}; route it through \
         `crate::transport::HttpClient` instead:\n{}",
        leaks.join("\n")
    );
}

#[test]
fn comment_mentions_are_not_leaks() {
    assert!(!names_reqwest_in_code(
        "    // a direct `reqwest` call once lived here"
    ));
    assert!(!names_reqwest_in_code(
        "/// A reqwest error can quote the URL"
    ));
    assert!(names_reqwest_in_code(
        "    client: reqwest::Client, // pooled"
    ));
    assert!(names_reqwest_in_code("use reqwest::StatusCode;"));
}
