//! The adapter conformance suite (plan §3.8, §3.9): the same behavioural
//! assertions against every `SecretSource` adapter, so a new adapter is
//! proven by running the existing suite rather than by writing a new one.

use std::sync::Arc;

use mcp_server_devtools::ports::{Scheme, SecretLocator, SecretSource, SecretSourceError};

/// How a test writes a document behind an adapter.
pub trait Fixture {
    fn source(&self) -> Arc<dyn SecretSource>;
    fn put(&self, target: &str, document: &str);
    fn remove(&self, target: &str);
    fn target(&self, name: &str) -> String;
    fn scheme(&self) -> Scheme {
        Scheme::File
    }
    /// What `document` comes back as. A file adapter returns the bytes it
    /// was given; a key-value adapter wraps them in its document shape.
    fn fetched_form(&self, document: &str) -> String {
        document.to_owned()
    }
}

pub async fn conformance(fixture: &dyn Fixture) {
    let source = fixture.source();
    assert_eq!(source.scheme(), fixture.scheme());
    let target = fixture.target("token");
    let locator = SecretLocator::new(fixture.scheme(), target.clone());

    // Absent → NotFound, naming the locator, never anything else.
    let missing = source.fetch(&locator).await.unwrap_err();
    assert!(
        matches!(missing, SecretSourceError::NotFound { .. }),
        "{missing:?}"
    );
    assert!(missing.to_string().contains(&locator.to_string()));

    // Present → the document, with a version.
    fixture.put(&target, "secret-v1\n");
    let first = source.fetch(&locator).await.unwrap();
    assert_eq!(first.document(), fixture.fetched_form("secret-v1\n"));
    assert!(!first.version().is_empty());
    assert!(
        !format!("{first:?}").contains("secret-v1"),
        "Debug leaks the document"
    );

    // Same bytes → same version; new bytes → new version.
    let again = source.fetch(&locator).await.unwrap();
    assert_eq!(again.version(), first.version());
    fixture.put(&target, "secret-v2\n");
    let second = source.fetch(&locator).await.unwrap();
    assert_eq!(second.document(), fixture.fetched_form("secret-v2\n"));
    assert_ne!(second.version(), first.version());

    // Removed → NotFound again (a rotation that deleted the document is a
    // refresh failure, not a value of "").
    fixture.remove(&target);
    assert!(matches!(
        source.fetch(&locator).await.unwrap_err(),
        SecretSourceError::NotFound { .. }
    ));
}
