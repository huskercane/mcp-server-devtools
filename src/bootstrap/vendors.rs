//! The per-product strategy objects, constructed once per process.
//!
//! Every vendor here is a zero-cost or near-zero-cost value type (unit struct
//! or a single optional base-URL override), so holding all of them costs
//! effectively nothing even in a deployment that only uses one.
//!
//! ## Why a struct and not a positional argument list
//!
//! This replaces a 14-argument constructor that grew by one parameter per
//! integration. Adding a vendor now means adding one field with a `Default`
//! impl — no call site changes, which is the open/closed property the old
//! signature lacked. Tests override exactly the one vendor they point at a mock
//! and inherit the rest via [`Default`] and struct update syntax:
//!
//! ```ignore
//! let vendors = Vendors {
//!     jira: JiraVendor::with_base_url(mock.uri()),
//!     ..Vendors::default()
//! };
//! ```

use crate::vendor::bitbucket::BitbucketVendor;
use crate::vendor::circleci::CircleCiVendor;
use crate::vendor::confluence::ConfluenceVendor;
use crate::vendor::edx::EdxVendor;
use crate::vendor::grafana::GrafanaVendor;
use crate::vendor::jira::JiraVendor;
use crate::vendor::newrelic::NewRelicVendor;
use crate::vendor::ninjaone::NinjaOneVendor;
use crate::vendor::postman::PostmanVendor;
use crate::vendor::slack::SlackVendor;
use crate::vendor::sonarqube::SonarqubeVendor;
use crate::vendor::splunk::SplunkVendor;
#[cfg(feature = "wrds")]
use crate::vendor::wrds::WrdsVendor;
use crate::vendor::zoom::ZoomVendor;

/// Every vendor strategy object the process can dispatch to.
///
/// Deliberately **not** `#[non_exhaustive]`: integration tests live in their own
/// crates, and `#[non_exhaustive]` would forbid the `..Vendors::default()`
/// update syntax there — the exact ergonomics this type exists to provide.
/// Adding a field stays non-breaking for anyone who spreads a default.
///
/// No `Debug` derive: `WrdsVendor` holds a cached rustls `ClientConfig` and
/// does not implement it, and a dump of vendor base URLs has no diagnostic value.
pub struct Vendors {
    pub bitbucket: BitbucketVendor,
    pub jira: JiraVendor,
    pub confluence: ConfluenceVendor,
    pub zoom: ZoomVendor,
    pub circleci: CircleCiVendor,
    pub slack: SlackVendor,
    pub postman: PostmanVendor,
    pub edx: EdxVendor,
    pub newrelic: NewRelicVendor,
    pub grafana: GrafanaVendor,
    pub sonarqube: SonarqubeVendor,
    pub splunk: SplunkVendor,
    pub ninjaone: NinjaOneVendor,
    /// WRDS (`PostgreSQL`) vendor. Feature-gated: a `--no-default-features`
    /// build drops the Postgres dependency tree entirely, so this field and
    /// the `wrds_*` tools do not exist.
    #[cfg(feature = "wrds")]
    pub wrds: WrdsVendor,
}

impl Default for Vendors {
    fn default() -> Self {
        Self {
            bitbucket: BitbucketVendor::new(),
            jira: JiraVendor::new(),
            confluence: ConfluenceVendor::new(),
            zoom: ZoomVendor::new(),
            circleci: CircleCiVendor::new(),
            slack: SlackVendor::new(),
            postman: PostmanVendor::new(),
            edx: EdxVendor::new(),
            newrelic: NewRelicVendor::new(),
            grafana: GrafanaVendor::new(),
            sonarqube: SonarqubeVendor::new(),
            splunk: SplunkVendor::new(),
            ninjaone: NinjaOneVendor::new(),
            #[cfg(feature = "wrds")]
            wrds: WrdsVendor::new(),
        }
    }
}
