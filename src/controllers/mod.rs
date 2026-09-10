#![allow(clippy::doc_markdown)]

//! Controller layer. Wraps the transport with domain-specific behaviour
//! (path normalisation, JMESPath filtering, output formatting) while keeping
//! tool/CLI handlers as thin adapters.

pub mod api;
pub mod artifactory;
pub mod bitbucket_downloads;
pub mod circleci;
pub mod clone;
pub mod edx;
pub mod figma;
pub mod github;
pub mod gitlab;
pub mod grafana;
pub mod jira;
pub mod mend;
pub mod newrelic;
pub mod ninjaone;
#[cfg(feature = "ninjaone-db")]
pub mod ninjaone_db;
pub mod postman;
pub mod segment;
pub mod sentry;
pub mod slack;
pub mod snyk;
pub mod sonarqube;
pub mod splunk;
pub mod teamcity;
pub mod upload;
pub mod vercel;
#[cfg(feature = "wrds")]
pub mod wrds;
pub mod zoom;

pub use api::{BitbucketContext, ControllerResponse, HandleContext, handle_request};
pub use bitbucket_downloads::upload_downloads;
pub use circleci::CircleCiContext;
pub use clone::handle_clone;
pub use edx::EdxContext;
pub use grafana::GrafanaContext;
pub use newrelic::NewRelicContext;
pub use ninjaone::NinjaOneContext;
pub use postman::PostmanContext;
pub use slack::SlackContext;
pub use sonarqube::SonarqubeContext;
pub use splunk::SplunkContext;
#[cfg(feature = "wrds")]
pub use wrds::WrdsContext;
pub use zoom::ZoomContext;

pub(crate) mod download;

pub(crate) mod paged;
