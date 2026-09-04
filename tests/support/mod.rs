//! Shared test support, compiled into each integration test binary that
//! declares `mod support;`. Not every binary uses every item.
#![allow(dead_code)]

pub mod audit_forwarder_conformance;
pub mod fake_vault;
pub mod rollup_store_conformance;
pub mod secret_source_conformance;
pub mod tls_syslog_receiver;
