//! Shared test support, compiled into each integration test binary that
//! declares `mod support;`. Not every binary uses every item.
#![allow(dead_code)]

pub mod fake_vault;
pub mod secret_source_conformance;
