//! Select the [`MutationGate`] adapter (plan §3.10.1, WP D.0).
//!
//! The only place `MCP_ADMIN_APPROVALS` is read. Unset or `off` selects
//! [`DirectGate`], the behaviour the admin boundary always had. `required`
//! names the two-person approval adapter, which WP D.2 builds; until then
//! it is a typed refusal at startup — the same shape as a reserved secret
//! scheme or `postgres://` — so an operator who sets it never runs
//! ungated by accident.

use std::sync::Arc;

use crate::config::Config;
use crate::ports::{DirectGate, MutationGate};

/// Config key selecting the adapter.
pub const APPROVALS_KEY: &str = "MCP_ADMIN_APPROVALS";

/// Build the gate the configuration names.
///
/// # Errors
///
/// A message naming the key and the value at fault.
pub fn gate_from_config(config: &Config) -> Result<Arc<dyn MutationGate>, String> {
    let value = config
        .get(APPROVALS_KEY)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match value.map(str::to_ascii_lowercase).as_deref() {
        None | Some("off") => Ok(Arc::new(DirectGate)),
        Some("required") => Err(format!(
            "{APPROVALS_KEY}=required: no approval adapter is compiled into this binary \
             (two-person approval is scoped as WP D.2, plan §3.10.3); unset it or set `off`"
        )),
        Some(other) => Err(format!(
            "{APPROVALS_KEY}: unknown value {other:?} (expected `off` or `required`)"
        )),
    }
}
