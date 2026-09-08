//! Community mutation-gate selection. Unsupported adapters fail closed.
use std::{sync::Arc, time::Duration};

use crate::config::Config;
use crate::ports::{AuditSink, DirectGate, MutationGate, ProposalRegistry};

/// Config key selecting the adapter.
pub const APPROVALS_KEY: &str = "MCP_ADMIN_APPROVALS";
/// Config key: how long a proposal stays approvable. Default one day.
pub const APPROVAL_TTL_KEY: &str = "MCP_ADMIN_APPROVAL_TTL_SECONDS";
pub const DEFAULT_APPROVAL_TTL: Duration = Duration::from_hours(24);
/// The longest TTL accepted: thirty days.
pub const MAX_APPROVAL_TTL: Duration = Duration::from_hours(30 * 24);

/// Whether `MCP_ADMIN_APPROVALS` asks for two-person approval, read the
/// way [`gate_from_config`] reads it. For settings that must not be
/// combined with it (`MCP_ADMIN_PRINCIPALS=any`), so the refusal happens at
/// startup and not on the first proposal.
#[must_use]
pub fn required(config: &Config) -> bool {
    config
        .get(APPROVALS_KEY)
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("required"))
}

/// What the configuration selected.
pub struct Selected {
    pub gate: Arc<dyn MutationGate>,
    /// Present when the gate keeps proposals.
    pub proposals: Option<Arc<dyn ProposalRegistry>>,
}

/// Build the gate the configuration names.
///
/// # Errors
///
/// A message naming the key and the value at fault.
pub fn gate_from_config(
    config: &Config,
    _audit_sink: Option<&Arc<dyn AuditSink>>,
    _append_timeout: Duration,
) -> Result<Selected, String> {
    let value = config
        .get(APPROVALS_KEY)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match value.map(str::to_ascii_lowercase).as_deref() {
        None | Some("off") => Ok(Selected {
            gate: Arc::new(DirectGate),
            proposals: None,
        }),
        Some("required") => Err(format!(
            "{APPROVALS_KEY}=required requires the Enterprise approval adapter"
        )),
        Some(other) => Err(format!(
            "{APPROVALS_KEY}: unknown value {other:?} (expected `off` or `required`)"
        )),
    }
}
