//! Select the [`MutationGate`] adapter (plan §3.10.1, WP D.0; §3.10.3, WP D.2).
//!
//! The only place `MCP_ADMIN_APPROVALS` and `MCP_ADMIN_APPROVAL_TTL_SECONDS`
//! are read. Unset or `off` selects [`DirectGate`], the behaviour the admin
//! boundary always had. `required` selects [`ApprovalGate`], which needs
//! the durable journal (its proposals are journal records) and rebuilds
//! its pending set from `MCP_AUDIT_JOURNAL_DIR` at startup; without a
//! journal it is a typed refusal, so an operator who asks for approvals
//! never runs ungated by accident.

use std::{sync::Arc, time::Duration};

use crate::approvals::ApprovalGate;
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
    audit_sink: Option<&Arc<dyn AuditSink>>,
    append_timeout: Duration,
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
        Some("required") => {
            let sink = audit_sink.ok_or_else(|| {
                format!(
                    "{APPROVALS_KEY}=required: two-person approval records proposals in the durable \
                     audit journal, and none is configured (set {}, plan §3.10.3)",
                    super::AUDIT_JOURNAL_DIR_KEY
                )
            })?;
            let ttl = approval_ttl(config)?;
            let gate = match super::configured_journal_dir(config) {
                Some(dir) => ApprovalGate::open(
                    Arc::clone(sink),
                    append_timeout,
                    ttl,
                    dir.as_ref(),
                )
                .map_err(|error| {
                    format!(
                        "{APPROVALS_KEY}=required: cannot rebuild pending proposals from the \
                             journal in {}={dir}: {error}",
                        super::AUDIT_JOURNAL_DIR_KEY
                    )
                })?,
                None => ApprovalGate::new(Arc::clone(sink), append_timeout, ttl),
            };
            let gate = Arc::new(gate);
            tracing::info!(pending = gate.pending(), "two-person approval required");
            Ok(Selected {
                proposals: Some(gate.clone()),
                gate,
            })
        }
        Some(other) => Err(format!(
            "{APPROVALS_KEY}: unknown value {other:?} (expected `off` or `required`)"
        )),
    }
}

fn approval_ttl(config: &Config) -> Result<Duration, String> {
    let Some(value) = config
        .get(APPROVAL_TTL_KEY)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(DEFAULT_APPROVAL_TTL);
    };
    match value.parse::<u64>() {
        Ok(seconds) if seconds >= 1 && seconds <= MAX_APPROVAL_TTL.as_secs() => {
            Ok(Duration::from_secs(seconds))
        }
        _ => Err(format!(
            "{APPROVAL_TTL_KEY}: expected whole seconds from 1 to {} (got {value:?})",
            MAX_APPROVAL_TTL.as_secs()
        )),
    }
}
