//! Enforcement at the egress chokepoint, and the bounded audit append every
//! enforcement point uses (WP A.7; carry-forward CF-14).
//!
//! ## Egress
//!
//! Plan §1.3: a tool name is a label; the HTTP request the vendor client is
//! about to send is the fact. The transport calls [`authorize_egress`] with
//! the canonical target it is about to put on the wire. Inside an enforcing
//! call scope, the request is classified by the vendor's extractor, joined
//! with the scope's principal and upstream identity into an
//! [`ActionContext`], and evaluated. A denial is journaled (so the journal
//! holds the decision *and* the canonical request it was about) and the
//! request is not sent. Outside a call scope, or under a decision point that
//! does not enforce, this is one task-local lookup and a return.
//!
//! An egress *allow* is not journaled separately: the tool-level intent
//! record already carries the allow decision and policy version, and the
//! outcome record proves the dispatch happened. Journaling every egress
//! allow would double the fsync cost of a call for no new fact.
//!
//! ## Bounded append (CF-14)
//!
//! `AuditSink::append` waits for durable acknowledgement, which on a
//! stalled disk is unbounded. [`append_bounded`] caps that wait. The
//! decision, recorded here because it is a semantic one and not a
//! one-liner: on timeout the **call is refused** (fail closed; the vendor
//! is never contacted), and the record that was already queued may still be
//! written later by the journal's writer thread. That is acceptable because
//! of what the two record kinds mean — an intent record proves a call was
//! requested and authorized; only the *outcome* record proves it was
//! dispatched. An intent with no outcome is therefore "requested, not
//! dispatched", which is exactly the state a timed-out call is in. The
//! caller sees a fixed refusal, not the transport's own timeout.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::error::McpError;
use crate::ports::audit_sink::{AppendFuture, AuditEvent, AuditEventKind, AuditFailure, AuditSink};
use crate::ports::policy_decision_point::PolicyDecisionPoint;
use crate::transport::HttpMethod;

use super::canonical::CanonicalTarget;
use super::scope::CallScope;
use super::{ActionContext, PolicyDecision, UpstreamIdentity, extractors};

/// Config key: how long an audit append may wait for durable acknowledgement
/// before the call is refused. Milliseconds; default 5000, clamped to
/// 100–60000.
pub const AUDIT_APPEND_TIMEOUT_KEY: &str = "MCP_AUDIT_APPEND_TIMEOUT_MS";
pub const DEFAULT_AUDIT_APPEND_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_AUDIT_APPEND_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_AUDIT_APPEND_TIMEOUT: Duration = Duration::from_mins(1);

/// Read the append timeout from configuration, clamped to a sane range.
#[must_use]
pub fn audit_append_timeout(config: &crate::config::Config) -> Duration {
    config
        .get(AUDIT_APPEND_TIMEOUT_KEY)
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_millis)
        .map_or(DEFAULT_AUDIT_APPEND_TIMEOUT, |timeout| {
            timeout.clamp(MIN_AUDIT_APPEND_TIMEOUT, MAX_AUDIT_APPEND_TIMEOUT)
        })
}

/// What a call scope carries so the egress chokepoint can decide and record.
pub struct Enforcement {
    pub policy: Arc<dyn PolicyDecisionPoint>,
    pub audit: Arc<dyn AuditSink>,
    pub upstream: UpstreamIdentity,
    pub append_timeout: Duration,
}

impl std::fmt::Debug for Enforcement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Enforcement")
            .field("policy_version", &self.policy.version())
            .field("upstream", &self.upstream)
            .field("append_timeout", &self.append_timeout)
            .finish_non_exhaustive()
    }
}

/// Append with a bound on the durable-acknowledgement wait. See the module
/// docs for what a timeout means.
///
/// # Errors
///
/// The sink's error, or `TimedOut` when the bound elapsed first.
pub fn append_bounded<'a>(
    sink: &'a dyn AuditSink,
    event: &'a AuditEvent,
    timeout: Duration,
) -> AppendFuture<'a> {
    Box::pin(async move {
        match tokio::time::timeout(timeout, sink.append(event)).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "audit append did not acknowledge within the configured bound",
            )),
        }
    })
}

/// The error a caller gets when policy denies. The reason names the rule
/// and policy version — operator-authored, and what the caller needs to
/// ask for access — never anything from the credential or the request
/// body.
#[must_use]
pub fn policy_denied(decision: &PolicyDecision) -> McpError {
    let version = decision.policy_version.as_deref().unwrap_or("unversioned");
    crate::error::api_error(
        format!("Policy denied: {} (policy {version})", decision.reason),
        Some(403),
        None,
    )
}

/// Evaluate the request the transport is about to send. `Ok(())` means
/// send it; `Err` means it was denied and the denial journaled.
///
/// # Errors
///
/// [`policy_denied`] when the decision point denies.
pub async fn authorize_egress(
    vendor: &str,
    method: HttpMethod,
    target: &CanonicalTarget,
    body: Option<&Value>,
) -> Result<(), McpError> {
    let Some(scope) = CallScope::current() else {
        return Ok(());
    };
    let Some(enforcement) = scope.enforcement() else {
        return Ok(());
    };
    let details = extractors::for_vendor(vendor, method, target, body);
    let context = ActionContext::assemble(
        scope.principal().clone(),
        scope.client().clone(),
        None,
        scope.tool_name(),
        details,
        None,
        enforcement.upstream.clone(),
    );
    let decision = enforcement.policy.evaluate(&context);
    if decision.is_allow() {
        return Ok(());
    }

    let event = AuditEvent {
        timestamp: crate::logger::iso_timestamp(),
        kind: AuditEventKind::EgressDecision,
        request_id: scope.request_id().to_owned(),
        tool_name: scope.tool_name().to_owned(),
        vendor: vendor.to_owned(),
        principal: scope.principal().clone(),
        client: scope.client().clone(),
        decision: decision.clone(),
        upstream_identity: enforcement.upstream.clone(),
        action: Some(context),
        outcome: Some("egress_denied".to_owned()),
        duration_ms: None,
    };
    if let Err(error) = append_bounded(
        enforcement.audit.as_ref(),
        &event,
        enforcement.append_timeout,
    )
    .await
    {
        // The request is refused either way; the denial not being durable
        // is loud but changes nothing about the refusal.
        tracing::error!(
            failure = %AuditFailure::classify(&error),
            tool = %scope.tool_name(),
            "failed to journal an egress denial"
        );
    }
    tracing::warn!(
        tool = %scope.tool_name(),
        vendor,
        rule = decision.rule_id.as_deref().unwrap_or("-"),
        "egress denied by policy"
    );
    Err(policy_denied(&decision))
}
