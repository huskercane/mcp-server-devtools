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
//! An egress *allow* is not journaled as its own record — that would add a
//! durable write per outbound request — but it is not lost either: every
//! egress decision, allow or deny, is noted on the [`CallScope`] as an
//! [`EgressRecord`](super::EgressRecord) and carried by the call's
//! **outcome** record, together with what the transport then did with it
//! ([`EgressDispatch`]: denied, never attempted, served from cache, or sent
//! — with the attempt count and the final result). One tool call can send
//! several requests (a partitioned Grafana query, a secondary lookup a
//! controller performs), so the intent's tool-level action alone cannot say
//! which URLs were individually authorized and sent; the outcome's egress
//! list can, and it distinguishes "authorized" from "went on the wire". The
//! trade: that list is written after dispatch, so a process that dies
//! between dispatch and outcome loses it — which is the "intent without
//! outcome" state described below, and nothing more.
//!
//! ## What is *not* an egress
//!
//! Two classes of outbound traffic do not pass this chokepoint, on purpose:
//!
//! - **Control-plane traffic** the gateway sends for itself: the JWKS fetch
//!   (`auth::okta`) and health probes. Their origins come from operator
//!   configuration and are validated at startup (`https`, or loopback).
//! - **Credential-provider bootstrap** a vendor client performs to obtain
//!   the credential it will then act with: Zoom's OAuth token exchange and
//!   `NinjaOne`'s console login. Their origins likewise come only from
//!   configuration, never from a request, and they carry no tool-supplied
//!   path. They are tool-triggered, though, so this exemption is a
//!   documented classification rather than an oversight; routing them
//!   through a separately classified chokepoint is CF-17.
//!
//! ## Bounded append (CF-14)
//!
//! `AuditSink::append` waits for durable acknowledgement, which on a
//! stalled disk is unbounded. [`append_bounded`] caps that wait for the
//! records written **before** dispatch. The decision, recorded here because
//! it is a semantic one and not a one-liner: on timeout the **call is
//! refused** (fail closed; the vendor is never contacted). The record may
//! or may not have entered the journal's queue when the wait was abandoned
//! — a queued one is still written later by the writer thread — and either
//! state is truthful, because of what the two record kinds mean: an intent
//! record proves a call was requested and authorized; only the *outcome*
//! record proves it was dispatched. An intent with no outcome is
//! "requested, not dispatched", which is exactly the state a refused call
//! is in. The caller sees a fixed refusal, not the transport's own timeout.
//!
//! The outcome record is the other way round: the dispatch has already
//! happened, so abandoning its append would make a dispatched call look
//! undispatched. It is therefore **not** appended through this function.
//! `DevtoolsServer::record_outcome` gives the append its own tracked task
//! that owns the record; the caller stops *waiting* at the bound but does
//! not cancel the write, and the transports drain those tasks at shutdown
//! (bounded, so a dead disk cannot hold the process open forever).
//!
//! What that leaves, stated precisely: an intent with no outcome means
//! **"authorized; dispatch not evidenced"**. Before dispatch it is a refused
//! call. After dispatch it can only be a process that died, or a journal
//! that never recovered, between the vendor's response and the outcome's
//! acknowledgement — and the operator log says which. It never means "known
//! not to have been dispatched"; an auditor treats it as possibly dispatched.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::error::McpError;
use crate::ports::audit_sink::{AppendFuture, AuditEvent, AuditEventKind, AuditFailure, AuditSink};
use crate::ports::policy_decision_point::PolicyDecisionPoint;
use crate::transport::HttpMethod;

use super::canonical::CanonicalTarget;
use super::scope::{CallScope, EgressDispatch, EgressTicket};
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

/// Evaluate the request the transport is about to send. `Ok(_)` means send
/// it; `Err` means it was denied and the denial journaled. Inside an
/// enforcing scope the `Ok` carries the [`EgressTicket`] the transport
/// reports the dispatch through (cache hit, each wire attempt and its
/// result); outside one it is `None` and nothing was recorded.
///
/// # Errors
///
/// [`policy_denied`] when the decision point denies.
pub async fn authorize_egress(
    vendor: &str,
    method: HttpMethod,
    target: &CanonicalTarget,
    body: Option<&Value>,
) -> Result<Option<EgressTicket>, McpError> {
    let Some(scope) = CallScope::current() else {
        return Ok(None);
    };
    let Some(enforcement) = scope.enforcement() else {
        return Ok(None);
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
    let ticket = scope.note_egress(super::EgressRecord {
        vendor: vendor.to_owned(),
        method,
        canonical_target: target.url_under(""),
        effect: decision.effect,
        rule_id: decision.rule_id.clone(),
        dispatch: if decision.is_allow() {
            EgressDispatch::NotAttempted
        } else {
            EgressDispatch::Denied
        },
    });
    if decision.is_allow() {
        return Ok(Some(ticket));
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
        egress: None,
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
