//! `PolicyDecisionPoint` port: an [`ActionContext`] in, a [`PolicyDecision`]
//! out (plan §3.1, ADR-003, WP A.7).
//!
//! Two implementations from day one:
//!
//! - `crate::policy::engine::FilePolicy` — a versioned YAML document whose
//!   rules match the canonical `ActionContext`, compiled to a matcher at
//!   load and hot-reloaded; the v1 engine, shaped to compile to Cedar later.
//! - [`AllowAll`] — today's community behaviour made explicit: everything
//!   the process can reach is allowed, with the `local` decision. It is what
//!   `MCP_AUTH_MODE=off` runs under, and it is the only decision point that
//!   answers `false` to [`PolicyDecisionPoint::enforces`], which lets the
//!   egress chokepoint skip the work entirely in local mode.
//!
//! Decisions are synchronous and pure: §8 budgets 20 µs for 500 rules, so
//! an implementation reads an `Arc` snapshot of a compiled rule set and
//! never touches I/O on the request path. Reloading swaps the snapshot;
//! in-flight calls keep the one they started with (plan §9, "hot-reload
//! races").
//!
//! Consumed as `Arc<dyn PolicyDecisionPoint>`: it is stored in the
//! composition root and consulted twice per tool call (tool level, egress),
//! and a generic parameter would ripple through `DevtoolsServer`, every
//! `#[tool_router]` block, and the transport (the documented deviation from
//! ports-prefer-generics).

use crate::policy::{ActionContext, PolicyDecision};

/// Decides whether an action may proceed.
pub trait PolicyDecisionPoint: Send + Sync {
    /// Evaluate `context`. Must be cheap, pure, and total: every context gets
    /// a decision, and a decision point with nothing to say answers deny.
    fn evaluate(&self, context: &ActionContext) -> PolicyDecision;

    /// The identity of the policy currently in force, for diagnostics and
    /// the `policy check` command. `None` when there is no versioned policy.
    fn version(&self) -> Option<String>;

    /// Whether this decision point can ever deny. `false` lets callers skip
    /// building an `ActionContext` at all — the local-mode zero-cost path.
    fn enforces(&self) -> bool {
        true
    }

    /// Why the decision point is running on stale policy, if it is: a
    /// file-backed policy whose source can no longer be read or compiled
    /// keeps its last good document in force and reports the reason here.
    /// Health reports it; decisions are unaffected. `None` when the policy
    /// in force is the current one.
    fn degraded(&self) -> Option<String> {
        None
    }
}

/// Everything is allowed — the community trust boundary, made explicit.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl PolicyDecisionPoint for AllowAll {
    fn evaluate(&self, _context: &ActionContext) -> PolicyDecision {
        PolicyDecision::local_allow()
    }

    fn version(&self) -> Option<String> {
        None
    }

    fn enforces(&self) -> bool {
        false
    }
}
