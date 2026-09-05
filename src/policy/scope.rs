//! The call scope: who a tool call runs as, made available to everything
//! the call does without threading a principal through fourteen vendor
//! controllers (WPs A.4, A.5, A.7).
//!
//! `call_tool` establishes a [`CallScope`] as a Tokio task-local around the
//! dispatch of one tool call. Anything that runs inside that dispatch — the
//! artifact registry deciding who owns a file it is about to register, the
//! HTTP response cache building a key, the egress policy chokepoint in the
//! transport — reads it with [`CallScope::current`]. A task-local follows
//! `.await`s within the task (the whole controller pipeline, including
//! `FuturesUnordered` fan-out) and is absent in anything `tokio::spawn`ed;
//! nothing on an artifact-creating or request-sending path spawns, and the
//! background tasks that do exist (retention sweeps, config watching) are
//! not acting for a principal.
//!
//! ## Local mode costs nothing
//!
//! The scope is set only when enterprise machinery is active (an audit
//! sink is configured). With no scope, every reader answers `local`:
//! [`OwnerKey::current`] returns [`OwnerKey::Local`] without allocating, and
//! the cache key hashes a constant. That is what keeps the community call
//! path byte-for-byte what it was.
//!
//! ## Default-deny direction
//!
//! A reader that finds no scope treats the caller as `local`, which is only
//! correct when nothing is enforcing. In enterprise mode the scope is
//! always set by `call_tool` before dispatch, and `call_tool` itself
//! refuses a call without a validated principal — so "no scope" cannot mean
//! "a remote caller whose identity was lost".

use std::sync::{Arc, Mutex};

use serde::Serialize;

use super::egress::Enforcement;
use super::{ClientIdentity, PolicyEffect, Principal};
use crate::transport::HttpMethod;

tokio::task_local! {
    static CALL_SCOPE: Arc<CallScope>;
}

/// Most egress records one outcome record carries verbatim. A tool that
/// sends more (a very wide partitioned query) still has every decision
/// counted in [`EgressSummary::omitted`], so the evidence is bounded
/// without being silently truncated.
pub const MAX_EGRESS_RECORDS: usize = 64;

/// One upstream request the egress chokepoint decided on inside a call
/// scope: what was about to go on the wire, what policy said about it, and
/// what the transport then did with it.
///
/// The decision is recorded when it is made, immediately before the
/// transport would send; the [`dispatch`](Self::dispatch) state is filled
/// in by the transport afterwards through an [`EgressTicket`]. An `allow`
/// on its own therefore means "authorized"; whether bytes went on the wire,
/// how many times, and with what result is the dispatch state's to say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EgressRecord {
    pub vendor: String,
    #[serde(serialize_with = "super::serialize_method")]
    pub method: HttpMethod,
    /// Canonical path and query (§3.5): the form evaluated, and the form
    /// the transport builds the wire URL from.
    pub canonical_target: String,
    pub effect: PolicyEffect,
    pub rule_id: Option<String>,
    pub dispatch: EgressDispatch,
}

/// What the transport did with an authorized request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum EgressDispatch {
    /// Policy denied it; nothing was sent.
    Denied,
    /// Allowed, but the transport never reported a send: it returned before
    /// one (a credential that would not form a header, a cancelled stream)
    /// or the call ended first.
    NotAttempted,
    /// Allowed and answered from the response cache: nothing went on the
    /// wire.
    CacheHit,
    /// Allowed and sent. `attempts` counts wire attempts (a streamed
    /// request retries on 429/502/503/504 and transport errors);
    /// `last_status` is the final attempt's HTTP status, `None` when it
    /// failed before a response, in which case `failure` says how:
    /// `transport_error`, `timeout`, or `cancelled` — the last meaning the
    /// send was in flight when the call was cancelled, so the vendor may
    /// have observed the request even though no response was read.
    Attempted {
        attempts: u32,
        last_status: Option<u16>,
        failure: Option<&'static str>,
    },
}

/// The transport's handle on one egress record, for reporting what it did
/// after the decision. Dropping it without a report leaves the record at
/// [`EgressDispatch::NotAttempted`].
#[derive(Debug)]
pub struct EgressTicket {
    scope: Arc<CallScope>,
    /// `None` when the record was beyond [`MAX_EGRESS_RECORDS`] and only
    /// counted; reports are then no-ops.
    index: Option<usize>,
}

impl EgressTicket {
    /// The request was answered from the response cache.
    pub fn cache_hit(&self) {
        self.update(|record| record.dispatch = EgressDispatch::CacheHit);
    }

    /// One wire attempt completed: with an HTTP status, or with a failure
    /// before any response.
    pub fn attempted(&self, status: Option<u16>, failure: Option<&'static str>) {
        self.update(|record| match &mut record.dispatch {
            EgressDispatch::Attempted {
                attempts,
                last_status,
                failure: last_failure,
            } => {
                *attempts += 1;
                *last_status = status;
                *last_failure = failure;
            }
            _ => {
                record.dispatch = EgressDispatch::Attempted {
                    attempts: 1,
                    last_status: status,
                    failure,
                };
            }
        });
    }

    fn update(&self, apply: impl FnOnce(&mut EgressRecord)) {
        let Some(index) = self.index else {
            return;
        };
        let mut log = self
            .scope
            .egress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(record) = log.records.get_mut(index) {
            apply(record);
        }
    }
}

/// Every egress decision a call made, in order, for its outcome record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EgressSummary {
    pub requests: Vec<EgressRecord>,
    /// Decisions beyond [`MAX_EGRESS_RECORDS`] that were made but not
    /// carried verbatim.
    pub omitted: usize,
}

#[derive(Debug, Default)]
struct EgressLog {
    records: Vec<EgressRecord>,
    omitted: usize,
}

/// The identity a tool call runs as, plus the facts every downstream
/// decision or record about that call shares.
#[derive(Debug)]
pub struct CallScope {
    principal: Principal,
    client: ClientIdentity,
    tool_name: String,
    /// The digested JSON-RPC request id (see [`super::correlation_id`]).
    request_id: String,
    /// What the egress chokepoint needs to decide and record. `None` under
    /// a decision point that does not enforce (local mode with a journal).
    enforcement: Option<Enforcement>,
    /// Egress decisions made so far. A `std::sync::Mutex`: held for a push
    /// or a swap, never across an `.await`.
    egress: Mutex<EgressLog>,
}

impl CallScope {
    #[must_use]
    pub fn new(
        principal: Principal,
        client: ClientIdentity,
        tool_name: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            principal,
            client,
            tool_name: tool_name.into(),
            request_id: request_id.into(),
            enforcement: None,
            egress: Mutex::new(EgressLog::default()),
        }
    }

    /// Record an egress decision for this call's outcome record, and hand
    /// back the ticket the transport reports the dispatch through.
    pub fn note_egress(self: &Arc<Self>, record: EgressRecord) -> EgressTicket {
        let mut log = self
            .egress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = if log.records.len() < MAX_EGRESS_RECORDS {
            log.records.push(record);
            Some(log.records.len() - 1)
        } else {
            log.omitted += 1;
            None
        };
        drop(log);
        EgressTicket {
            scope: Arc::clone(self),
            index,
        }
    }

    /// Everything [`Self::note_egress`] recorded, leaving the log empty.
    /// `None` when no egress decision was made (the call never reached the
    /// transport, or nothing was enforcing).
    #[must_use]
    pub fn take_egress(&self) -> Option<EgressSummary> {
        let log = std::mem::take(
            &mut *self
                .egress
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        (!log.records.is_empty() || log.omitted > 0).then_some(EgressSummary {
            requests: log.records,
            omitted: log.omitted,
        })
    }

    /// Attach the egress enforcement for this call.
    #[must_use]
    pub fn with_enforcement(mut self, enforcement: Enforcement) -> Self {
        self.enforcement = Some(enforcement);
        self
    }

    #[must_use]
    pub fn enforcement(&self) -> Option<&Enforcement> {
        self.enforcement.as_ref()
    }

    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    #[must_use]
    pub fn client(&self) -> &ClientIdentity {
        &self.client
    }

    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The scope of the tool call this code is running inside, if any.
    /// One `Arc` clone; no allocation.
    #[must_use]
    pub fn current() -> Option<Arc<Self>> {
        CALL_SCOPE.try_with(Arc::clone).ok()
    }

    /// Run `future` with `scope` as the current call scope.
    pub async fn enter<F>(scope: Arc<Self>, future: F) -> F::Output
    where
        F: Future,
    {
        CALL_SCOPE.scope(scope, future).await
    }

    /// The owner key for artifacts and cache partitions created in this
    /// scope.
    #[must_use]
    pub fn owner(&self) -> OwnerKey {
        OwnerKey::of(&self.principal)
    }
}

/// Who owns an artifact or a cache partition: the tenant and subject of the
/// principal that created it, or `local` for the community trust boundary.
///
/// Compared for equality on access: an artifact is served only to the owner
/// that created it, and a cache entry is only ever a hit for the owner that
/// stored it. Cross-owner access is a `404`, indistinguishable from a
/// missing artifact, so an id cannot be used to probe for someone else's
/// results.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OwnerKey {
    /// The community trust boundary: stdio or loopback without auth.
    Local,
    /// A validated principal.
    Principal { tenant: String, subject: String },
}

impl OwnerKey {
    /// The owner key for a principal. A local principal maps to
    /// [`Self::Local`], so the two spellings of "local" are one owner.
    #[must_use]
    pub fn of(principal: &Principal) -> Self {
        if principal.authority == super::PrincipalAuthority::Local {
            return Self::Local;
        }
        Self::Principal {
            tenant: principal.tenant.clone(),
            subject: principal.subject.clone(),
        }
    }

    /// The owner of whatever the current call creates: the call scope's
    /// principal, or `local` when there is no scope. Allocates only when
    /// a scope exists.
    #[must_use]
    pub fn current() -> Self {
        CallScope::current().map_or(Self::Local, |scope| scope.owner())
    }

    /// Feed the owner into a hash, with a fixed framing so `Local` and a
    /// principal can never collide. Used by the response cache, which must
    /// not allocate per request to partition.
    pub fn hash_into(&self, hasher: &mut impl sha2::Digest) {
        match self {
            Self::Local => hasher.update(b"owner:local\0"),
            Self::Principal { tenant, subject } => {
                hasher.update(b"owner:principal\0");
                hasher.update(tenant.as_bytes());
                hasher.update([0]);
                hasher.update(subject.as_bytes());
                hasher.update([0]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PrincipalAuthority;

    fn okta(subject: &str) -> Principal {
        Principal {
            tenant: "acme".to_owned(),
            subject: subject.to_owned(),
            groups: Vec::new(),
            scopes: Vec::new(),
            authority: PrincipalAuthority::oidc("https://acme.okta.com/oauth2/default"),
        }
    }

    #[tokio::test]
    async fn scope_is_visible_inside_enter_and_absent_outside() {
        assert!(CallScope::current().is_none());
        assert_eq!(OwnerKey::current(), OwnerKey::Local);

        let scope = Arc::new(CallScope::new(
            okta("alice"),
            ClientIdentity::default(),
            "jira_get",
            "sha256:x",
        ));
        let seen = CallScope::enter(Arc::clone(&scope), async {
            // Survives an await point within the same task.
            tokio::task::yield_now().await;
            (
                CallScope::current().map(|s| s.tool_name().to_owned()),
                OwnerKey::current(),
            )
        })
        .await;
        assert_eq!(seen.0.as_deref(), Some("jira_get"));
        assert_eq!(
            seen.1,
            OwnerKey::Principal {
                tenant: "acme".to_owned(),
                subject: "alice".to_owned()
            }
        );
        assert!(CallScope::current().is_none(), "scope ends with the future");
    }

    #[test]
    fn local_principal_and_no_scope_are_the_same_owner() {
        assert_eq!(OwnerKey::of(&Principal::local()), OwnerKey::Local);
        assert_ne!(OwnerKey::of(&okta("alice")), OwnerKey::Local);
        assert_ne!(OwnerKey::of(&okta("alice")), OwnerKey::of(&okta("bob")));
    }

    #[test]
    fn owner_hashing_cannot_collide_across_kinds_or_boundaries() {
        use sha2::{Digest as _, Sha256};
        let digest = |owner: &OwnerKey| {
            let mut hasher = Sha256::new();
            owner.hash_into(&mut hasher);
            hasher.finalize()
        };
        let a = OwnerKey::Principal {
            tenant: "ac".to_owned(),
            subject: "me".to_owned(),
        };
        let b = OwnerKey::Principal {
            tenant: "acm".to_owned(),
            subject: "e".to_owned(),
        };
        assert_ne!(digest(&a), digest(&b), "tenant/subject boundary is framed");
        assert_ne!(digest(&OwnerKey::Local), digest(&a));
    }
}
