//! Two-person approval endpoints (plan §3.10.3, WP D.2):
//!
//! | Method and path | Answer |
//! |---|---|
//! | `GET /admin/proposals` | `{"rows": [proposal…]}` for the caller's tenant |
//! | `GET /admin/proposals/{id}` | `{"proposal": …}` |
//! | `POST /admin/proposals/{id}/approve` (`{}`) | `{"proposal": …}`, applied |
//! | `POST /admin/proposals/{id}/reject` (`{}` or `{"reason": "…"}`) | `{"proposal": …}` |
//!
//! Approval needs a token that satisfies the fresh-token rule for writes
//! (`MCP_WRITE_MAX_TOKEN_AGE_SECONDS`, §3.6) and a subject other than the
//! proposer. The candidate is applied through the same code the direct
//! path uses, so it journals its own `admin_mutation` intent.
use super::{
    Admin, Error, INVALID, NOT_FOUND, Outcome, SignedDocument, UNAVAILABLE, decode, policy_error,
};
use crate::{
    policy::Principal,
    ports::{Candidate, MutationKind, ProposalError, ProposalRegistry, TokenFacts},
};
use axum::http::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

const APPROVALS_OFF: Error = Error(StatusCode::SERVICE_UNAVAILABLE, "approvals_off");
const STALE_TOKEN: Error = Error(StatusCode::FORBIDDEN, "stale_token");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rejection {
    #[serde(default)]
    reason: Option<String>,
}

/// `p-` and sixteen hex digits, as the adapter mints them.
fn valid_id(id: &str) -> bool {
    id.len() == 18 && id.starts_with("p-") && id[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn proposal_error(error: ProposalError) -> Error {
    let status = match error {
        ProposalError::NotFound => StatusCode::NOT_FOUND,
        ProposalError::AuditUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        ProposalError::SelfApproval
        | ProposalError::Expired
        | ProposalError::Decided
        | ProposalError::Incomplete
        | ProposalError::DigestMismatch => StatusCode::CONFLICT,
    };
    Error(status, error.code())
}

impl Admin {
    pub(super) async fn proposals(
        &self,
        principal: &Principal,
        facts: Option<&TokenFacts>,
        method: &Method,
        op: &str,
        body: &[u8],
    ) -> Result<Outcome, Error> {
        let registry = self.server.proposals().ok_or(APPROVALS_OFF)?;
        let rest = op.strip_prefix("proposals").unwrap_or_default();
        let data = match (method, rest) {
            (&Method::GET, "") => json!({"rows": registry.list(&principal.tenant)}),
            (_, "") => return Err(super::method_not_allowed()),
            _ => {
                let mut parts = rest.trim_start_matches('/').splitn(2, '/');
                let id = parts.next().unwrap_or_default();
                if !valid_id(id) {
                    return Err(NOT_FOUND);
                }
                match (method, parts.next()) {
                    (&Method::GET, None) => {
                        json!({"proposal": registry.get(&principal.tenant, id).ok_or(NOT_FOUND)?})
                    }
                    (&Method::POST, Some("approve")) => {
                        if !decode::<std::collections::BTreeMap<String, Value>>(body)?.is_empty() {
                            return Err(INVALID);
                        }
                        self.approve(&registry, principal, facts, id).await?
                    }
                    (&Method::POST, Some("reject")) => {
                        let input: Rejection = decode(body)?;
                        if input
                            .reason
                            .as_ref()
                            .is_some_and(|reason| reason.len() > 512)
                        {
                            return Err(INVALID);
                        }
                        let proposal = registry
                            .reject(id, principal, input.reason.as_deref())
                            .await
                            .map_err(proposal_error)?;
                        json!({"proposal": proposal})
                    }
                    (_, None | Some("approve" | "reject")) => {
                        return Err(super::method_not_allowed());
                    }
                    _ => return Err(NOT_FOUND),
                }
            }
        };
        Ok(Outcome::Applied(data))
    }

    async fn approve(
        &self,
        registry: &Arc<dyn ProposalRegistry>,
        principal: &Principal,
        facts: Option<&TokenFacts>,
        id: &str,
    ) -> Result<Value, Error> {
        let facts = facts.ok_or(UNAVAILABLE)?;
        if crate::tools::stale_for_write(facts, self.server.write_max_token_age()).is_some() {
            return Err(STALE_TOKEN);
        }
        let approval = registry
            .approve(id, principal)
            .await
            .map_err(proposal_error)?;
        if let Some(candidate) = approval.apply {
            let audit_seq = self.apply(principal, candidate).await?;
            registry
                .applied(id, audit_seq)
                .await
                .map_err(proposal_error)?;
        }
        let proposal = registry.get(&principal.tenant, id).ok_or(NOT_FOUND)?;
        Ok(json!({"proposal": proposal}))
    }

    /// The approved candidate through the ordinary mutation path: the same
    /// verification, lock, durable intent, and effect as a direct call.
    async fn apply(&self, principal: &Principal, candidate: Candidate) -> Result<u64, Error> {
        match candidate.kind {
            MutationKind::PolicyInstall => Ok(self
                .policy()?
                .install(principal, candidate.document, candidate.signature)
                .await
                .map_err(policy_error)?
                .audit_seq),
            MutationKind::DenyListReplace => {
                let list = self.auth.revocations().ok_or(UNAVAILABLE)?.clone();
                let _guard = list.mutation.lock().await;
                let staging = list.clone();
                let input = SignedDocument {
                    document: candidate.document,
                    signature: candidate.signature,
                };
                let (input, staged) = tokio::task::spawn_blocking(move || {
                    let staged = staging
                        .stage_candidate(input.document.as_bytes(), &input.signature)
                        .map_err(|_| INVALID)?;
                    Ok::<_, Error>((input, staged))
                })
                .await
                .map_err(|_| UNAVAILABLE)??;
                let applied = self
                    .install_deny_list(principal, &list, staged, input.document, input.signature)
                    .await?;
                applied["audit_seq"].as_u64().ok_or(UNAVAILABLE)
            }
            MutationKind::PolicyReload
            | MutationKind::SessionRevoke
            | MutationKind::ArtifactPurge => Err(UNAVAILABLE),
        }
    }
}
