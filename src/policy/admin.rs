//! File-backed implementation of the policy administration port.
use super::{BundleAudit, FilePolicy, Principal};
use crate::{
    audit::export::{AccessRow, GroupsFile, access_review},
    ports::{
        ControlEvent, ControlEventKind,
        policy_admin::{
            AdminFuture, PolicyAdmin, PolicyAdminError, PolicyDiff, PolicyDocument, PolicyReload,
            PolicyValidation,
        },
    },
};
use PolicyAdminError::{AuditUnavailable, Invalid, Unavailable};
use std::{collections::BTreeMap, sync::Arc};

pub struct FilePolicyAdmin {
    policy: Arc<FilePolicy>,
    audit: Option<BundleAudit>,
}
impl FilePolicyAdmin {
    pub fn new(policy: Arc<FilePolicy>, audit: Option<BundleAudit>) -> Self {
        Self { policy, audit }
    }
}
async fn candidate(document: String) -> Result<Arc<FilePolicy>, PolicyAdminError> {
    tokio::task::spawn_blocking(move || FilePolicy::from_bytes(document.as_bytes()))
        .await
        .map_err(|_| Unavailable)?
        .map_err(|_| Invalid)
}
impl PolicyAdmin for FilePolicyAdmin {
    fn read(&self) -> AdminFuture<'_, PolicyDocument> {
        Box::pin(async move {
            let _guard = self.policy.mutation.lock().await;
            Ok(PolicyDocument {
                version: self.policy.version(),
                document: String::from_utf8(self.policy.document_bytes())
                    .map_err(|_| Unavailable)?,
                signature: self.policy.signature(),
            })
        })
    }
    fn validate(&self, document: String) -> AdminFuture<'_, PolicyValidation> {
        Box::pin(async move {
            let candidate = candidate(document).await?;
            Ok(PolicyValidation {
                valid: true,
                version: candidate.version(),
                rules: candidate.rule_count(),
                signature_verified: false,
            })
        })
    }
    fn diff(&self, document: String) -> AdminFuture<'_, PolicyDiff> {
        Box::pin(async move {
            let candidate = candidate(document).await?;
            let _guard = self.policy.mutation.lock().await;
            Ok(PolicyDiff {
                current_version: self.policy.version(),
                candidate_version: candidate.version(),
                current_rules: self.policy.describe_rules(),
                candidate_rules: candidate.describe_rules(),
            })
        })
    }
    fn reload<'a>(&'a self, principal: &'a Principal) -> AdminFuture<'a, PolicyReload> {
        Box::pin(async move {
            // This async lock intentionally spans staging and the durable audit
            // append: the watcher must not commit a different policy between
            // the recorded intent and its effect. Releasing it early would
            // break correctness. No standard mutex crosses an await.
            let _guard = self.policy.mutation.lock().await;
            let staging = self.policy.clone();
            let staged = tokio::task::spawn_blocking(move || staging.stage())
                .await
                .map_err(|_| Unavailable)?
                .map_err(|_| Invalid)?;
            let mut event = ControlEvent::now(ControlEventKind::AdminMutation);
            event.principal = Some(principal.clone());
            event.source = Some("policy/reload".into());
            event.version = staged.as_ref().map(|s| s.version().to_owned());
            let audit = self.audit.as_ref().ok_or(AuditUnavailable)?;
            let audit_seq = super::egress::append_control_bounded(
                audit.sink.as_ref(),
                &event,
                audit.append_timeout,
            )
            .await
            .map_err(|_| AuditUnavailable)?;
            let changed = staged.is_some();
            if let Some(staged) = staged {
                self.policy.commit(staged);
            }
            Ok(PolicyReload {
                audit_seq,
                changed,
                version: self.policy.version(),
            })
        })
    }
    fn access_review(
        &self,
        groups: BTreeMap<String, Vec<String>>,
        tenant: String,
    ) -> AdminFuture<'_, Vec<AccessRow>> {
        let policy = self.policy.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                access_review(&policy, &GroupsFile(groups), &tenant)
            })
            .await
            .map_err(|_| Unavailable)
        })
    }
}
