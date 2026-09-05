//! Audited control HTTP boundary (C.4). No backend paths are accepted from
//! callers. Expensive work has an independent, bounded task budget.
//!
//! `proposals` holds the two-person approval endpoints (WP D.2), a
//! self-contained file so that it can move under ADR-012.
mod proposals;
use super::auth::{InboundAuth, require_bearer};
use crate::{
    policy::{BundleAudit, Principal},
    ports::{
        Admission, ControlEvent, ControlEventKind, MutationGate, MutationIntent, MutationKind,
        TokenFacts,
        admin_inventory::{ArtifactStore, SessionStore},
    },
    tools::DevtoolsServer,
};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::any,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Clone)]
struct Admin {
    server: DevtoolsServer,
    auth: Arc<InboundAuth>,
    sessions: Option<Arc<dyn SessionStore>>,
    artifacts: Option<Arc<dyn ArtifactStore>>,
    reports: Option<Arc<dyn crate::ports::activity_reports::ActivityReports>>,
    policy: Option<Arc<dyn crate::ports::policy_admin::PolicyAdmin>>,
    /// Consulted before every durable intent (plan §3.10.1).
    gate: Arc<dyn MutationGate>,
    budget: Arc<tokio::sync::Semaphore>,
    mutations: Arc<tokio::sync::Mutex<()>>,
}

/// Compose the file-backed policy backend and the server's admission gate,
/// preserving the public router API. The HTTP adapter picks these defaults
/// itself so that it never reaches into the composition root; embedders
/// inject another backend or gate via [`router_with_policy`].
pub fn router(
    server: DevtoolsServer,
    auth: &InboundAuth,
    sessions: Option<Arc<dyn SessionStore>>,
    artifacts: Option<Arc<dyn ArtifactStore>>,
    reports: Option<Arc<dyn crate::ports::activity_reports::ActivityReports>>,
) -> Router {
    let policy = file_policy_admin(&server);
    let gate = server.mutation_gate();
    router_with_policy(server, auth, sessions, artifacts, reports, policy, gate)
}

fn file_policy_admin(
    server: &DevtoolsServer,
) -> Option<Arc<dyn crate::ports::policy_admin::PolicyAdmin>> {
    let policy = server.policy_file()?;
    let audit = server.audit_sink().map(|sink| BundleAudit {
        sink,
        append_timeout: server.audit_append_timeout(),
    });
    Some(Arc::new(crate::policy::admin::FilePolicyAdmin::new(
        policy, audit,
    )))
}

/// Build the HTTP boundary with an explicitly supplied policy backend and
/// admission gate.
pub fn router_with_policy(
    server: DevtoolsServer,
    auth: &InboundAuth,
    sessions: Option<Arc<dyn SessionStore>>,
    artifacts: Option<Arc<dyn ArtifactStore>>,
    reports: Option<Arc<dyn crate::ports::activity_reports::ActivityReports>>,
    policy: Option<Arc<dyn crate::ports::policy_admin::PolicyAdmin>>,
    gate: Arc<dyn MutationGate>,
) -> Router {
    let auth = Arc::new(auth.for_admin());
    let state = Admin {
        server,
        auth: auth.clone(),
        sessions,
        artifacts,
        reports,
        policy,
        gate,
        budget: Arc::new(tokio::sync::Semaphore::new(4)),
        mutations: Arc::new(tokio::sync::Mutex::new(())),
    };
    Router::new()
        .route("/admin/{*operation}", any(dispatch))
        .with_state(state)
        .route_layer(middleware::from_fn_with_state(auth, require_bearer))
}

#[derive(Debug, Clone, Copy)]
struct Error(StatusCode, &'static str);
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(json!({"error": self.1, "error_description": self.1})),
        )
            .into_response()
    }
}
const INVALID: Error = Error(StatusCode::BAD_REQUEST, "invalid_request");
const UNAVAILABLE: Error = Error(StatusCode::SERVICE_UNAVAILABLE, "admin_backend_unavailable");
const NOT_FOUND: Error = Error(StatusCode::NOT_FOUND, "not_found");
const AUDIT_FAILED: Error = Error(StatusCode::SERVICE_UNAVAILABLE, "audit_unavailable");
const fn method_not_allowed() -> Error {
    Error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    document: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedDocument {
    document: String,
    signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identifier {
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lookup {
    subject: String,
    tenant: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessReview {
    groups: std::collections::BTreeMap<String, Vec<String>>,
    tenant: String,
}
/// `POST /admin/policy/explain`: the inputs `mcp-devtools policy explain`
/// takes, less the document (the policy in force is the one explained).
/// Everything the gateway reads from configuration is read from
/// configuration here too; only what arrives with a request is supplied.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Explain {
    tool: String,
    #[serde(default)]
    arguments: Option<serde_json::Map<String, Value>>,
    /// Default `someone@example`, as the CLI defaults.
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    /// Default `mcp:tools`.
    #[serde(default)]
    scopes: Vec<String>,
    /// A what-if override of the configured `MCP_VENDOR_ENVIRONMENT`.
    #[serde(default)]
    environment: Option<String>,
    /// Default: the caller's tenant.
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    client_version: Option<String>,
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Activity {
    since: Option<String>,
    until: Option<String>,
    subject: Option<String>,
    vendor: Option<String>,
}

fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(body).map_err(|_| INVALID)
}

/// What a mutation came back with: applied (`200`), or held as a proposal
/// by the admission gate (`202`, plan §3.10.3).
enum Outcome {
    Applied(Value),
    Deferred(Value),
}
async fn dispatch(State(state): State<Admin>, request: Request) -> Result<Response, Error> {
    let permit = state
        .budget
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::TOO_MANY_REQUESTS, "admin_busy"))?;
    let principal = request
        .extensions()
        .get::<Principal>()
        .cloned()
        .ok_or(UNAVAILABLE)?;
    let facts = request.extensions().get::<TokenFacts>().cloned();
    let method = request.method().clone();
    let operation = request
        .uri()
        .path()
        .trim_start_matches("/admin/")
        .to_owned();
    if request.uri().query().is_some() {
        return Err(INVALID);
    }
    let body = axum::body::to_bytes(request.into_body(), 1_000_000)
        .await
        .map_err(|_| Error(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"))?;
    // Detached task owns both permit and mutation lock. Disconnecting the HTTP
    // caller cannot cancel the interval between durable intent and effect.
    state
        .server
        .pending_audit()
        .spawn(async move {
            let _permit = permit;
            let result = state
                .execute(&principal, facts.as_ref(), &method, &operation, &body)
                .await?;
            Ok(match result {
                Outcome::Applied(data) => Json(json!({"data": data})).into_response(),
                Outcome::Deferred(data) => {
                    (StatusCode::ACCEPTED, Json(json!({"data": data}))).into_response()
                }
            })
        })
        .await
        .map_err(|_| UNAVAILABLE)?
}

impl Admin {
    fn policy(&self) -> Result<&dyn crate::ports::policy_admin::PolicyAdmin, Error> {
        self.policy.as_deref().ok_or(UNAVAILABLE)
    }
    fn audit(&self) -> Result<BundleAudit, Error> {
        Ok(BundleAudit {
            sink: self.server.audit_sink().ok_or(AUDIT_FAILED)?,
            append_timeout: self.server.audit_append_timeout(),
        })
    }
    async fn record(
        &self,
        principal: &Principal,
        operation: &str,
        target: Option<String>,
    ) -> Result<u64, Error> {
        let mut event = ControlEvent::now(ControlEventKind::AdminMutation);
        event.principal = Some(principal.clone());
        event.source = Some(operation.into());
        event.version = target;
        let audit = self.audit()?;
        crate::policy::egress::append_control_bounded(
            audit.sink.as_ref(),
            &event,
            audit.append_timeout,
        )
        .await
        .map_err(|_| AUDIT_FAILED)
    }

    /// Ask the gate. `Ok(None)` is admission; `Ok(Some(_))` the deferred
    /// answer the caller returns instead of acting; `Err` a refusal.
    async fn admit(&self, intent: &MutationIntent<'_>) -> Result<Option<Outcome>, Error> {
        match self.gate.admit(intent).await {
            Admission::Apply => Ok(None),
            Admission::Deferred { proposal } => Ok(Some(Outcome::Deferred(json!({
                "proposal": proposal,
                "state": "pending",
                "operation": intent.kind.operation(),
            })))),
            // The journal being down is not a refusal; it is the same 503 as
            // every other failed append.
            Admission::Refused(cause) if cause == AUDIT_FAILED.1 => Err(AUDIT_FAILED),
            Admission::Refused(cause) => Err(Error(StatusCode::CONFLICT, cause)),
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn execute(
        &self,
        principal: &Principal,
        facts: Option<&TokenFacts>,
        method: &Method,
        op: &str,
        body: &[u8],
    ) -> Result<Outcome, Error> {
        if op == "proposals" || op.starts_with("proposals/") {
            return self.proposals(principal, facts, method, op, body).await;
        }
        let applied = match (method, op) {
            (&Method::GET, "policy") => encode(self.policy()?.read().await.map_err(policy_error)?),
            (&Method::POST, "policy/validate" | "policy/diff") => {
                let input: Document = decode(body)?;
                let policy = self.policy()?;
                if op == "policy/validate" {
                    encode(
                        policy
                            .validate(input.document)
                            .await
                            .map_err(policy_error)?,
                    )
                } else {
                    encode(policy.diff(input.document).await.map_err(policy_error)?)
                }
            }
            (&Method::POST, "policy/explain") => {
                let input: Explain = decode(body)?;
                return self.explain(principal, input).await.map(Outcome::Applied);
            }
            (&Method::POST, "policy/reload") => {
                if !decode::<std::collections::BTreeMap<String, Value>>(body)?.is_empty() {
                    return Err(INVALID);
                }
                let intent = MutationIntent {
                    kind: MutationKind::PolicyReload,
                    principal,
                    target: None,
                    candidate: None,
                    signature: None,
                };
                if let Some(deferred) = self.admit(&intent).await? {
                    return Ok(deferred);
                }
                encode(
                    self.policy()?
                        .reload(principal)
                        .await
                        .map_err(policy_error)?,
                )
            }
            (&Method::GET, "sessions") => {
                let rows = self
                    .sessions
                    .as_ref()
                    .ok_or(UNAVAILABLE)?
                    .list()
                    .await
                    .map_err(inventory_error)?;
                Ok(json!({"scope": "process", "rows": rows}))
            }
            (&Method::GET, "artifacts") => {
                let rows = self
                    .artifacts
                    .as_ref()
                    .ok_or(UNAVAILABLE)?
                    .list()
                    .await
                    .map_err(inventory_error)?;
                Ok(json!({"scope": "process", "rows": rows}))
            }
            (&Method::POST, "sessions/revoke" | "artifacts/purge") => {
                let input: Identifier = decode(body)?;
                if input.id.is_empty() || input.id.len() > 256 {
                    return Err(INVALID);
                }
                let _guard = self.mutations.lock().await;
                let kind = if op == "sessions/revoke" {
                    self.sessions.as_ref().ok_or(UNAVAILABLE)?;
                    MutationKind::SessionRevoke
                } else {
                    self.artifacts.as_ref().ok_or(UNAVAILABLE)?;
                    MutationKind::ArtifactPurge
                };
                let intent = MutationIntent {
                    kind,
                    principal,
                    target: Some(&input.id),
                    candidate: None,
                    signature: None,
                };
                if let Some(deferred) = self.admit(&intent).await? {
                    return Ok(deferred);
                }
                let seq = self.record(principal, op, Some(input.id.clone())).await?;
                if op == "sessions/revoke" {
                    self.sessions
                        .as_ref()
                        .ok_or(UNAVAILABLE)?
                        .revoke(&input.id)
                        .await
                        .map_err(inventory_error)?;
                } else {
                    self.artifacts
                        .as_ref()
                        .ok_or(UNAVAILABLE)?
                        .purge(&input.id)
                        .await
                        .map_err(inventory_error)?;
                }
                Ok(json!({"audit_seq": seq, "id": input.id, "scope": "process"}))
            }
            (&Method::GET, "deny-list") => {
                let list = self.auth.revocations().ok_or(UNAVAILABLE)?;
                let _guard = list.mutation.lock().await;
                Ok(
                    json!({"version": list.version(), "document": String::from_utf8(list.document_bytes()).map_err(|_| UNAVAILABLE)?, "signature": list.signature()}),
                )
            }
            (&Method::PUT, "deny-list") => {
                return self.replace_deny_list(principal, body).await;
            }
            (&Method::PUT, "policy") => {
                return self.install_policy(principal, body).await;
            }
            (&Method::POST, "principals/lookup") => {
                let input: Lookup = decode(body)?;
                let rows = self
                    .sessions
                    .as_ref()
                    .ok_or(UNAVAILABLE)?
                    .list()
                    .await
                    .map_err(inventory_error)?;
                let sessions: Vec<_> = rows.into_iter().filter(|row| matches!(&row.owner, Some(crate::policy::OwnerKey::Principal { subject, tenant }) if subject == &input.subject && tenant == &input.tenant)).collect();
                Ok(
                    json!({"subject": input.subject, "tenant": input.tenant, "scope": "process", "principal": self.auth.observed_principal(&input.tenant, &input.subject), "sessions": sessions,
                    "subject_denied": self.auth.revocations().map(|list| list.snapshot().document.revokes_subject(&input.subject))}),
                )
            }
            (&Method::POST, "usage") => {
                let query: crate::ports::ReportQuery = decode(body)?;
                let store = self.server.rollup_store().ok_or(UNAVAILABLE)?;
                Ok(
                    serde_json::to_value(store.report(&query).await.map_err(|_| UNAVAILABLE)?)
                        .map_err(|_| UNAVAILABLE)?,
                )
            }
            (&Method::POST, "reports/access-review") => {
                let input: AccessReview = decode(body)?;
                let rows = self
                    .policy()?
                    .access_review(input.groups, input.tenant)
                    .await
                    .map_err(policy_error)?;
                Ok(json!({"rows": rows}))
            }
            (&Method::POST, "reports/activity") => {
                let input: Activity = decode(body)?;
                for bound in [input.since.as_deref(), input.until.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    if crate::audit::export::instant(bound).is_none() {
                        return Err(INVALID);
                    }
                }
                let result = self
                    .reports
                    .as_ref()
                    .ok_or(UNAVAILABLE)?
                    .activity(&crate::audit::export::ActivityFilter {
                        since: input.since,
                        until: input.until,
                        subject: input.subject,
                        vendor: input.vendor,
                        kinds: vec![],
                    })
                    .await
                    .map_err(|_| UNAVAILABLE)?;
                Ok(
                    json!({"rows": result.rows, "records_read": result.records_read, "stopped": result.stopped}),
                )
            }
            _ if matches!(
                op,
                "policy"
                    | "policy/validate"
                    | "policy/diff"
                    | "policy/explain"
                    | "policy/reload"
                    | "sessions"
                    | "sessions/revoke"
                    | "artifacts"
                    | "artifacts/purge"
                    | "deny-list"
                    | "principals/lookup"
                    | "usage"
                    | "reports/access-review"
                    | "reports/activity"
            ) =>
            {
                Err(method_not_allowed())
            }
            _ => Err(NOT_FOUND),
        }?;
        Ok(Outcome::Applied(applied))
    }

    /// `POST /admin/policy/explain` (plan §3.10.2): build the action exactly
    /// as `call_tool` would — the same extractor through
    /// `ActionContext::for_tool_call`, the server-declared risk, the
    /// upstream identity the broker predicts under the configuration in
    /// force — and ask the policy in force why. The answer has the shape
    /// `policy explain --json` prints. Read-only: nothing is journaled.
    async fn explain(&self, caller: &Principal, input: Explain) -> Result<Value, Error> {
        let declared_risk = DevtoolsServer::declared_tool_risk(&input.tool).ok_or(INVALID)?;
        let vendor = crate::tools::vendor_for_tool(&input.tool).unwrap_or("unknown");
        let environment_override = input
            .environment
            .as_deref()
            .map(|value| crate::policy::EnvironmentClass::parse(value).ok_or(INVALID))
            .transpose()?;
        let mut upstream = self.server.predicted_upstream_identity(vendor).await;
        let configured_environment = upstream.environment;
        if let Some(environment) = environment_override {
            upstream.environment = environment;
        }
        let mut scopes = input.scopes;
        if scopes.is_empty() {
            scopes.push(super::auth::DEFAULT_REQUIRED_SCOPE.to_owned());
        }
        // The principal as the bearer middleware would build it for these
        // claims: the caller's tenant and issuer unless a tenant is given,
        // the CLI's placeholder subject when none is.
        let principal = Principal {
            tenant: input.tenant.unwrap_or_else(|| caller.tenant.clone()),
            subject: input
                .subject
                .unwrap_or_else(|| "someone@example".to_owned()),
            groups: input.groups,
            scopes,
            authority: caller.authority.clone(),
        };
        let context = crate::policy::ActionContext::for_tool_call(
            principal,
            crate::policy::ClientIdentity::reported(
                input.client_name.as_deref(),
                input.client_version.as_deref(),
            ),
            &input.tool,
            input.arguments.as_ref(),
            declared_risk,
            upstream,
        );
        let action = encode(&context)?;
        let explained = self
            .policy()?
            .explain(context)
            .await
            .map_err(policy_error)?;
        Ok(json!({
            "policy_version": explained.policy_version,
            "action": action,
            "configured_environment": configured_environment,
            "explanation": explained.explanation,
        }))
    }

    /// `PUT /admin/policy`: the mirror of the deny-list replacement for the
    /// policy (plan §3.10.3). The candidate is verified before the gate sees
    /// it, so a proposal binds to bytes that would install; the adapter
    /// verifies again under its lock when it installs.
    async fn install_policy(&self, principal: &Principal, body: &[u8]) -> Result<Outcome, Error> {
        let input: SignedDocument = decode(body)?;
        let policy = self.policy()?;
        let verified = policy
            .verify(&input.document, &input.signature)
            .await
            .map_err(policy_error)?;
        let intent = MutationIntent {
            kind: MutationKind::PolicyInstall,
            principal,
            target: Some(&verified.version),
            candidate: Some(input.document.as_bytes()),
            signature: Some(&input.signature),
        };
        if let Some(deferred) = self.admit(&intent).await? {
            return Ok(deferred);
        }
        let installed = policy
            .install(principal, input.document, input.signature)
            .await
            .map_err(policy_error)?;
        Ok(Outcome::Applied(
            json!({"audit_seq": installed.audit_seq, "version": installed.version}),
        ))
    }

    async fn replace_deny_list(
        &self,
        principal: &Principal,
        body: &[u8],
    ) -> Result<Outcome, Error> {
        let input: SignedDocument = decode(body)?;
        let list = self.auth.revocations().ok_or(UNAVAILABLE)?.clone();
        let _guard = list.mutation.lock().await;
        let staging = list.clone();
        let (input, staged) = tokio::task::spawn_blocking(move || {
            let staged = staging
                .stage_candidate(input.document.as_bytes(), &input.signature)
                .map_err(|_| INVALID)?;
            Ok::<_, Error>((input, staged))
        })
        .await
        .map_err(|_| UNAVAILABLE)??;
        // Admission is asked of the verified candidate: a proposal (D.2)
        // binds to these exact bytes and this version.
        let version = staged.version().to_owned();
        let intent = MutationIntent {
            kind: MutationKind::DenyListReplace,
            principal,
            target: Some(&version),
            candidate: Some(input.document.as_bytes()),
            signature: Some(&input.signature),
        };
        if let Some(deferred) = self.admit(&intent).await? {
            return Ok(deferred);
        }
        self.install_deny_list(principal, &list, staged, input.document, input.signature)
            .await
            .map(Outcome::Applied)
    }

    /// Apply an admitted (or approved) deny-list candidate. The caller
    /// holds the list's mutation lock and has staged `staged` from exactly
    /// `document` and `signature`.
    async fn install_deny_list(
        &self,
        principal: &Principal,
        list: &Arc<crate::auth::revocation::RevocationList>,
        staged: crate::policy::Staged<crate::auth::revocation::RevocationDocument>,
        document: String,
        signature: String,
    ) -> Result<Value, Error> {
        let version = staged.version().to_owned();
        let seq = self
            .record(principal, "deny-list/replace", Some(version))
            .await?;
        let files = list.clone();
        // Both files are atomically replaced under the bundle lock the
        // watcher shares; a crash between them fails closed at startup.
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let signature = crate::policy::signing::Signature::from_base64(&signature)
                .map_err(std::io::Error::other)?;
            files.install_signed(document.as_bytes(), &signature)
        })
        .await
        .map_err(|_| UNAVAILABLE)?
        .map_err(|_| UNAVAILABLE)?;
        list.commit(staged);
        self.auth.validator().forget_validated();
        // All process sessions are closed: token-id revocation cannot be
        // mapped back to a session's original token facts.
        if let Some(sessions) = &self.sessions {
            for row in sessions.list().await.map_err(inventory_error)? {
                sessions.revoke(&row.id).await.map_err(inventory_error)?;
            }
        }
        Ok(json!({"audit_seq": seq, "version": list.version()}))
    }
}
fn inventory_error(error: crate::ports::admin_inventory::InventoryError) -> Error {
    match error {
        crate::ports::admin_inventory::InventoryError::NotFound => NOT_FOUND,
        crate::ports::admin_inventory::InventoryError::Unavailable => UNAVAILABLE,
    }
}

fn encode(value: impl serde::Serialize) -> Result<Value, Error> {
    serde_json::to_value(value).map_err(|_| UNAVAILABLE)
}
fn policy_error(error: crate::ports::policy_admin::PolicyAdminError) -> Error {
    use crate::ports::policy_admin::PolicyAdminError;
    match error {
        PolicyAdminError::Invalid => INVALID,
        PolicyAdminError::Unavailable => UNAVAILABLE,
        PolicyAdminError::AuditUnavailable => AUDIT_FAILED,
    }
}
