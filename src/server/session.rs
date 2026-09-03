//! Session manager that wraps [`LocalSessionManager`] with an idle-reap task.
//!
//! rmcp's built-in [`LocalSessionManager`] tracks completed-cache TTLs on
//! per-request channels but does not expire the top-level session map. The TS
//! reference (`src/index.ts:113-360`) expires sessions after 30 min of
//! inactivity, sweeping every 5 min. This wrapper delegates every
//! `SessionManager` call to `LocalSessionManager` and records a last-seen
//! timestamp so a background task can close idle sessions on the same cadence.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use futures::Stream;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::common::server_side_http::{ServerSseMessage, SessionId};
use rmcp::transport::streamable_http_server::SessionManager;
use rmcp::transport::streamable_http_server::session::local::{
    LocalSessionManager, LocalSessionManagerError,
};
use tokio::sync::RwLock;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, warn};

use crate::policy::{OwnerKey, Principal};

/// The header rmcp uses to name a session.
const SESSION_ID_HEADER: &str = "mcp-session-id";

/// TS reference uses a 30-minute idle timeout. See `src/index.ts`.
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_mins(30);
/// TS reference sweeps every 5 minutes.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_mins(5);

/// What the manager tracks per session beyond rmcp's own state.
#[derive(Debug)]
struct SessionState {
    last_seen: Instant,
    /// The principal that initialized the session (WP A.5). `None` until
    /// the auth middleware binds it — which it does on the initialize
    /// response — and always `None` in local mode, where nothing checks it.
    owner: Option<OwnerKey>,
}

/// [`SessionManager`] that layers an idle-reap policy over
/// [`LocalSessionManager`].
#[derive(Debug, Clone)]
pub struct ReapingSessionManager {
    inner: Arc<LocalSessionManager>,
    sessions: Arc<RwLock<HashMap<SessionId, SessionState>>>,
    idle_ttl: Duration,
}

impl ReapingSessionManager {
    /// Construct a new manager. `idle_ttl` is the duration after last activity
    /// at which a session becomes eligible for reap.
    pub fn new(idle_ttl: Duration) -> Self {
        Self {
            inner: Arc::new(LocalSessionManager::default()),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            idle_ttl,
        }
    }

    /// Spawn the background sweep task. It ticks every `sweep_interval` and
    /// closes sessions whose last-seen instant is older than `idle_ttl`.
    ///
    /// Returns the task handle; callers that care about shutdown should abort
    /// it when the server exits. The default call-site ignores the handle and
    /// relies on process exit.
    pub fn spawn_reaper(self: &Arc<Self>, sweep_interval: Duration) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = interval(sweep_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            // Consume the immediate first tick so the first sweep happens one
            // interval in, matching TS `setInterval` semantics.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                this.reap_once().await;
            }
        })
    }

    /// Run a single sweep pass. Exposed for tests; production uses the loop
    /// inside [`Self::spawn_reaper`].
    pub async fn reap_once(&self) {
        let now = Instant::now();
        let expired: Vec<SessionId> = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .filter(|(_, state)| now.duration_since(state.last_seen) > self.idle_ttl)
                .map(|(id, _)| id.clone())
                .collect()
        };
        for id in expired {
            debug!(session_id = %id, "reaping idle session");
            if let Err(err) = self.inner.close_session(&id).await {
                warn!(session_id = %id, error = %err, "failed to close idle session");
            }
            self.sessions.write().await.remove(&id);
        }
    }

    async fn bump(&self, id: &SessionId) {
        let mut sessions = self.sessions.write().await;
        match sessions.get_mut(id) {
            Some(state) => state.last_seen = Instant::now(),
            None => {
                sessions.insert(
                    id.clone(),
                    SessionState {
                        last_seen: Instant::now(),
                        owner: None,
                    },
                );
            }
        }
    }

    async fn forget(&self, id: &SessionId) {
        self.sessions.write().await.remove(id);
    }

    /// Bind a freshly created session to the principal that initialized
    /// it. Only the first binding sticks: a session's owner never changes.
    pub async fn bind_owner(&self, id: &SessionId, owner: OwnerKey) {
        let mut sessions = self.sessions.write().await;
        let state = sessions.entry(id.clone()).or_insert_with(|| SessionState {
            last_seen: Instant::now(),
            owner: None,
        });
        if state.owner.is_none() {
            state.owner = Some(owner);
        }
    }

    /// Whether `requester` may use session `id`: the session exists, is
    /// bound, and is bound to this owner. Unknown and unbound sessions are
    /// both `false` — an unbound session under enforcement is a session
    /// whose owner was never established, and nobody gets to be first.
    pub async fn owner_matches(&self, id: &SessionId, requester: &OwnerKey) -> bool {
        self.sessions
            .read()
            .await
            .get(id)
            .and_then(|state| state.owner.as_ref())
            .is_some_and(|owner| owner == requester)
    }

    /// Close every session whose owner satisfies `revoked` (WP B.4): a
    /// revoked subject's sessions must not outlive the revocation, and a
    /// `revoke all` closes every principal-bound session. Returns how many
    /// were closed. Unbound and local sessions are never touched.
    pub async fn close_where(&self, revoked: impl Fn(&OwnerKey) -> bool) -> usize {
        let doomed: Vec<SessionId> = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .filter(|(_, state)| state.owner.as_ref().is_some_and(&revoked))
                .map(|(id, _)| id.clone())
                .collect()
        };
        for id in &doomed {
            debug!(session_id = %id, "closing session of a revoked principal");
            if let Err(err) = self.inner.close_session(id).await {
                warn!(session_id = %id, error = %err, "failed to close revoked session");
            }
            self.sessions.write().await.remove(id);
        }
        doomed.len()
    }

    /// The owner a session is bound to, for tests and diagnostics.
    pub async fn owner_of(&self, id: &SessionId) -> Option<OwnerKey> {
        self.sessions
            .read()
            .await
            .get(id)
            .and_then(|state| state.owner.clone())
    }
}

/// Bind sessions to the principal that created them and refuse any other
/// principal's use of them (WP A.5, "session bound to subject").
///
/// Sits inside the bearer middleware, so the [`Principal`] is already in
/// the request extensions. A request naming a session another principal
/// owns — or one with no binding — gets the same `404` rmcp gives an
/// unknown session, so a session id is not a capability. A request with
/// no session id passes through; if its response *creates* a session (the
/// initialize response carries `Mcp-Session-Id`), the session is bound to
/// the requester before the response leaves.
pub async fn enforce_session_owner(
    State(manager): State<Arc<ReapingSessionManager>>,
    request: Request,
    next: Next,
) -> Response {
    let requester = request
        .extensions()
        .get::<Principal>()
        .map_or(OwnerKey::Local, OwnerKey::of);
    let named_session = request
        .headers()
        .get(SESSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|id| SessionId::from(id.to_owned()));

    if let Some(id) = named_session {
        if !manager.owner_matches(&id, &requester).await {
            debug!("session named by a request is not bound to its principal; answering 404");
            return session_not_found();
        }
        return next.run(request).await;
    }

    let response = next.run(request).await;
    if let Some(created) = response
        .headers()
        .get(SESSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|id| SessionId::from(id.to_owned()))
    {
        manager.bind_owner(&created, requester).await;
    }
    response
}

fn session_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        "Session not found",
    )
        .into_response()
}

impl SessionManager for ReapingSessionManager {
    type Error = LocalSessionManagerError;
    type Transport = <LocalSessionManager as SessionManager>::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        let (id, transport) = self.inner.create_session().await?;
        self.bump(&id).await;
        Ok((id, transport))
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        let resp = self.inner.initialize_session(id, message).await?;
        self.bump(id).await;
        Ok(resp)
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        let exists = self.inner.has_session(id).await?;
        if exists {
            self.bump(id).await;
        }
        Ok(exists)
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        let res = self.inner.close_session(id).await;
        self.forget(id).await;
        res
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + 'static, Self::Error> {
        let stream = self.inner.create_stream(id, message).await?;
        self.bump(id).await;
        Ok(stream)
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        self.inner.accept_message(id, message).await?;
        self.bump(id).await;
        Ok(())
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + 'static, Self::Error> {
        let stream = self.inner.create_standalone_stream(id).await?;
        self.bump(id).await;
        Ok(stream)
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + 'static, Self::Error> {
        let stream = self.inner.resume(id, last_event_id).await?;
        self.bump(id).await;
        Ok(stream)
    }
}
