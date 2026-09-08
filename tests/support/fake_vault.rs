//! A fake Vault / `OpenBao` for contract tests: enough of the HTTP API for
//! the `vault://` adapter — KV v2 reads, `AppRole` and Kubernetes logins,
//! `lookup-self`, `renew-self`, and a seal switch — behind wiremock, with
//! every request recorded so a test can assert on the headers the adapter
//! sent. The real-server proof is `tests/vault_live_tests.rs`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[derive(Debug, Clone)]
pub struct SeenRequest {
    pub method: String,
    pub path: String,
    pub token: Option<String>,
    pub namespace: Option<String>,
    pub body: Value,
}

#[derive(Debug, Clone, Copy)]
pub struct Lease {
    pub seconds: u64,
    pub renewable: bool,
}

#[derive(Default)]
pub struct State {
    /// `mount/path` → (data object or `Null` for a deleted version, version).
    pub kv: HashMap<String, (Value, u64)>,
    /// Tokens Vault currently accepts, with their lease.
    pub tokens: HashMap<String, Lease>,
    pub approle: Option<(String, String)>,
    pub kubernetes_role: Option<String>,
    pub sealed: bool,
    /// Lease issued to the next login.
    pub issued_lease: Lease,
    pub issued: u64,
    pub renewals: u64,
    pub requests: Vec<SeenRequest>,
}

impl Default for Lease {
    fn default() -> Self {
        Self {
            seconds: 3600,
            renewable: true,
        }
    }
}

#[derive(Clone)]
pub struct FakeVault {
    pub server: Arc<MockServer>,
    pub state: Arc<Mutex<State>>,
}

impl FakeVault {
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let state = Arc::new(Mutex::new(State::default()));
        Mock::given(wiremock::matchers::path_regex("^/v1/.*$"))
            .respond_with(Responder {
                state: Arc::clone(&state),
            })
            .mount(&server)
            .await;
        Self {
            server: Arc::new(server),
            state,
        }
    }

    pub fn addr(&self) -> String {
        self.server.uri()
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }

    /// Accept `token` from now on.
    pub fn accept_token(&self, token: &str, lease: Lease) {
        self.with(|state| {
            state.tokens.insert(token.to_owned(), lease);
        });
    }

    pub fn revoke_token(&self, token: &str) {
        self.with(|state| {
            state.tokens.remove(token);
        });
    }

    /// Write a KV v2 secret: a new version each time, as Vault does.
    pub fn write_kv(&self, target: &str, data: Value) {
        self.with(|state| {
            let entry = state
                .kv
                .entry(target.to_owned())
                .or_insert_with(|| (Value::Null, 0));
            entry.0 = data;
            entry.1 += 1;
        });
    }

    /// Soft-delete the current version: Vault answers 200 with `data: null`.
    pub fn delete_kv(&self, target: &str) {
        self.with(|state| {
            if let Some(entry) = state.kv.get_mut(target) {
                entry.0 = Value::Null;
            }
        });
    }

    pub fn destroy_kv(&self, target: &str) {
        self.with(|state| {
            state.kv.remove(target);
        });
    }

    pub fn requests(&self) -> Vec<SeenRequest> {
        self.with(|state| state.requests.clone())
    }

    /// Requests to a KV data path, in order.
    pub fn kv_reads(&self) -> Vec<SeenRequest> {
        self.requests()
            .into_iter()
            .filter(|request| request.path.contains("/data/"))
            .collect()
    }

    pub fn logins(&self) -> Vec<SeenRequest> {
        self.requests()
            .into_iter()
            .filter(|request| request.path.ends_with("/login"))
            .collect()
    }
}

struct Responder {
    state: Arc<Mutex<State>>,
}

impl Respond for Responder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut state = self.state.lock().unwrap();
        let path = request.url.path().to_owned();
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let token = header("x-vault-token");
        let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        state.requests.push(SeenRequest {
            method: request.method.to_string(),
            path: path.clone(),
            token: token.clone(),
            namespace: header("x-vault-namespace"),
            body: body.clone(),
        });
        if state.sealed {
            return ResponseTemplate::new(503)
                .set_body_json(json!({ "errors": ["Vault is sealed"] }));
        }
        let method = request.method.to_string();
        let segments: Vec<&str> = path.trim_start_matches("/v1/").split('/').collect();
        match (method.as_str(), segments.as_slice()) {
            ("POST", ["auth", mount, "login"]) => state.login(mount, &body),
            ("GET", ["auth", "token", "lookup-self"]) => state.lookup_self(token.as_deref()),
            ("POST", ["auth", "token", "renew-self"]) => state.renew_self(token.as_deref()),
            ("GET", [mount, "data", rest @ ..]) => {
                state.read_kv(token.as_deref(), &format!("{mount}/{}", rest.join("/")))
            }
            _ => ResponseTemplate::new(404).set_body_json(json!({ "errors": ["no handler"] })),
        }
    }
}

impl State {
    fn login(&mut self, mount: &str, body: &Value) -> ResponseTemplate {
        let accepted = match mount {
            "approle" => self.approle.as_ref().is_some_and(|(role_id, secret_id)| {
                body["role_id"] == *role_id && body["secret_id"] == *secret_id
            }),
            "kubernetes" => {
                self.kubernetes_role
                    .as_deref()
                    .is_some_and(|role| body["role"] == role)
                    && body["jwt"].as_str().is_some_and(|jwt| !jwt.is_empty())
            }
            _ => false,
        };
        if !accepted {
            return ResponseTemplate::new(400)
                .set_body_json(json!({ "errors": ["invalid role or secret ID"] }));
        }
        self.issued += 1;
        let issued = format!("hvs.fake-{mount}-{}", self.issued);
        let lease = self.issued_lease;
        self.tokens.insert(issued.clone(), lease);
        ResponseTemplate::new(200).set_body_json(json!({
            "auth": {
                "client_token": issued,
                "lease_duration": lease.seconds,
                "renewable": lease.renewable,
                "policies": ["default", "mcp"],
            }
        }))
    }

    fn lookup_self(&self, token: Option<&str>) -> ResponseTemplate {
        let Some(lease) = token.and_then(|token| self.tokens.get(token)) else {
            return forbidden();
        };
        ResponseTemplate::new(200).set_body_json(json!({
            "data": { "ttl": lease.seconds, "renewable": lease.renewable, "policies": ["default"] }
        }))
    }

    fn renew_self(&mut self, token: Option<&str>) -> ResponseTemplate {
        let Some(token) = token else {
            return forbidden();
        };
        let Some(lease) = self.tokens.get(token).copied() else {
            return forbidden();
        };
        if !lease.renewable {
            return ResponseTemplate::new(400)
                .set_body_json(json!({ "errors": ["lease is not renewable"] }));
        }
        self.renewals += 1;
        ResponseTemplate::new(200).set_body_json(json!({
            "auth": {
                "client_token": token,
                "lease_duration": lease.seconds,
                "renewable": true,
            }
        }))
    }

    fn read_kv(&self, token: Option<&str>, key: &str) -> ResponseTemplate {
        if token.is_none_or(|token| !self.tokens.contains_key(token)) {
            return forbidden();
        }
        match self.kv.get(key) {
            None => ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })),
            Some((data, version)) => ResponseTemplate::new(200).set_body_json(json!({
                "request_id": "fake",
                "data": {
                    "data": data,
                    "metadata": {
                        "created_time": "2026-09-04T00:00:00Z",
                        "deletion_time": if data.is_null() { "2026-09-04T00:00:01Z" } else { "" },
                        "destroyed": false,
                        "version": version,
                    }
                }
            })),
        }
    }
}

fn forbidden() -> ResponseTemplate {
    ResponseTemplate::new(403).set_body_json(json!({ "errors": ["permission denied"] }))
}
