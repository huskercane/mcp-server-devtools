//! `vault://`: `HashiCorp` Vault and `OpenBao` KV v2 (plan §3.8, C.2b).
//!
//! A reference `vault://<mount>/<path>#<key>` names the KV v2 secret at
//! `<mount>/data/<path>`; the document is that secret's `data` object as
//! JSON, so every `#key` into it is served from one read (the resolver's
//! atomic multi-part rule), and the version is Vault's own version number —
//! the rotation evidence an audit record carries. A reference without a
//! `#key` is refused at parse time: a KV secret is a document, not a value.
//!
//! ## Authentication is explicit
//!
//! `MCP_VAULT_AUTH` names one of three methods and nothing falls back to
//! another (plan §3.8, "Provider authentication"): `kubernetes` (the
//! projected service-account token, re-read at every login so a rotated
//! projection is used), `approle` (`role_id` + `secret_id`; the secret id
//! may itself be a `file://` reference, which is how a wrapped or
//! CSI-delivered secret id is picked up), or `token` (development, or a
//! token an agent sidecar keeps fresh). The client token is renewed with
//! `renew-self` once two thirds of its lease is gone and re-obtained when
//! renewal fails, the lease is over, or a read answers `403`; a token with
//! no lease is used as long as Vault accepts it.
//!
//! ## Nothing of Vault's in the domain
//!
//! Every failure is a [`SecretSourceError`] whose `detail` is a category
//! (`connection failed`, `forbidden`, `sealed`, `http 5xx`, …). Vault's own
//! error text, which can quote a request, is never copied; the client
//! token, role id, and secret id appear in no error, log line, or `Debug`.
//!
//! ## Channel
//!
//! `MCP_VAULT_ADDR` must be `https` — or `http` on loopback, which is a
//! local dev server or a Vault Agent sidecar on the same pod. A private CA
//! is trusted through `MCP_VAULT_CACERT`. `MCP_VAULT_NAMESPACE` sets
//! `X-Vault-Namespace` on every request (Vault Enterprise / HCP).
//!
//! Compiled in under the `secrets-vault` feature (on by default; no extra
//! dependencies — KV v2 is a handful of JSON endpoints over the pinned
//! shared HTTP client). Constructed by [`crate::secrets::SecretResolver::from_config`]
//! when `MCP_VAULT_ADDR` is set; a `vault://` reference with no address is a
//! typed startup error.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Deserialize;
use tokio::time::Instant;

use crate::config::Config;
use crate::ports::{
    FetchedSecret, Scheme, SecretFetchFuture, SecretLocator, SecretSource, SecretSourceError,
};

/// Config key: the Vault address, `https://vault.example:8200`. Setting it
/// enables the adapter.
pub const ADDR_KEY: &str = "MCP_VAULT_ADDR";
/// Config key: `kubernetes`, `approle`, or `token`. Required with
/// [`ADDR_KEY`]; never guessed.
pub const AUTH_KEY: &str = "MCP_VAULT_AUTH";
/// Config key (`token` auth): the client token, or a `file://` reference to
/// it.
pub const TOKEN_KEY: &str = "MCP_VAULT_TOKEN";
/// Config key (`approle` auth): the role id.
pub const ROLE_ID_KEY: &str = "MCP_VAULT_ROLE_ID";
/// Config key (`approle` auth): the secret id, or a `file://` reference to
/// it.
pub const SECRET_ID_KEY: &str = "MCP_VAULT_SECRET_ID";
/// Config key (`kubernetes` auth): the Vault role bound to the service
/// account.
pub const ROLE_KEY: &str = "MCP_VAULT_ROLE";
/// Config key (`kubernetes` auth): where the projected service-account
/// token is. Defaults to the kubelet's path.
pub const JWT_PATH_KEY: &str = "MCP_VAULT_JWT_PATH";
/// Config key: the auth method's mount path when it is not the default
/// (`approle`, `kubernetes`).
pub const AUTH_MOUNT_KEY: &str = "MCP_VAULT_AUTH_MOUNT";
/// Config key: `X-Vault-Namespace` for Vault Enterprise and HCP Vault.
pub const NAMESPACE_KEY: &str = "MCP_VAULT_NAMESPACE";
/// Config key: a PEM file holding the CA that signed Vault's certificate.
pub const CACERT_KEY: &str = "MCP_VAULT_CACERT";

const DEFAULT_JWT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
/// Per-request timeout. Fetches run on the refresher, never a tool call,
/// so this bounds how long a refresh can hang, not a request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest response body accepted. A KV secret is small.
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Secret material given either inline or as a `file://` reference, read
/// at every login so a rotated file is used without a restart. Opaque
/// outside this module: the literal is never readable through it.
#[derive(Clone)]
pub struct Material(MaterialInner);

#[derive(Clone)]
enum MaterialInner {
    Literal(String),
    File(PathBuf),
}

impl Material {
    fn parse(key: &str, raw: &str) -> Result<Self, String> {
        match crate::secrets::SecretReference::parse(raw) {
            Ok(None) => Ok(Self(MaterialInner::Literal(raw.trim().to_owned()))),
            Ok(Some(reference)) if reference.scheme() == Scheme::File => {
                if reference.fragment().is_some() {
                    return Err(format!(
                        "{key}: a `file://` reference here names the whole file; `#key` is not \
                         supported for provider credentials"
                    ));
                }
                let path = super::file::FileSecretSource::path_for(reference.locator())
                    .map_err(|error| format!("{key}: {error}"))?;
                Ok(Self(MaterialInner::File(path)))
            }
            Ok(Some(reference)) => Err(format!(
                "{key} cannot be a `{}://` reference: the provider's own credential must come \
                 from a literal or a file",
                reference.scheme()
            )),
            Err(error) => Err(format!("{key}: {error}")),
        }
    }

    async fn read(&self) -> Result<String, &'static str> {
        match &self.0 {
            MaterialInner::Literal(value) => Ok(value.clone()),
            MaterialInner::File(path) => read_credential_file(path).await,
        }
    }

    /// The file the material is read from, when it is a `file://`
    /// reference.
    #[must_use]
    pub fn file(&self) -> Option<&Path> {
        match &self.0 {
            MaterialInner::Literal(_) => None,
            MaterialInner::File(path) => Some(path),
        }
    }
}

impl fmt::Debug for Material {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            MaterialInner::Literal(_) => formatter.write_str("<redacted>"),
            MaterialInner::File(path) => write!(formatter, "file:{}", path.display()),
        }
    }
}

async fn read_credential_file(path: &Path) -> Result<String, &'static str> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|_| "credential file unreadable")?;
    let text = String::from_utf8(bytes).map_err(|_| "credential file not UTF-8")?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("credential file empty");
    }
    Ok(trimmed.to_owned())
}

/// How the adapter obtains a client token.
#[derive(Debug, Clone)]
pub enum VaultAuth {
    /// A token given directly (development, or one an agent keeps fresh).
    Token { token: Material },
    /// `AppRole`: `POST auth/<mount>/login { role_id, secret_id }`.
    AppRole {
        mount: String,
        role_id: String,
        secret_id: Material,
    },
    /// Kubernetes: `POST auth/<mount>/login { role, jwt }` with the
    /// projected service-account token.
    Kubernetes {
        mount: String,
        role: String,
        jwt_path: PathBuf,
    },
}

impl VaultAuth {
    /// The method's name as configured.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Token { .. } => "token",
            Self::AppRole { .. } => "approle",
            Self::Kubernetes { .. } => "kubernetes",
        }
    }
}

/// Everything the adapter needs, read once from configuration.
#[derive(Debug, Clone)]
pub struct VaultSettings {
    /// The address without a trailing slash.
    pub addr: String,
    pub auth: VaultAuth,
    pub namespace: Option<String>,
    pub ca_cert: Option<PathBuf>,
}

impl VaultSettings {
    /// Whether the configuration enables the adapter at all.
    #[must_use]
    pub fn is_configured(config: &Config) -> bool {
        optional(config, ADDR_KEY).is_some()
    }

    /// Read the settings, refusing anything incomplete or ambiguous.
    ///
    /// # Errors
    ///
    /// A human-readable reason: no or unknown auth method, a method's
    /// credential missing, an address that is not `https` (or `http` on
    /// loopback), a CA file that cannot be read.
    pub fn from_config(config: &Config) -> Result<Self, String> {
        let addr = optional(config, ADDR_KEY)
            .ok_or_else(|| format!("{ADDR_KEY} is required for vault:// references"))?;
        let addr = addr.trim_end_matches('/').to_owned();
        let parsed =
            url::Url::parse(&addr).map_err(|error| format!("{ADDR_KEY} is not a URL: {error}"))?;
        require_https_unless_loopback(&parsed)?;
        let method = optional(config, AUTH_KEY).ok_or_else(|| {
            format!(
                "{AUTH_KEY} is required with {ADDR_KEY}: one of kubernetes, approle, token \
                 (the adapter never guesses an authentication method)"
            )
        })?;
        let mount = |default: &str| {
            optional(config, AUTH_MOUNT_KEY).map_or_else(
                || default.to_owned(),
                |mount| mount.trim_matches('/').to_owned(),
            )
        };
        let auth = if method.eq_ignore_ascii_case("token") {
            VaultAuth::Token {
                token: Material::parse(TOKEN_KEY, required(config, TOKEN_KEY, "token")?)?,
            }
        } else if method.eq_ignore_ascii_case("approle") {
            VaultAuth::AppRole {
                mount: mount("approle"),
                role_id: required(config, ROLE_ID_KEY, "approle")?.trim().to_owned(),
                secret_id: Material::parse(
                    SECRET_ID_KEY,
                    required(config, SECRET_ID_KEY, "approle")?,
                )?,
            }
        } else if method.eq_ignore_ascii_case("kubernetes") {
            VaultAuth::Kubernetes {
                mount: mount("kubernetes"),
                role: required(config, ROLE_KEY, "kubernetes")?.trim().to_owned(),
                jwt_path: PathBuf::from(optional(config, JWT_PATH_KEY).unwrap_or(DEFAULT_JWT_PATH)),
            }
        } else {
            return Err(format!(
                "{AUTH_KEY} is {method:?}; expected one of kubernetes, approle, token"
            ));
        };
        let namespace = optional(config, NAMESPACE_KEY).map(str::to_owned);
        let ca_cert = optional(config, CACERT_KEY).map(PathBuf::from);
        Ok(Self {
            addr,
            auth,
            namespace,
            ca_cert,
        })
    }
}

fn require_https_unless_loopback(url: &url::Url) -> Result<(), String> {
    if url.scheme() == "https" {
        return Ok(());
    }
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if url.scheme() == "http" && loopback {
        return Ok(());
    }
    Err(format!(
        "{ADDR_KEY} must be an https URL (or http on loopback, for a dev server or an agent \
         sidecar): the client token and every secret travel over it"
    ))
}

fn required<'a>(config: &'a Config, key: &str, method: &str) -> Result<&'a str, String> {
    optional(config, key).ok_or_else(|| format!("{key} is required when {AUTH_KEY}={method}"))
}

fn optional<'a>(config: &'a Config, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// A client token and what is known about its lease.
struct Session {
    token: String,
    obtained_at: Instant,
    /// `None`: no lease (a root or periodic-less token).
    ttl: Option<Duration>,
    renewable: bool,
}

impl Session {
    fn expired(&self) -> bool {
        self.ttl
            .is_some_and(|ttl| self.obtained_at.elapsed() >= ttl)
    }

    fn due_for_renewal(&self) -> bool {
        self.renewable
            && self
                .ttl
                .is_some_and(|ttl| self.obtained_at.elapsed() >= ttl.mul_f64(2.0 / 3.0))
    }
}

/// Reads `vault://<mount>/<path>` KV v2 documents.
pub struct VaultSecretSource {
    settings: VaultSettings,
    client: crate::transport::HttpClient,
    /// Held across the login `await`s on purpose: one login at a time, and
    /// every concurrent fetch waits for it rather than logging in too.
    session: tokio::sync::Mutex<Option<Session>>,
    logins: AtomicU64,
    renewals: AtomicU64,
}

impl VaultSecretSource {
    /// Build the adapter. No network I/O: the first fetch logs in.
    ///
    /// # Errors
    ///
    /// When the CA file cannot be read or is not PEM, or the HTTP client
    /// cannot be built.
    pub fn new(settings: VaultSettings) -> Result<Self, String> {
        let mut builder = crate::transport::HttpClient::builder()
            .crate_user_agent()
            .timeout(REQUEST_TIMEOUT);
        if let Some(path) = &settings.ca_cert {
            let pem = std::fs::read(path).map_err(|error| {
                format!(
                    "{CACERT_KEY}: cannot read {}: {}",
                    path.display(),
                    error.kind()
                )
            })?;
            builder = builder.add_root_certificate_pem(&pem).map_err(|_| {
                format!("{CACERT_KEY}: {} is not a PEM certificate", path.display())
            })?;
        }
        let client = builder
            .build()
            .map_err(|_| "cannot build the Vault HTTP client".to_owned())?;
        Ok(Self {
            settings,
            client,
            session: tokio::sync::Mutex::new(None),
            logins: AtomicU64::new(0),
            renewals: AtomicU64::new(0),
        })
    }

    /// Read the adapter's settings from configuration and build it.
    ///
    /// # Errors
    ///
    /// See [`VaultSettings::from_config`] and [`Self::new`].
    pub fn from_config(config: &Config) -> Result<Self, String> {
        Self::new(VaultSettings::from_config(config)?)
    }

    #[must_use]
    pub fn settings(&self) -> &VaultSettings {
        &self.settings
    }

    /// How many logins have happened — the re-login proof in tests.
    #[must_use]
    pub fn logins(&self) -> u64 {
        self.logins.load(Ordering::Acquire)
    }

    /// How many `renew-self` calls succeeded — the renewal proof in tests.
    #[must_use]
    pub fn renewals(&self) -> u64 {
        self.renewals.load(Ordering::Acquire)
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{path}", self.settings.addr)
    }

    fn request(
        &self,
        request: crate::transport::HttpRequest,
        token: Option<&str>,
    ) -> crate::transport::HttpRequest {
        let mut request = request;
        if let Some(namespace) = &self.settings.namespace {
            request = request.header("X-Vault-Namespace", namespace);
        }
        if let Some(token) = token {
            request = request.header("X-Vault-Token", token);
        }
        request
    }

    /// A usable client token: the current one, renewed if due, or a fresh
    /// login.
    async fn token(&self, force_login: bool) -> Result<String, &'static str> {
        let mut session = self.session.lock().await;
        if !force_login
            && let Some(current) = session.as_mut()
            && !current.expired()
        {
            if current.due_for_renewal() {
                match self.renew(&current.token).await {
                    Ok(lease) => {
                        current.obtained_at = Instant::now();
                        current.ttl = lease.ttl;
                        current.renewable = lease.renewable;
                        self.renewals.fetch_add(1, Ordering::AcqRel);
                        return Ok(current.token.clone());
                    }
                    Err(detail) => {
                        tracing::debug!(detail, "Vault token renewal failed; logging in again");
                    }
                }
            } else {
                return Ok(current.token.clone());
            }
        }
        let fresh = self.login().await?;
        self.logins.fetch_add(1, Ordering::AcqRel);
        let token = fresh.token.clone();
        *session = Some(fresh);
        Ok(token)
    }

    async fn login(&self) -> Result<Session, &'static str> {
        match &self.settings.auth {
            VaultAuth::Token { token } => {
                let token = token.read().await?;
                // `lookup-self` tells us whether the token has a lease to
                // renew. A token whose policy forbids it is used as given.
                let lease = match self.lookup_self(&token).await {
                    Ok(lease) => lease,
                    Err(detail) => {
                        tracing::debug!(
                            detail,
                            "Vault token lookup-self failed; using the token as given"
                        );
                        Lease {
                            ttl: None,
                            renewable: false,
                        }
                    }
                };
                Ok(Session {
                    token,
                    obtained_at: Instant::now(),
                    ttl: lease.ttl,
                    renewable: lease.renewable,
                })
            }
            VaultAuth::AppRole {
                mount,
                role_id,
                secret_id,
            } => {
                let secret_id = secret_id.read().await?;
                self.login_with(
                    &format!("auth/{mount}/login"),
                    &serde_json::json!({ "role_id": role_id, "secret_id": secret_id }),
                )
                .await
            }
            VaultAuth::Kubernetes {
                mount,
                role,
                jwt_path,
            } => {
                let jwt = read_credential_file(jwt_path)
                    .await
                    .map_err(|_| "service-account token unreadable")?;
                self.login_with(
                    &format!("auth/{mount}/login"),
                    &serde_json::json!({ "role": role, "jwt": jwt }),
                )
                .await
            }
        }
    }

    async fn login_with(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<Session, &'static str> {
        let response = self
            .request(self.client.post(self.url(path)).json(body), None)
            .send()
            .await
            .map_err(|error| redacted_transport_error(&error))?;
        let status = response.status();
        if !status.is_success() {
            return Err(match status.as_u16() {
                400 | 403 => "login refused",
                503 => "sealed",
                _ => status_class(status),
            });
        }
        let body: LoginResponse = read_json(response).await?;
        let auth = body.auth.ok_or("login response has no auth")?;
        let token = auth
            .client_token
            .filter(|token| !token.is_empty())
            .ok_or("login response has no token")?;
        Ok(Session {
            token,
            obtained_at: Instant::now(),
            ttl: lease_duration(auth.lease_duration),
            renewable: auth.renewable.unwrap_or(false),
        })
    }

    async fn lookup_self(&self, token: &str) -> Result<Lease, &'static str> {
        let response = self
            .request(
                self.client.get(self.url("auth/token/lookup-self")),
                Some(token),
            )
            .send()
            .await
            .map_err(|error| redacted_transport_error(&error))?;
        if !response.status().is_success() {
            return Err(status_class(response.status()));
        }
        let body: LookupResponse = read_json(response).await?;
        let data = body.data.ok_or("lookup response has no data")?;
        Ok(Lease {
            ttl: lease_duration(data.ttl),
            renewable: data.renewable.unwrap_or(false),
        })
    }

    async fn renew(&self, token: &str) -> Result<Lease, &'static str> {
        let response = self
            .request(
                self.client
                    .post(self.url("auth/token/renew-self"))
                    .json(&serde_json::json!({})),
                Some(token),
            )
            .send()
            .await
            .map_err(|error| redacted_transport_error(&error))?;
        if !response.status().is_success() {
            return Err(status_class(response.status()));
        }
        let body: LoginResponse = read_json(response).await?;
        let auth = body.auth.ok_or("renew response has no auth")?;
        Ok(Lease {
            ttl: lease_duration(auth.lease_duration),
            renewable: auth.renewable.unwrap_or(false),
        })
    }

    /// One KV v2 read with a token; `Ok(None)` means the token was refused
    /// (`403`) so the caller may log in again and retry once.
    async fn read_once(
        &self,
        locator: &SecretLocator,
        token: &str,
    ) -> Result<Option<FetchedSecret>, SecretSourceError> {
        let (mount, path) = split_target(locator)?;
        let unavailable = |detail: &str| SecretSourceError::Unavailable {
            locator: locator.to_string(),
            detail: detail.to_owned(),
        };
        let response = self
            .request(
                self.client.get(self.url(&format!("{mount}/data/{path}"))),
                Some(token),
            )
            .send()
            .await
            .map_err(|error| unavailable(redacted_transport_error(&error)))?;
        let status = response.status();
        match status.as_u16() {
            200 => {}
            403 => return Ok(None),
            404 => {
                return Err(SecretSourceError::NotFound {
                    locator: locator.to_string(),
                });
            }
            503 => return Err(unavailable("sealed")),
            _ => return Err(unavailable(status_class(status))),
        }
        let body: KvReadResponse = read_json(response).await.map_err(unavailable)?;
        let data = body
            .data
            .ok_or_else(|| unavailable("response has no data"))?;
        // A deleted or destroyed version answers 200 with `data: null`.
        let Some(document) = data.data else {
            return Err(SecretSourceError::NotFound {
                locator: locator.to_string(),
            });
        };
        if !document.is_object() {
            return Err(SecretSourceError::Malformed {
                locator: locator.to_string(),
                detail: "KV data is not an object".to_owned(),
            });
        }
        let version = data
            .metadata
            .and_then(|metadata| metadata.version)
            .map_or_else(|| "unknown".to_owned(), |version| version.to_string());
        let text =
            serde_json::to_string(&document).map_err(|_| unavailable("response not json"))?;
        Ok(Some(FetchedSecret::new(text, version)))
    }
}

impl SecretSource for VaultSecretSource {
    fn scheme(&self) -> Scheme {
        Scheme::Vault
    }

    fn fetch<'a>(&'a self, locator: &'a SecretLocator) -> SecretFetchFuture<'a> {
        Box::pin(async move {
            let unavailable = |detail: &str| SecretSourceError::Unavailable {
                locator: locator.to_string(),
                detail: detail.to_owned(),
            };
            let token = self.token(false).await.map_err(unavailable)?;
            if let Some(fetched) = self.read_once(locator, &token).await? {
                return Ok(fetched);
            }
            // The token was refused: revoked, expired under us, or a policy
            // change. One fresh login, one retry; a second refusal is the
            // answer.
            let token = self.token(true).await.map_err(unavailable)?;
            self.read_once(locator, &token)
                .await?
                .ok_or_else(|| unavailable("forbidden"))
        })
    }
}

impl fmt::Debug for VaultSecretSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultSecretSource")
            .field("addr", &self.settings.addr)
            .field("auth", &self.settings.auth.method())
            .field("namespace", &self.settings.namespace)
            .finish_non_exhaustive()
    }
}

/// `vault://<mount>/<path>`: the first segment is the mount, the rest the
/// secret path. A mount that itself contains `/` cannot be referenced this
/// way, which is documented rather than guessed at.
fn split_target(locator: &SecretLocator) -> Result<(&str, &str), SecretSourceError> {
    let target = locator.target().trim_matches('/');
    match target.split_once('/') {
        Some((mount, path)) if !mount.is_empty() && !path.trim_matches('/').is_empty() => {
            Ok((mount, path.trim_matches('/')))
        }
        _ => Err(SecretSourceError::Malformed {
            locator: locator.to_string(),
            detail: "expected vault://<mount>/<path>#<key>".to_owned(),
        }),
    }
}

struct Lease {
    ttl: Option<Duration>,
    renewable: bool,
}

fn lease_duration(seconds: Option<u64>) -> Option<Duration> {
    seconds
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
}

#[derive(Deserialize)]
struct LoginResponse {
    auth: Option<AuthBlock>,
}

#[derive(Deserialize)]
struct AuthBlock {
    client_token: Option<String>,
    lease_duration: Option<u64>,
    renewable: Option<bool>,
}

#[derive(Deserialize)]
struct LookupResponse {
    data: Option<LookupData>,
}

#[derive(Deserialize)]
struct LookupData {
    ttl: Option<u64>,
    renewable: Option<bool>,
}

#[derive(Deserialize)]
struct KvReadResponse {
    data: Option<KvData>,
}

#[derive(Deserialize)]
struct KvData {
    data: Option<serde_json::Value>,
    metadata: Option<KvMetadata>,
}

#[derive(Deserialize)]
struct KvMetadata {
    version: Option<u64>,
}

async fn read_json<T: serde::de::DeserializeOwned>(
    response: crate::transport::HttpResponse,
) -> Result<T, &'static str> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
        return Err("response too large");
    }
    let bytes = response.bytes().await.map_err(|_| "body error")?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("response too large");
    }
    serde_json::from_slice(&bytes).map_err(|_| "response not json")
}

const fn status_class(status: http::StatusCode) -> &'static str {
    match status.as_u16() {
        400..=499 => "http 4xx",
        500..=599 => "http 5xx",
        _ => "http error status",
    }
}

/// A transport error can quote the URL; keep to the kind so nothing else can
/// ride along.
fn redacted_transport_error(error: &crate::transport::HttpError) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_body() || error.is_decode() {
        "body error"
    } else {
        "request error"
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config(pairs: &[(&str, &str)]) -> Config {
        Config::from_map(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<HashMap<_, _>>(),
        )
    }

    #[test]
    fn auth_method_is_explicit_and_each_method_names_its_missing_credential() {
        let addr = ("MCP_VAULT_ADDR", "https://vault.example:8200/");
        let no_method = VaultSettings::from_config(&config(&[addr])).unwrap_err();
        assert!(no_method.contains("MCP_VAULT_AUTH"), "{no_method}");
        let unknown =
            VaultSettings::from_config(&config(&[addr, ("MCP_VAULT_AUTH", "aws")])).unwrap_err();
        assert!(unknown.contains("kubernetes, approle, token"), "{unknown}");
        for (method, missing) in [
            ("token", "MCP_VAULT_TOKEN"),
            ("approle", "MCP_VAULT_ROLE_ID"),
            ("kubernetes", "MCP_VAULT_ROLE"),
        ] {
            let error = VaultSettings::from_config(&config(&[addr, ("MCP_VAULT_AUTH", method)]))
                .unwrap_err();
            assert!(error.contains(missing), "{method}: {error}");
        }
        let settings = VaultSettings::from_config(&config(&[
            addr,
            ("MCP_VAULT_AUTH", "Kubernetes"),
            ("MCP_VAULT_ROLE", "mcp-devtools"),
            ("MCP_VAULT_NAMESPACE", "admin/platform"),
        ]))
        .unwrap();
        assert_eq!(settings.addr, "https://vault.example:8200");
        assert_eq!(settings.namespace.as_deref(), Some("admin/platform"));
        match settings.auth {
            VaultAuth::Kubernetes {
                mount,
                role,
                jwt_path,
            } => {
                assert_eq!(mount, "kubernetes");
                assert_eq!(role, "mcp-devtools");
                assert_eq!(jwt_path, PathBuf::from(DEFAULT_JWT_PATH));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn plain_http_is_loopback_only() {
        let remote = VaultSettings::from_config(&config(&[
            ("MCP_VAULT_ADDR", "http://vault.internal:8200"),
            ("MCP_VAULT_AUTH", "token"),
            ("MCP_VAULT_TOKEN", "t"),
        ]));
        assert!(remote.unwrap_err().contains("https"));
        assert!(
            VaultSettings::from_config(&config(&[
                ("MCP_VAULT_ADDR", "http://127.0.0.1:8200"),
                ("MCP_VAULT_AUTH", "token"),
                ("MCP_VAULT_TOKEN", "t"),
            ]))
            .is_ok()
        );
    }

    #[test]
    fn provider_credentials_may_be_files_but_not_other_references() {
        let base = [
            ("MCP_VAULT_ADDR", "https://vault.example"),
            ("MCP_VAULT_AUTH", "approle"),
            ("MCP_VAULT_ROLE_ID", "r"),
        ];
        let mut with_file = base.to_vec();
        with_file.push(("MCP_VAULT_SECRET_ID", "file:///run/secrets/secret-id"));
        let settings = VaultSettings::from_config(&config(&with_file)).unwrap();
        match &settings.auth {
            VaultAuth::AppRole { secret_id, .. } => {
                assert_eq!(secret_id.file(), Some(Path::new("/run/secrets/secret-id")));
            }
            other => panic!("{other:?}"),
        }
        assert!(!format!("{settings:?}").contains("hunter"));

        let mut with_vault = base.to_vec();
        with_vault.push(("MCP_VAULT_SECRET_ID", "vault://secret/x#id"));
        let error = VaultSettings::from_config(&config(&with_vault)).unwrap_err();
        assert!(error.contains("MCP_VAULT_SECRET_ID"), "{error}");

        let mut with_key = base.to_vec();
        with_key.push(("MCP_VAULT_SECRET_ID", "file:///run/secrets/x#id"));
        assert!(VaultSettings::from_config(&config(&with_key)).is_err());

        let mut literal = base.to_vec();
        literal.push(("MCP_VAULT_SECRET_ID", "hunter2-secret-id"));
        let settings = VaultSettings::from_config(&config(&literal)).unwrap();
        assert!(
            !format!("{settings:?}").contains("hunter2"),
            "Debug leaks the secret id"
        );
    }

    #[test]
    fn target_splits_at_the_first_slash() {
        let ok = SecretLocator::new(Scheme::Vault, "secret/mcp/grafana");
        assert_eq!(split_target(&ok).unwrap(), ("secret", "mcp/grafana"));
        let trimmed = SecretLocator::new(Scheme::Vault, "/kv/app/");
        assert_eq!(split_target(&trimmed).unwrap(), ("kv", "app"));
        for bad in ["secret", "secret/", "/x"] {
            let locator = SecretLocator::new(Scheme::Vault, bad);
            assert!(
                matches!(
                    split_target(&locator).unwrap_err(),
                    SecretSourceError::Malformed { .. }
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn session_lease_arithmetic() {
        let mut session = Session {
            token: "t".to_owned(),
            obtained_at: Instant::now() - Duration::from_secs(70),
            ttl: Some(Duration::from_secs(90)),
            renewable: true,
        };
        assert!(!session.expired());
        assert!(
            session.due_for_renewal(),
            "70 s of a 90 s lease is past two thirds"
        );
        session.renewable = false;
        assert!(!session.due_for_renewal());
        session.ttl = Some(Duration::from_mins(1));
        assert!(session.expired());
        session.ttl = None;
        assert!(!session.expired());
    }
}
