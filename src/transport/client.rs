//! The crate's outbound HTTP boundary.
//!
//! Every HTTP request this process sends — vendor API calls, streamed
//! artifact downloads, JWKS and OIDC discovery fetches, EMA token exchanges,
//! Vault, the audit forwarder, the remote admin client, and the health
//! probe — goes through the types in this module. It is the only module in
//! `src/` that names `reqwest`; `tests/outbound_http_boundary_tests.rs`
//! locks that.
//!
//! ## Why a facade and not a port trait
//!
//! [`crate::ports`] reserves traits for boundaries with a real second
//! implementation. This boundary has one adapter today, so it is a concrete
//! newtype layer: zero dispatch cost, no invented seam, and the compiler
//! still stops `reqwest` types from reaching a controller, vendor, or auth
//! module. The surface below is deliberately the set of knobs the
//! application actually uses. That list *is* the contract a second adapter
//! (hyper + hyper-util) would have to satisfy, and the point at which this
//! becomes a trait in `ports/`.
//!
//! What the surface commits a future adapter to, beyond the obvious:
//!
//! - The underlying adapter can follow redirects by default, but shared API
//!   clients explicitly disable them with [`HttpClientBuilder::no_redirects`].
//!   The transport authorizes and follows bounded GET hops itself.
//! - **Transparent decompression is on by default** and disabled for the
//!   streaming client, which accounts for wire bytes itself
//!   ([`HttpClientBuilder::no_decompression`]).
//! - **Safe automatic retries are on by default** (`reqwest` retries only
//!   transport errors known to be safe) and disabled where a replay is never
//!   acceptable ([`HttpClientBuilder::no_retries`]).
//! - **`HTTPS_PROXY` / `NO_PROXY` are honoured** from the environment.
//! - **Error classification is by predicate** ([`HttpError::is_timeout`] and
//!   friends), never by message text: every caller maps the kind to its own
//!   vocabulary, and several redact the message on purpose.
//! - **`text()` decodes by the response charset**, falling back to UTF-8.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use futures::{FutureExt as _, Stream, TryFutureExt as _, TryStreamExt as _};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use serde::Serialize;

/// A pooled HTTP client. Cheap to clone: clones share the connection pool.
#[derive(Clone, Debug)]
pub struct HttpClient {
    inner: reqwest::Client,
}

impl HttpClient {
    /// Start configuring a client. Defaults: redirects followed, safe
    /// retries on, decompression on, no timeout, no `User-Agent`.
    #[must_use]
    pub fn builder() -> HttpClientBuilder {
        HttpClientBuilder::default()
    }

    /// Begin a request. `url` may be a `&str`, `String`, or [`url::Url`];
    /// an unparseable URL surfaces from [`HttpRequest::send`].
    pub fn request(&self, method: Method, url: impl AsRef<str>) -> HttpRequest {
        self.request_str(method, url.as_ref())
    }

    /// `GET url`.
    pub fn get(&self, url: impl AsRef<str>) -> HttpRequest {
        self.request_str(Method::GET, url.as_ref())
    }

    /// `POST url`.
    pub fn post(&self, url: impl AsRef<str>) -> HttpRequest {
        self.request_str(Method::POST, url.as_ref())
    }

    fn request_str(&self, method: Method, url: &str) -> HttpRequest {
        HttpRequest {
            inner: self.inner.request(method, url),
        }
    }
}

/// Configuration for one [`HttpClient`]. Every method is a knob some part
/// of the crate needs; see the module docs for what the defaults commit to.
#[derive(Debug, Default)]
pub struct HttpClientBuilder {
    inner: reqwest::ClientBuilder,
}

impl HttpClientBuilder {
    /// Send `value` as the `User-Agent` on every request. An invalid header
    /// value is reported by [`Self::build`].
    #[must_use]
    pub fn user_agent(self, value: &str) -> Self {
        Self {
            inner: self.inner.user_agent(value),
        }
    }

    /// Identify as this crate: `mcp-server-devtools/<version>`.
    #[must_use]
    pub fn crate_user_agent(self) -> Self {
        self.user_agent(&format!(
            "{}/{}",
            crate::constants::UNSCOPED_PACKAGE_NAME,
            crate::constants::VERSION
        ))
    }

    /// Total time allowed per request, connect through body read. A
    /// per-request [`HttpRequest::timeout`] overrides it.
    #[must_use]
    pub fn timeout(self, timeout: Duration) -> Self {
        Self {
            inner: self.inner.timeout(timeout),
        }
    }

    /// Never follow a redirect: a 3xx is returned to the caller as-is. For
    /// clients that attach a credential meant for exactly one host.
    #[must_use]
    pub fn no_redirects(self) -> Self {
        Self {
            inner: self.inner.redirect(reqwest::redirect::Policy::none()),
        }
    }

    /// Never resend a request automatically, even on a transport error the
    /// adapter would otherwise consider safe to retry. For requests whose
    /// replay is never acceptable (token grants, assertions).
    #[must_use]
    pub fn no_retries(self) -> Self {
        Self {
            inner: self.inner.retry(reqwest::retry::never()),
        }
    }

    /// Deliver bodies as they came off the wire: no `Accept-Encoding` is
    /// advertised and no `Content-Encoding` is decoded. For callers that
    /// bound and decode the encoded stream themselves.
    #[must_use]
    pub fn no_decompression(self) -> Self {
        Self {
            inner: self
                .inner
                .gzip(false)
                .brotli(false)
                .deflate(false)
                .zstd(false),
        }
    }

    /// Trust one extra CA, given as a single PEM certificate, in addition to
    /// the platform roots.
    ///
    /// # Errors
    ///
    /// When `pem` is not a PEM-encoded X.509 certificate.
    pub fn add_root_certificate_pem(self, pem: &[u8]) -> Result<Self, HttpError> {
        let certificate = reqwest::Certificate::from_pem(pem).map_err(HttpError::from)?;
        Ok(Self {
            inner: self.inner.add_root_certificate(certificate),
        })
    }

    /// Build the client. Initialises the TLS backend and the connection
    /// pool; no request is sent.
    ///
    /// # Errors
    ///
    /// When the TLS backend cannot be initialised or a configured value
    /// (such as the user agent) is invalid.
    pub fn build(self) -> Result<HttpClient, HttpError> {
        self.inner
            .build()
            .map(|inner| HttpClient { inner })
            .map_err(HttpError::from)
    }
}

/// A request under construction. Consumed by [`Self::send`].
#[derive(Debug)]
pub struct HttpRequest {
    inner: reqwest::RequestBuilder,
}

impl HttpRequest {
    /// Add a header. Accepts any pairing of [`HeaderName`] / `&str` and
    /// [`HeaderValue`] / `&str` / `String`; an invalid name or value is
    /// reported by [`Self::send`].
    #[must_use]
    pub fn header<K, V>(self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        Self {
            inner: self.inner.header(key, value),
        }
    }

    /// Total time allowed for this request, connect through body read.
    /// Overrides the client-wide [`HttpClientBuilder::timeout`].
    #[must_use]
    pub fn timeout(self, timeout: Duration) -> Self {
        Self {
            inner: self.inner.timeout(timeout),
        }
    }

    /// `Authorization: Bearer <token>`. The value is marked sensitive so
    /// the adapter never logs it.
    #[must_use]
    pub fn bearer_auth(self, token: &str) -> Self {
        Self {
            inner: self.inner.bearer_auth(token),
        }
    }

    /// Serialise `body` as the JSON request body and set
    /// `Content-Type: application/json`.
    #[must_use]
    pub fn json<T: Serialize + ?Sized>(self, body: &T) -> Self {
        Self {
            inner: self.inner.json(body),
        }
    }

    /// Serialise `form` as a URL-encoded request body and set
    /// `Content-Type: application/x-www-form-urlencoded`.
    #[must_use]
    pub fn form<T: Serialize + ?Sized>(self, form: &T) -> Self {
        Self {
            inner: self.inner.form(form),
        }
    }

    /// Send `body` verbatim. `Vec<u8>` and `String` convert without a copy;
    /// the caller sets `Content-Type`.
    #[must_use]
    pub fn body(self, body: impl Into<Bytes>) -> Self {
        self.body_bytes(body.into())
    }

    fn body_bytes(self, body: Bytes) -> Self {
        Self {
            inner: self.inner.body(body),
        }
    }

    /// Send the request and wait for the response head. The body is read
    /// through the returned [`HttpResponse`].
    pub fn send(self) -> impl Future<Output = Result<HttpResponse, HttpError>> + Send {
        self.inner
            .send()
            .map(|result| result.map(HttpResponse::from).map_err(HttpError::from))
    }
}

/// A response head with an unread body.
#[derive(Debug)]
pub struct HttpResponse {
    inner: reqwest::Response,
}

impl From<reqwest::Response> for HttpResponse {
    fn from(inner: reqwest::Response) -> Self {
        Self { inner }
    }
}

impl HttpResponse {
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }

    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }

    pub(crate) fn url(&self) -> &url::Url {
        self.inner.url()
    }

    /// The declared `Content-Length`, when the response carries one. A
    /// transparently decompressed body reports `None`.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.inner.content_length()
    }

    /// Read the whole body as text, decoded by the response's declared
    /// charset (UTF-8 when it declares none).
    pub fn text(self) -> impl Future<Output = Result<String, HttpError>> + Send {
        self.inner.text().map_err(HttpError::from)
    }

    /// Read the whole body.
    pub fn bytes(self) -> impl Future<Output = Result<Bytes, HttpError>> + Send {
        self.inner.bytes().map_err(HttpError::from)
    }

    /// Read the next body chunk; `None` once the body is complete. Lets a
    /// caller stop at a byte bound without buffering the rest.
    pub fn chunk(&mut self) -> impl Future<Output = Result<Option<Bytes>, HttpError>> + Send + '_ {
        self.inner.chunk().map_err(HttpError::from)
    }

    /// The body as a stream of chunks.
    pub fn bytes_stream(self) -> impl Stream<Item = Result<Bytes, HttpError>> + Send {
        self.inner.bytes_stream().map_err(HttpError::from)
    }
}

/// A transport-level failure: the request could not be built or sent, or
/// the body could not be read. A non-2xx status is *not* an error here;
/// callers classify statuses themselves.
///
/// `Display` may quote the request URL (never a header), so callers that
/// log or return the text must have already decided the URL is safe to
/// show; the `is_*` predicates are the redacting alternative.
pub struct HttpError {
    inner: reqwest::Error,
}

impl From<reqwest::Error> for HttpError {
    fn from(inner: reqwest::Error) -> Self {
        Self { inner }
    }
}

impl HttpError {
    /// The request or body read exceeded a configured timeout.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        self.inner.is_timeout()
    }

    /// The connection could not be established (DNS, TCP, TLS).
    #[must_use]
    pub fn is_connect(&self) -> bool {
        self.inner.is_connect()
    }

    /// The request failed while being sent. Includes some connection
    /// resets that arrive before any response byte.
    #[must_use]
    pub fn is_request(&self) -> bool {
        self.inner.is_request()
    }

    /// The response body could not be read.
    #[must_use]
    pub fn is_body(&self) -> bool {
        self.inner.is_body()
    }

    /// The response body could not be decoded (charset, JSON).
    #[must_use]
    pub fn is_decode(&self) -> bool {
        self.inner.is_decode()
    }

    /// An error carrying an HTTP status. Never produced by this module's
    /// own calls (statuses are returned, not raised); kept so callers can
    /// classify exhaustively.
    #[must_use]
    pub fn is_status(&self) -> bool {
        self.inner.is_status()
    }
}

impl fmt::Debug for HttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, formatter)
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, formatter)
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.inner)
    }
}
