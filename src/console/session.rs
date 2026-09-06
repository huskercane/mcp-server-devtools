//! Bounded in-memory state for the console (ADR-013): browser sessions
//! holding the administrator's bearer, and the logins in flight between
//! the redirect to the identity provider and its callback.
//!
//! Everything here lives on the process that serves the control plane and
//! nowhere else: never on disk, never in a cookie beyond an opaque id. A
//! restart means a new sign-in, not lost work. Both maps are bounded: past
//! the cap, expired entries are swept and, if that is not enough, the entry
//! nearest its expiry is evicted rather than the map grown.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use base64::Engine as _;

struct Timed<T> {
    value: T,
    expires: Instant,
}

/// A map from random id to value, bounded and expiring.
struct Bounded<T> {
    inner: Mutex<HashMap<String, Timed<T>>>,
    cap: usize,
}

impl<T> Bounded<T> {
    fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            cap: cap.max(1),
        }
    }

    /// Insert under a fresh 256-bit id and return it.
    fn insert(&self, value: T, ttl: Duration) -> String {
        let id = random_id();
        let now = Instant::now();
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= self.cap {
            map.retain(|_, entry| entry.expires > now);
        }
        if map.len() >= self.cap
            && let Some(soonest) = map
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(id, _)| id.clone())
        {
            map.remove(&soonest);
        }
        map.insert(
            id.clone(),
            Timed {
                value,
                expires: now + ttl,
            },
        );
        id
    }

    /// Remove and return the entry, if present and unexpired.
    fn take(&self, id: &str) -> Option<T> {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = map.remove(id)?;
        (entry.expires > Instant::now()).then_some(entry.value)
    }

    fn remove(&self, id: &str) -> bool {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.remove(id).is_some()
    }

    fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

impl<T: Clone> Bounded<T> {
    /// A copy of the value, if present and unexpired; an expired entry is
    /// dropped on the way.
    fn get(&self, id: &str) -> Option<T> {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let expired = map
            .get(id)
            .is_some_and(|entry| entry.expires <= Instant::now());
        if expired {
            map.remove(id);
            return None;
        }
        map.get(id).map(|entry| entry.value.clone())
    }
}

/// 32 random bytes, base64url without padding: the session and login ids.
pub fn random_id() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Browser sessions: id → the bearer the admin API sees on every render.
pub struct SessionStore(Bounded<String>);

impl SessionStore {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self(Bounded::new(cap))
    }

    /// Hold `token` for `ttl` and return the session id the cookie carries.
    pub fn insert(&self, token: String, ttl: Duration) -> String {
        self.0.insert(token, ttl)
    }

    /// The bearer for a live session. A clone: the token travels into the
    /// admin call as a borrowed `&str`, and a page is one call.
    #[must_use]
    pub fn token(&self, id: &str) -> Option<String> {
        self.0.get(id)
    }

    /// Drop a session (logout, or the API's own 401).
    pub fn remove(&self, id: &str) -> bool {
        self.0.remove(id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a login in flight remembers between the redirect and the callback.
#[derive(Clone)]
pub struct PendingLogin {
    pub state: String,
    pub verifier: String,
}

/// Logins in flight: pre-session id → the state and PKCE verifier bound to
/// it. Consumed by the callback, once.
pub struct PendingLogins {
    inner: Bounded<PendingLogin>,
    ttl: Duration,
}

impl PendingLogins {
    #[must_use]
    pub fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            inner: Bounded::new(cap),
            ttl,
        }
    }

    pub fn insert(&self, login: PendingLogin) -> String {
        self.inner.insert(login, self.ttl)
    }

    /// Take the login bound to `id`; a second take finds nothing.
    #[must_use]
    pub fn take(&self, id: &str) -> Option<PendingLogin> {
        self.inner.take(id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
