//! Per-principal rate limit (plan §8 "Abuse controls", WP C.6).
//!
//! A token bucket per subject, applied in the bearer middleware once the
//! token has validated and the scope has passed — so the limit keys on a
//! *validated* identity, and an attacker cannot exhaust another
//! principal's budget by naming them. Single replica, in process (CF-16:
//! a shared limiter is part of the horizontal-scaling design, not this).
//!
//! On the request path, so: one `Mutex`, one `HashMap<String, Bucket>`
//! lookup by `&str` — no allocation on a hit; an insert only for a subject
//! never seen. The map is bounded: past [`MAX_TRACKED`] subjects, buckets
//! idle longer than [`IDLE_EVICTION`] are dropped on the next insert, so
//! a flood of fresh subjects (which are still validated tokens) cannot
//! grow it without bound.
//!
//! A refused request is `429 Too Many Requests` with `Retry-After` in
//! whole seconds and the JSON envelope the other refusals use. Nothing
//! about it is journaled: a rate limit is a capacity control, not a
//! security decision, and the journal is evidence of decisions.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::config::Config;

/// Config key: sustained requests per second per principal (`0` or
/// absent: off). Fractions allowed (`0.5` is one every two seconds).
pub const RATE_KEY: &str = "MCP_RATE_LIMIT_PER_PRINCIPAL";
/// Config key: burst size (bucket capacity). Default: twice the rate,
/// at least 1.
pub const BURST_KEY: &str = "MCP_RATE_LIMIT_BURST";

/// Past this many tracked subjects, idle buckets are evicted on insert.
pub const MAX_TRACKED: usize = 10_000;
/// A bucket untouched this long is idle.
pub const IDLE_EVICTION: Duration = Duration::from_mins(1);

/// What the middleware enforces.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimitSettings {
    pub per_second: f64,
    pub burst: f64,
}

impl RateLimitSettings {
    /// Read [`RATE_KEY`] and [`BURST_KEY`]; `None` when off.
    ///
    /// # Errors
    ///
    /// When a value is set but not a positive number.
    pub fn from_config(config: &Config) -> Result<Option<Self>, String> {
        let Some(rate) = config
            .get(RATE_KEY)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let per_second: f64 = rate
            .parse()
            .ok()
            .filter(|value: &f64| value.is_finite() && *value >= 0.0)
            .ok_or_else(|| format!("{RATE_KEY} must be a non-negative number, got {rate:?}"))?;
        if per_second == 0.0 {
            return Ok(None);
        }
        let burst = match config
            .get(BURST_KEY)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(value) => value
                .parse::<f64>()
                .ok()
                .filter(|value| value.is_finite() && *value >= 1.0)
                .ok_or_else(|| {
                    format!("{BURST_KEY} must be a number of at least 1, got {value:?}")
                })?,
            None => (per_second * 2.0).max(1.0),
        };
        Ok(Some(Self { per_second, burst }))
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    refilled: Instant,
}

/// The limiter. One per deployment surface (`/mcp` and, in C.4, the admin
/// API get their own).
#[derive(Debug)]
pub struct RateLimiter {
    settings: RateLimitSettings,
    buckets: Mutex<HashMap<String, Bucket>>,
    refused: AtomicU64,
}

/// The outcome of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Refuse; retry after this many whole seconds (at least 1).
    Refuse {
        retry_after_secs: u64,
    },
}

impl RateLimiter {
    #[must_use]
    pub fn new(settings: RateLimitSettings) -> Self {
        Self {
            settings,
            buckets: Mutex::new(HashMap::new()),
            refused: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub const fn settings(&self) -> RateLimitSettings {
        self.settings
    }

    /// Requests refused so far.
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Take one token for `subject`, now.
    pub fn check(&self, subject: &str) -> Verdict {
        self.check_at(subject, Instant::now())
    }

    /// [`Self::check`] at an explicit instant (tests).
    pub fn check_at(&self, subject: &str, now: Instant) -> Verdict {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let verdict = if let Some(bucket) = buckets.get_mut(subject) {
            let elapsed = now.saturating_duration_since(bucket.refilled).as_secs_f64();
            bucket.tokens =
                (bucket.tokens + elapsed * self.settings.per_second).min(self.settings.burst);
            bucket.refilled = now;
            Self::take(bucket, self.settings.per_second)
        } else {
            if buckets.len() >= MAX_TRACKED {
                buckets.retain(|_, bucket| {
                    now.saturating_duration_since(bucket.refilled) < IDLE_EVICTION
                });
            }
            let mut bucket = Bucket {
                tokens: self.settings.burst,
                refilled: now,
            };
            let verdict = Self::take(&mut bucket, self.settings.per_second);
            buckets.insert(subject.to_owned(), bucket);
            verdict
        };
        drop(buckets);
        if matches!(verdict, Verdict::Refuse { .. }) {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
        verdict
    }

    fn take(bucket: &mut Bucket, per_second: f64) -> Verdict {
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Verdict::Allow
        } else {
            let wait = (1.0 - bucket.tokens) / per_second;
            Verdict::Refuse {
                retry_after_secs: retry_after(wait),
            }
        }
    }

    /// Subjects currently tracked (tests).
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

fn retry_after(wait_seconds: f64) -> u64 {
    let Ok(wait) = Duration::try_from_secs_f64(wait_seconds) else {
        return u64::MAX;
    };
    wait.as_secs()
        .saturating_add(u64::from(wait.subsec_nanos() > 0))
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map;

    fn config(pairs: &[(&str, &str)]) -> Config {
        Config::from_map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<Map<_, _>>(),
        )
    }

    #[test]
    fn settings_parse_and_default_the_burst() {
        assert_eq!(RateLimitSettings::from_config(&config(&[])).unwrap(), None);
        assert_eq!(
            RateLimitSettings::from_config(&config(&[(RATE_KEY, "0")])).unwrap(),
            None
        );
        let settings = RateLimitSettings::from_config(&config(&[(RATE_KEY, "5")]))
            .unwrap()
            .unwrap();
        assert_eq!(
            settings,
            RateLimitSettings {
                per_second: 5.0,
                burst: 10.0
            }
        );
        let settings =
            RateLimitSettings::from_config(&config(&[(RATE_KEY, "0.5"), (BURST_KEY, "3")]))
                .unwrap()
                .unwrap();
        assert_eq!(
            settings,
            RateLimitSettings {
                per_second: 0.5,
                burst: 3.0
            }
        );
        assert!(RateLimitSettings::from_config(&config(&[(RATE_KEY, "many")])).is_err());
        assert!(
            RateLimitSettings::from_config(&config(&[(RATE_KEY, "1"), (BURST_KEY, "0")])).is_err()
        );
    }

    #[test]
    fn burst_then_refill_per_subject() {
        let limiter = RateLimiter::new(RateLimitSettings {
            per_second: 2.0,
            burst: 3.0,
        });
        let start = Instant::now();
        for _ in 0..3 {
            assert_eq!(limiter.check_at("alice", start), Verdict::Allow);
        }
        assert_eq!(
            limiter.check_at("alice", start),
            Verdict::Refuse {
                retry_after_secs: 1
            }
        );
        // Another subject has its own bucket.
        assert_eq!(limiter.check_at("bob", start), Verdict::Allow);
        // Half a second refills one token at 2/s.
        assert_eq!(
            limiter.check_at("alice", start + Duration::from_millis(500)),
            Verdict::Allow
        );
        assert_eq!(
            limiter.check_at("alice", start + Duration::from_millis(500)),
            Verdict::Refuse {
                retry_after_secs: 1
            }
        );
        assert_eq!(limiter.refused(), 2);
        // Never above the burst.
        for _ in 0..3 {
            assert_eq!(
                limiter.check_at("alice", start + Duration::from_mins(1)),
                Verdict::Allow
            );
        }
        assert_eq!(
            limiter.check_at("alice", start + Duration::from_mins(1)),
            Verdict::Refuse {
                retry_after_secs: 1
            }
        );
    }

    #[test]
    fn slow_rates_report_a_longer_retry_after() {
        let limiter = RateLimiter::new(RateLimitSettings {
            per_second: 0.1,
            burst: 1.0,
        });
        let start = Instant::now();
        assert_eq!(limiter.check_at("alice", start), Verdict::Allow);
        assert_eq!(
            limiter.check_at("alice", start),
            Verdict::Refuse {
                retry_after_secs: 10
            }
        );
    }

    #[test]
    fn idle_buckets_are_evicted_past_the_cap() {
        let limiter = RateLimiter::new(RateLimitSettings {
            per_second: 1.0,
            burst: 1.0,
        });
        let start = Instant::now();
        for index in 0..MAX_TRACKED {
            limiter.check_at(&format!("s{index}"), start);
        }
        assert_eq!(limiter.tracked(), MAX_TRACKED);
        // One more, after everyone else went idle: the map shrinks.
        limiter.check_at("fresh", start + IDLE_EVICTION + Duration::from_secs(1));
        assert_eq!(limiter.tracked(), 1);
    }
}
