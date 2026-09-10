//! Shared Retry-After timing. Missing/malformed values use equal jitter.
use std::time::{Duration, SystemTime};

pub(super) fn parse(headers: &http::HeaderMap, now: SystemTime) -> Option<Duration> {
    let value = headers
        .get(http::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value.parse::<u64>().ok().map(Duration::from_secs);
    }
    httpdate::parse_http_date(value)
        .ok()
        .map(|date| date.duration_since(now).unwrap_or_default())
}

pub(super) fn jitter(attempt: usize) -> Duration {
    use rand::RngExt as _;
    jitter_with(attempt, |range| rand::rng().random_range(range))
}

fn jitter_with(
    attempt: usize,
    sample: impl FnOnce(std::ops::RangeInclusive<u64>) -> u64,
) -> Duration {
    let envelope = 100_u64 * (1_u64 << attempt.min(5));
    Duration::from_millis(sample(envelope / 2..=envelope))
}

pub(super) fn metadata(
    mut error: crate::error::McpError,
    delay: Option<Duration>,
) -> crate::error::McpError {
    if let Some(delay) = delay {
        let original = error.original.take().and_then(|value| value.render());
        error.original = Some(crate::error::OriginalError::Json(serde_json::json!({
            "retryAfterMs": u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "vendorError": original
        })));
    }
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_jitter_bounds_use_controlled_samples() {
        for attempt in [0, 1, 5, 100] {
            let envelope = 100 * (1_u64 << attempt.min(5));
            assert_eq!(
                jitter_with(attempt, |range| *range.start()),
                Duration::from_millis(envelope / 2)
            );
            assert_eq!(
                jitter_with(attempt, |range| *range.end()),
                Duration::from_millis(envelope)
            );
        }
    }

    #[tokio::test]
    async fn retry_deadlines_and_cancellation_never_send_early() {
        let policy = super::super::StreamingPolicy::new(1, 1);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let error =
            super::super::retry_stream_attempt(1, &policy, deadline, Some(Duration::from_secs(1)))
                .await
                .unwrap_err();
        assert_eq!(error.status_code, Some(408));
        assert!(error.original.unwrap().render().unwrap().contains("1000"));
        policy.cancellation.cancel();
        let error = super::super::retry_stream_attempt(
            1,
            &policy,
            deadline,
            Some(Duration::from_millis(20)),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status_code, Some(499));
    }

    #[test]
    fn parses_seconds_dates_and_rejects_invalid_values() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut headers = http::HeaderMap::new();
        assert_eq!(parse(&headers, now), None);
        for (value, expected) in [
            ("12", Some(Duration::from_secs(12))),
            ("0", Some(Duration::ZERO)),
            ("-1", None),
            ("1.5", None),
            ("18446744073709551616", None),
            ("bad", None),
        ] {
            headers.insert(http::header::RETRY_AFTER, value.parse().unwrap());
            assert_eq!(parse(&headers, now), expected);
        }
        for offset in [0, 30] {
            let date = httpdate::fmt_http_date(now + Duration::from_secs(offset));
            headers.insert(http::header::RETRY_AFTER, date.parse().unwrap());
            assert_eq!(parse(&headers, now), Some(Duration::from_secs(offset)));
        }
        headers.insert(
            http::header::RETRY_AFTER,
            httpdate::fmt_http_date(SystemTime::UNIX_EPOCH)
                .parse()
                .unwrap(),
        );
        assert_eq!(parse(&headers, now), Some(Duration::ZERO));
    }
}
