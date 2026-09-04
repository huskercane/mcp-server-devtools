//! Prometheus exposition behind the `UsageSink` port (plan §3.9
//! "Metrics", §7, §8; WP C.6).
//!
//! [`PrometheusUsageSink`] is a `UsageSink` adapter: every usage event
//! bumps in-process counters keyed by vendor, tool, decision, and outcome,
//! and a duration histogram per vendor, and `GET /metrics` renders them
//! in the text exposition format. Hand-rolled: the format is a few lines
//! per series, and a metrics crate would bring a registry, a global, and
//! a dependency tree for a page of text. No exporter type reaches the
//! domain — the sink takes the port's own `UsageEvent`.
//!
//! Labels never include the subject: metrics are unauthenticated in most
//! scrape setups, and per-principal figures live in the rollups behind
//! the admin API. Tool names are bounded by the tool surface (a few
//! hundred), which bounds series cardinality.
//!
//! `record` is on the tail of every enterprise tool call, so it is one
//! `Mutex` lock and two nested `HashMap<String, …>` lookups by `&str` —
//! no allocation on a hit, one entry per new (vendor, tool) pair for the
//! life of the process. [`FanOutUsageSink`] delivers one event to both
//! this and the rollup channel.
//!
//! Gauges that describe the process rather than usage — the journal
//! available, forwarding acknowledged and degraded, rollups degraded,
//! usage events dropped, requests rate-limited — are supplied by the
//! composition root as a [`Gauges`] callback set, so this module knows
//! nothing about the components that own them.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ports::{UsageEvent, UsageSink};

/// Config key: `on` exposes `GET /metrics` (unauthenticated; scrape it
/// from inside the cluster). Anything else leaves it off.
pub const METRICS_KEY: &str = "MCP_METRICS";

/// Histogram bucket upper bounds for tool-call duration, in seconds.
const DURATION_BUCKETS: [(&str, u128); 12] = [
    ("0.005", 5),
    ("0.01", 10),
    ("0.025", 25),
    ("0.05", 50),
    ("0.1", 100),
    ("0.25", 250),
    ("0.5", 500),
    ("1", 1_000),
    ("2.5", 2_500),
    ("5", 5_000),
    ("10", 10_000),
    ("30", 30_000),
];

#[derive(Debug, Default)]
struct ToolCounters {
    /// (decision, outcome) → count. Small: a handful of pairs per tool.
    by_result: Vec<(String, String, u64)>,
}

#[derive(Debug, Default)]
struct VendorSeries {
    tools: HashMap<String, ToolCounters>,
    histogram: [u64; 12],
    histogram_count: u64,
    histogram_sum_ms: u64,
}

/// The Prometheus adapter.
#[derive(Debug, Default)]
pub struct PrometheusUsageSink {
    vendors: Mutex<HashMap<String, VendorSeries>>,
    events: AtomicU64,
}

impl PrometheusUsageSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Events recorded so far.
    #[must_use]
    pub fn events(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    /// Render the usage series (no process gauges) in text exposition.
    pub fn render_into(&self, out: &mut String) {
        let vendors = self
            .vendors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        out.push_str(
            "# HELP mcp_tool_calls_total Tool calls by vendor, tool, decision, and outcome.\n\
             # TYPE mcp_tool_calls_total counter\n",
        );
        let mut vendor_names: Vec<&String> = vendors.keys().collect();
        vendor_names.sort();
        for vendor in &vendor_names {
            let series = &vendors[*vendor];
            let mut tools: Vec<&String> = series.tools.keys().collect();
            tools.sort();
            for tool in tools {
                for (decision, outcome, count) in &series.tools[tool].by_result {
                    let _ = writeln!(
                        out,
                        "mcp_tool_calls_total{{vendor=\"{}\",tool=\"{}\",decision=\"{}\",outcome=\"{}\"}} {count}",
                        escape(vendor),
                        escape(tool),
                        escape(decision),
                        escape(outcome)
                    );
                }
            }
        }
        out.push_str(
            "# HELP mcp_tool_call_duration_seconds Duration of dispatched tool calls by vendor.\n\
             # TYPE mcp_tool_call_duration_seconds histogram\n",
        );
        for vendor in &vendor_names {
            let series = &vendors[*vendor];
            let mut cumulative = 0u64;
            for ((bound, _), count) in DURATION_BUCKETS.iter().zip(series.histogram) {
                cumulative += count;
                let _ = writeln!(
                    out,
                    "mcp_tool_call_duration_seconds_bucket{{vendor=\"{}\",le=\"{bound}\"}} {cumulative}",
                    escape(vendor)
                );
            }
            let _ = writeln!(
                out,
                "mcp_tool_call_duration_seconds_bucket{{vendor=\"{}\",le=\"+Inf\"}} {}",
                escape(vendor),
                series.histogram_count
            );
            let _ = writeln!(
                out,
                "mcp_tool_call_duration_seconds_sum{{vendor=\"{}\"}} {}",
                escape(vendor),
                seconds_from_millis(series.histogram_sum_ms)
            );
            let _ = writeln!(
                out,
                "mcp_tool_call_duration_seconds_count{{vendor=\"{}\"}} {}",
                escape(vendor),
                series.histogram_count
            );
        }
    }
}

fn seconds_from_millis(millis: u64) -> String {
    let seconds = millis / 1_000;
    let remainder = millis % 1_000;
    if remainder == 0 {
        seconds.to_string()
    } else {
        format!("{seconds}.{remainder:03}")
            .trim_end_matches('0')
            .to_owned()
    }
}

/// Escape a label value per the exposition format.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

impl UsageSink for PrometheusUsageSink {
    fn record(&self, event: UsageEvent) {
        self.events.fetch_add(1, Ordering::Relaxed);
        let mut vendors = self
            .vendors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Two `&str` lookups; an insert (with its allocations) only for a
        // pair never seen before.
        let vendor = match vendors.get_mut(event.vendor.as_str()) {
            Some(vendor) => vendor,
            None => vendors.entry(event.vendor.clone()).or_default(),
        };
        let tool = match vendor.tools.get_mut(event.tool_name.as_str()) {
            Some(tool) => tool,
            None => vendor.tools.entry(event.tool_name.clone()).or_default(),
        };
        match tool
            .by_result
            .iter_mut()
            .find(|(decision, outcome, _)| *decision == event.decision && *outcome == event.outcome)
        {
            Some((_, _, count)) => *count += 1,
            None => tool
                .by_result
                .push((event.decision.clone(), event.outcome.clone(), 1)),
        }
        if event.decision == "allow" {
            for ((_, bound_ms), bucket) in DURATION_BUCKETS.iter().zip(vendor.histogram.iter_mut())
            {
                if event.duration_ms <= *bound_ms {
                    *bucket += 1;
                    break;
                }
            }
            vendor.histogram_count += 1;
            vendor.histogram_sum_ms = vendor
                .histogram_sum_ms
                .saturating_add(u64::try_from(event.duration_ms).unwrap_or(u64::MAX));
        }
    }

    fn dropped(&self) -> u64 {
        0
    }
}

/// One event to every sink. `dropped` reports the sum.
pub struct FanOutUsageSink {
    sinks: Vec<std::sync::Arc<dyn UsageSink>>,
}

impl FanOutUsageSink {
    #[must_use]
    pub fn new(sinks: Vec<std::sync::Arc<dyn UsageSink>>) -> Self {
        Self { sinks }
    }
}

impl UsageSink for FanOutUsageSink {
    fn record(&self, event: UsageEvent) {
        let Some((last, rest)) = self.sinks.split_last() else {
            return;
        };
        for sink in rest {
            sink.record(event.clone());
        }
        last.record(event);
    }

    fn dropped(&self) -> u64 {
        self.sinks.iter().map(|sink| sink.dropped()).sum()
    }
}

/// Process-level gauges the composition root supplies to the page.
#[derive(Default)]
pub struct Gauges {
    pub audit_journal_available: Option<bool>,
    pub audit_forward_acknowledged_seq: Option<u64>,
    pub audit_forward_degraded: Option<bool>,
    pub rollups_degraded: Option<bool>,
    pub rollups_appended: Option<u64>,
    pub usage_events_dropped: u64,
    pub rate_limited_total: u64,
    pub secrets_degraded: Option<bool>,
    pub policy_degraded: Option<bool>,
}

/// Render the whole page: usage series plus the gauges.
#[must_use]
pub fn render(sink: &PrometheusUsageSink, gauges: &Gauges) -> String {
    let mut out = String::with_capacity(4096);
    let _ = writeln!(
        out,
        "# HELP mcp_build_info Build information.\n# TYPE mcp_build_info gauge\nmcp_build_info{{version=\"{}\"}} 1",
        crate::constants::VERSION
    );
    sink.render_into(&mut out);
    let mut gauge = |name: &str, help: &str, value: Option<u64>| {
        if let Some(value) = value {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
            );
        }
    };
    let flag = |value: Option<bool>| value.map(u64::from);
    gauge(
        "mcp_audit_journal_available",
        "1 when the durable audit journal accepts records.",
        flag(gauges.audit_journal_available),
    );
    gauge(
        "mcp_audit_forward_acknowledged_seq",
        "Last journal sequence the SIEM receiver acknowledged.",
        gauges.audit_forward_acknowledged_seq,
    );
    gauge(
        "mcp_audit_forward_degraded",
        "1 while audit forwarding is failing (journal retained).",
        flag(gauges.audit_forward_degraded),
    );
    gauge(
        "mcp_rollups_degraded",
        "1 while usage rollup appends are failing.",
        flag(gauges.rollups_degraded),
    );
    gauge(
        "mcp_rollups_appended_total",
        "Usage rows appended to the rollup store.",
        gauges.rollups_appended,
    );
    gauge(
        "mcp_secrets_degraded",
        "1 while secret refresh is failing (last good values in force).",
        flag(gauges.secrets_degraded),
    );
    gauge(
        "mcp_policy_degraded",
        "1 while policy reload is failing (last good policy in force).",
        flag(gauges.policy_degraded),
    );
    let _ = writeln!(
        out,
        "# HELP mcp_usage_events_dropped_total Usage events dropped by the bounded channel.\n# TYPE mcp_usage_events_dropped_total counter\nmcp_usage_events_dropped_total {}",
        gauges.usage_events_dropped
    );
    let _ = writeln!(
        out,
        "# HELP mcp_rate_limited_total Requests refused by the per-principal rate limit.\n# TYPE mcp_rate_limited_total counter\nmcp_rate_limited_total {}",
        gauges.rate_limited_total
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(vendor: &str, tool: &str, decision: &str, outcome: &str, ms: u128) -> UsageEvent {
        UsageEvent {
            timestamp: "2026-09-04T12:00:00Z".to_owned(),
            tenant: "acme".to_owned(),
            subject: "alice".to_owned(),
            tool_name: tool.to_owned(),
            vendor: vendor.to_owned(),
            environment: "qa".to_owned(),
            decision: decision.to_owned(),
            risk: "read".to_owned(),
            outcome: outcome.to_owned(),
            duration_ms: ms,
        }
    }

    #[test]
    fn counters_and_histogram_render_in_exposition_format_without_the_subject() {
        let sink = PrometheusUsageSink::new();
        sink.record(event(
            "grafana",
            "grafana_query_logs",
            "allow",
            "success",
            40,
        ));
        sink.record(event(
            "grafana",
            "grafana_query_logs",
            "allow",
            "success",
            300,
        ));
        sink.record(event(
            "grafana",
            "grafana_query_logs",
            "deny",
            "policy_denied",
            0,
        ));
        sink.record(event("jira", "jira_get", "allow", "error", 3000));
        let page = render(&sink, &Gauges::default());
        assert!(page.contains("mcp_tool_calls_total{vendor=\"grafana\",tool=\"grafana_query_logs\",decision=\"allow\",outcome=\"success\"} 2\n"), "{page}");
        assert!(page.contains("mcp_tool_calls_total{vendor=\"grafana\",tool=\"grafana_query_logs\",decision=\"deny\",outcome=\"policy_denied\"} 1\n"));
        assert!(
            page.contains(
                "mcp_tool_call_duration_seconds_bucket{vendor=\"grafana\",le=\"0.05\"} 1\n"
            ),
            "{page}"
        );
        assert!(
            page.contains(
                "mcp_tool_call_duration_seconds_bucket{vendor=\"grafana\",le=\"0.5\"} 2\n"
            )
        );
        assert!(
            page.contains(
                "mcp_tool_call_duration_seconds_bucket{vendor=\"grafana\",le=\"+Inf\"} 2\n"
            )
        );
        assert!(page.contains("mcp_tool_call_duration_seconds_sum{vendor=\"grafana\"} 0.34\n"));
        assert!(page.contains("mcp_tool_call_duration_seconds_count{vendor=\"jira\"} 1\n"));
        assert!(!page.contains("alice"), "the subject is never a label");
        assert!(page.contains("mcp_build_info{version="));
        assert_eq!(sink.events(), 4);
    }

    #[test]
    fn gauges_render_only_when_supplied() {
        let sink = PrometheusUsageSink::new();
        let page = render(
            &sink,
            &Gauges {
                audit_journal_available: Some(true),
                audit_forward_degraded: Some(false),
                rate_limited_total: 3,
                ..Gauges::default()
            },
        );
        assert!(page.contains("mcp_audit_journal_available 1\n"));
        assert!(page.contains("mcp_audit_forward_degraded 0\n"));
        assert!(!page.contains("mcp_rollups_degraded"));
        assert!(page.contains("mcp_rate_limited_total 3\n"));
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
