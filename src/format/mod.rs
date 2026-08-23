//! Output formatting, filtering, and truncation helpers.

pub mod jmespath;
pub mod markdown;
pub mod truncation;

use serde_json::Value;

/// How tool output should be rendered before being handed to the MCP client.
///
/// Default is [`OutputFormat::Toon`] to match the TS server, which promises
/// token-efficient TOON output in README/tool descriptions. On encode failure
/// the renderer falls back to pretty JSON — same behaviour as TS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Toon,
    Json,
}

impl OutputFormat {
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            Some("json") => Self::Json,
            _ => Self::Toon,
        }
    }
}

/// Render `data` as the requested output string. Falls back to pretty JSON if
/// TOON encoding fails. Matches TS `toOutputString`.
///
/// The JSON fallback is built lazily (`unwrap_or_else`, not `unwrap_or`): on
/// the default TOON path it is only ever needed when the encoder fails, and
/// materialising it eagerly costs a full pretty-print of the whole response
/// that is then dropped. On a 2 MB payload that was ~4 MB and ~9 ms of pure
/// waste per tool call.
pub fn render(data: &Value, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => to_pretty_json(data),
        OutputFormat::Toon => encode_toon(data).unwrap_or_else(|| to_pretty_json(data)),
    }
}

/// Pretty JSON with 2-space indent — matches TS `JSON.stringify(value, null, 2)`.
pub fn to_pretty_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

fn encode_toon(value: &Value) -> Option<String> {
    serde_toon::to_string(value).ok()
}
