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
        if value.is_some_and(|value| value.trim().eq_ignore_ascii_case("json")) {
            Self::Json
        } else {
            Self::Toon
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

/// Join borrowed strings with one exactly sized output allocation. Empty
/// elements still contribute separators, matching `slice::join` byte for byte.
pub(crate) fn join_strings<'a>(
    items: impl Iterator<Item = &'a str> + Clone,
    separator: &str,
) -> String {
    let (count, bytes) = items
        .clone()
        .fold((0usize, 0usize), |(count, bytes), item| {
            (count + 1, bytes + item.len())
        });
    let mut output = String::with_capacity(bytes + count.saturating_sub(1) * separator.len());
    for (index, item) in items.enumerate() {
        if index != 0 {
            output.push_str(separator);
        }
        output.push_str(item);
    }
    output
}

#[cfg(test)]
mod join_tests {
    #[test]
    fn empty_elements_and_unicode_keep_their_separators() {
        for values in [vec![], vec![""], vec!["", "", "é", ""]] {
            assert_eq!(
                super::join_strings(values.iter().copied(), ";"),
                values.join(";")
            );
        }
    }
}
