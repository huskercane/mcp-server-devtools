//! Header pagination for native repository adapters. Continuations are data,
//! never URLs followed by the server.
use crate::controllers::api::ControllerResponse;
use crate::format::{OutputFormat, jmespath::apply_jq_filter, render};
use crate::transport::{ResponseBody, TransportResponse};
use serde_json::{Value, json};

pub(crate) fn response(
    response: TransportResponse,
    jq: Option<&str>,
    format: OutputFormat,
    patches: bool,
) -> ControllerResponse {
    let next_page = response
        .headers
        .get("x-next-page")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|page| *page > 0)
        .or_else(|| {
            response
                .headers
                .get_all(http::header::LINK)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .find_map(next_page)
        });
    let data = match response.data {
        ResponseBody::Json(value) => value,
        ResponseBody::Text(value) => Value::String(value),
        ResponseBody::Empty => json!([]),
    };
    let missing_patches = patches
        && data
            .as_array()
            .is_some_and(|files| files.iter().any(|file| file.get("patch").is_none()));
    let filtered = apply_jq_filter(&data, jq);
    let mut output = json!({"data": filtered.as_ref(), "nextPage": next_page});
    if patches {
        output["patchesUnavailable"] = json!(missing_patches);
    }
    ControllerResponse {
        content: render(&output, format),
        raw_response_path: response.raw_response_path,
    }
}

fn next_page(link: &str) -> Option<u64> {
    link.split(", <").find_map(|entry| {
        let (url, attributes) = entry.split_once('>')?;
        let next = attributes
            .split(';')
            .map(str::trim)
            .any(|attr| attr == "rel=\"next\"" || attr == "rel=next");
        if !next {
            return None;
        }
        url::Url::parse(url.trim().trim_start_matches('<'))
            .ok()?
            .query_pairs()
            .find_map(|(key, value)| (key == "page").then(|| value.parse::<u64>().ok()).flatten())
            .filter(|page| *page > 0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extracts_page_without_following_a_link() {
        assert_eq!(
            next_page(
                "<https://example.com/repos?page=3>; rel=\"next\", <https://example.com/repos?page=7>; rel=\"last\""
            ),
            Some(3)
        );
        assert_eq!(
            next_page("<https://example.com/repos?page=7>; rel=\"last\""),
            None
        );
        assert_eq!(
            next_page("<https://example.com/repos?page=invalid>; rel=\"next\""),
            None
        );
    }
}
