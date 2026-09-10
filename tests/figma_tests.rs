use std::collections::HashMap;

use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::figma::{
    FigmaContext, bounded_depth, get_file, get_nodes, list_comments, list_components,
    parse_file_key, parse_node_ids,
};
use mcp_server_devtools::error::ErrorKind;
use mcp_server_devtools::tools::args::{
    FigmaGetFileArgs, FigmaGetNodesArgs, FigmaListCommentsArgs, FigmaListComponentsArgs,
};
use mcp_server_devtools::transport::build_client;
use mcp_server_devtools::vendor::{Vendor, figma::FigmaVendor};
use serde_json::json;
use wiremock::matchers::{
    header, header_exists, method, path, query_param, query_param_is_missing,
};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY: &str = "AbC123dEf456GhI789jKl0";
const TOKEN: &str = "figd_secret";

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
    )
}

fn file_args(value: serde_json::Value) -> FigmaGetFileArgs {
    serde_json::from_value(value).unwrap()
}

fn nodes_args(value: serde_json::Value) -> FigmaGetNodesArgs {
    serde_json::from_value(value).unwrap()
}

#[tokio::test]
async fn configuration_base_url_and_tool_registration() {
    let vendor = FigmaVendor::new();
    assert_eq!(vendor.name(), "figma");
    for value in [None, Some(""), Some("   ")] {
        let cfg = value.map_or_else(
            || Config::from_map(HashMap::new()),
            |v| config(&[("FIGMA_TOKEN", v)]),
        );
        assert_eq!(
            vendor.token(&cfg).await.unwrap_err().kind,
            ErrorKind::AuthMissing
        );
        // The base is fixed: it never depends on config.
        assert_eq!(vendor.base_url(&cfg).unwrap(), "https://api.figma.com");
    }
    let cfg = config(&[("FIGMA_TOKEN", TOKEN)]);
    assert_eq!(vendor.token(&cfg).await.unwrap(), TOKEN);
    assert_eq!(
        FigmaVendor::with_base_url("http://localhost:1234/")
            .base_url(&cfg)
            .unwrap(),
        "http://localhost:1234"
    );
    assert_eq!(vendor.normalize_path("v1/files/x"), "/v1/files/x");
    assert_eq!(vendor.normalize_path("/v1/files/x"), "/v1/files/x");
    for tool in [
        "figma_get_file",
        "figma_get_nodes",
        "figma_list_components",
        "figma_list_comments",
    ] {
        assert_eq!(
            mcp_server_devtools::tools::vendor_for_tool(tool),
            Some("figma")
        );
    }
}

#[test]
fn parse_file_key_accepts_keys_and_figma_urls() {
    assert_eq!(parse_file_key(KEY).unwrap(), KEY);
    assert_eq!(parse_file_key(&format!("  {KEY}  ")).unwrap(), KEY);
    for url in [
        format!("https://www.figma.com/file/{KEY}/My-Design"),
        format!("https://www.figma.com/design/{KEY}/My-Design?node-id=1-2&t=abc"),
        format!("https://www.figma.com/proto/{KEY}"),
        format!("https://figma.com/board/{KEY}/Board#frag"),
        format!("https://www.figma.com/design/{KEY}"),
    ] {
        assert_eq!(parse_file_key(&url).unwrap(), KEY, "{url}");
    }
}

#[test]
fn parse_file_key_rejects_structure_and_foreign_urls() {
    for bad in [
        "",
        "   ",
        ".",
        "..",
        "a/b",
        "abc-def",
        "abc def",
        "abc?x=1",
        "abc%2Fdef",
        "../etc",
        "AbC123dEf456GhI789jKl0/nodes",
        "https://evil.example/design/AbC123dEf456GhI789jKl0/x",
        "https://www.figma.com.evil.example/design/AbC123dEf456GhI789jKl0/x",
        "http://www.figma.com/design/AbC123dEf456GhI789jKl0/x",
        "https://www.figma.com/other/AbC123dEf456GhI789jKl0/x",
        "https://www.figma.com/design/",
        "https://www.figma.com/design/../admin",
        "https://www.figma.com/design/bad-key/x",
        "not a url://x",
    ] {
        let err = parse_file_key(bad).unwrap_err();
        assert_eq!(err.status_code, Some(400), "{bad:?}: {}", err.message);
        assert!(err.message.contains("`file`"), "{bad:?}: {}", err.message);
    }
}

#[test]
fn node_ids_and_depth_are_validated_and_bounded() {
    assert_eq!(parse_node_ids("1:2").unwrap(), "1:2");
    assert_eq!(
        parse_node_ids(" 1:2 , 3:4 ,I5;6-7 ").unwrap(),
        "1:2,3:4,I5;6-7"
    );
    for bad in [
        "", " ", ",", "1:2,", "1:2,,3:4", "1/2", "1:2 3:4", "a?b", "1:2%3A",
    ] {
        assert_eq!(
            parse_node_ids(bad).unwrap_err().status_code,
            Some(400),
            "{bad:?}"
        );
    }
    let hundred = (0..100)
        .map(|n| format!("1:{n}"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(parse_node_ids(&hundred).is_ok());
    let err = parse_node_ids(&format!("{hundred},1:100")).unwrap_err();
    assert_eq!(err.status_code, Some(400));
    assert!(err.message.contains("100"));

    assert_eq!(bounded_depth(None).unwrap(), 1);
    assert_eq!(bounded_depth(Some(3)).unwrap(), 3);
    assert_eq!(bounded_depth(Some(4)).unwrap(), 4);
    assert_eq!(bounded_depth(Some(99)).unwrap(), 4);
    assert_eq!(bounded_depth(Some(0)).unwrap_err().status_code, Some(400));
}

#[tokio::test]
async fn get_file_sends_token_header_and_all_query_params() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/files/{KEY}")))
        .and(header("x-figma-token", TOKEN))
        .and(header("accept", "application/json"))
        .and(query_param("depth", "2"))
        .and(query_param("ids", "1:2,3:4"))
        .and(query_param("version", "123456"))
        .and(query_param("branch_data", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "My Design",
            "document": {"id": "0:0", "children": [{"id": "0:1", "name": "Page 1", "type": "CANVAS"}]}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("FIGMA_TOKEN", TOKEN)]);
    let client = build_client().unwrap();
    let vendor = FigmaVendor::with_base_url(server.uri());
    let ctx = FigmaContext::new(&client, &cfg, &vendor);
    let args = file_args(json!({
        "file": format!("https://www.figma.com/design/{KEY}/My-Design?node-id=1-2"),
        "depth": 2,
        "ids": " 1:2, 3:4 ",
        "version": "123456",
        "branchData": true,
        "jq": "document.children[0].name",
        "outputFormat": "json"
    }));
    let response = get_file(&ctx, &args).await.unwrap();
    assert!(response.content.contains("Page 1"), "{}", response.content);
    assert!(
        !response.content.contains("My Design"),
        "{}",
        response.content
    );
}

#[tokio::test]
async fn get_file_defaults_depth_caps_it_and_omits_unset_params() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/files/{KEY}")))
        .and(header("x-figma-token", TOKEN))
        .and(query_param("depth", "1"))
        .and(query_param_is_missing("ids"))
        .and(query_param_is_missing("version"))
        .and(query_param_is_missing("branch_data"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "default"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/files/{KEY}")))
        .and(query_param("depth", "4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "capped"})))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("FIGMA_TOKEN", TOKEN)]);
    let client = build_client().unwrap();
    let vendor = FigmaVendor::with_base_url(server.uri());
    let ctx = FigmaContext::new(&client, &cfg, &vendor);

    let response = get_file(&ctx, &file_args(json!({"file": KEY, "branchData": false})))
        .await
        .unwrap();
    assert!(response.content.contains("default"));
    let response = get_file(&ctx, &file_args(json!({"file": KEY, "depth": 12})))
        .await
        .unwrap();
    assert!(response.content.contains("capped"));

    let err = get_file(&ctx, &file_args(json!({"file": KEY, "depth": 0})))
        .await
        .unwrap_err();
    assert_eq!(err.status_code, Some(400));
    let err = get_file(&ctx, &file_args(json!({"file": KEY, "ids": "1:2,"})))
        .await
        .unwrap_err();
    assert_eq!(err.status_code, Some(400));
    let err = get_file(&ctx, &file_args(json!({"file": "a/b"})))
        .await
        .unwrap_err();
    assert_eq!(err.status_code, Some(400));
}

#[tokio::test]
async fn get_nodes_requires_ids_and_sends_them() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/files/{KEY}/nodes")))
        .and(header("x-figma-token", TOKEN))
        .and(query_param("ids", "1:2,3:4"))
        .and(query_param("depth", "3"))
        .and(query_param("version", "v9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "nodes": {"1:2": {"document": {"name": "Frame A"}}, "3:4": null}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("FIGMA_TOKEN", TOKEN)]);
    let client = build_client().unwrap();
    let vendor = FigmaVendor::with_base_url(server.uri());
    let ctx = FigmaContext::new(&client, &cfg, &vendor);
    let args = nodes_args(json!({
        "file": KEY, "ids": "1:2,3:4", "depth": 3, "version": "v9",
        "jq": "nodes.\"1:2\".document.name"
    }));
    let response = get_nodes(&ctx, &args).await.unwrap();
    assert!(response.content.contains("Frame A"), "{}", response.content);

    for bad_ids in ["", "1:2,,3:4", "1/2", "../x"] {
        let err = get_nodes(&ctx, &nodes_args(json!({"file": KEY, "ids": bad_ids})))
            .await
            .unwrap_err();
        assert_eq!(err.status_code, Some(400), "{bad_ids:?}");
        assert!(
            err.message.contains("`ids`"),
            "{bad_ids:?}: {}",
            err.message
        );
    }
    // `ids` is a required schema field: an argument object without it does
    // not deserialize at all.
    assert!(serde_json::from_value::<FigmaGetNodesArgs>(json!({"file": KEY})).is_err());
}

#[tokio::test]
async fn components_and_comments_hit_their_endpoints() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/files/{KEY}/components")))
        .and(header("x-figma-token", TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "meta": {"components": [{"key": "k1", "name": "Button", "node_id": "5:6"}]}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/files/{KEY}/comments")))
        .and(header("x-figma-token", TOKEN))
        .and(query_param("as_md", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "comments": [{"id": "c1", "message": "**Fix** spacing", "resolved_at": null}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/files/{KEY}/comments")))
        .and(query_param_is_missing("as_md"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "comments": [{"id": "c1", "message": "Fix spacing"}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("FIGMA_TOKEN", TOKEN)]);
    let client = build_client().unwrap();
    let vendor = FigmaVendor::with_base_url(server.uri());
    let ctx = FigmaContext::new(&client, &cfg, &vendor);

    let args: FigmaListComponentsArgs = serde_json::from_value(json!({
        "file": format!("https://www.figma.com/file/{KEY}/Lib"),
        "jq": "meta.components[0].name"
    }))
    .unwrap();
    let response = list_components(&ctx, &args).await.unwrap();
    assert!(response.content.contains("Button"));

    let args: FigmaListCommentsArgs =
        serde_json::from_value(json!({"file": KEY, "asMd": true, "outputFormat": "json"})).unwrap();
    let response = list_comments(&ctx, &args).await.unwrap();
    assert!(response.content.contains("**Fix** spacing"));
    let args: FigmaListCommentsArgs = serde_json::from_value(json!({"file": KEY})).unwrap();
    let response = list_comments(&ctx, &args).await.unwrap();
    assert!(response.content.contains("Fix spacing"));

    let err = list_components(
        &ctx,
        &serde_json::from_value(json!({"file": "https://evil.example/design/x"})).unwrap(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(400));
}

#[tokio::test]
async fn missing_token_is_auth_missing_before_any_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(header_exists("x-figma-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(0)
        .mount(&server)
        .await;
    let cfg = Config::from_map(HashMap::new());
    let client = build_client().unwrap();
    let vendor = FigmaVendor::with_base_url(server.uri());
    let ctx = FigmaContext::new(&client, &cfg, &vendor);
    let err = get_file(&ctx, &file_args(json!({"file": KEY})))
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthMissing);
    assert!(err.message.contains("FIGMA_TOKEN"));
}

#[tokio::test]
async fn upstream_errors_are_classified_with_envelope_preserved() {
    let server = MockServer::start().await;
    let cfg = config(&[("FIGMA_TOKEN", TOKEN)]);
    let client = build_client().unwrap();
    let vendor = FigmaVendor::with_base_url(server.uri());
    let ctx = FigmaContext::new(&client, &cfg, &vendor);

    // (status, body, expected kind, must-contain fragments)
    let cases: [(u16, serde_json::Value, ErrorKind, &[&str]); 6] = [
        (
            401,
            json!({"status": 401, "err": "Invalid token"}),
            ErrorKind::AuthInvalid,
            &["Invalid token", "FIGMA_TOKEN"],
        ),
        (
            403,
            json!({"status": 403, "err": "Invalid scope(s): file_content:read"}),
            ErrorKind::AuthInvalid,
            &["Invalid scope(s): file_content:read", "scope"],
        ),
        (
            404,
            json!({"status": 404, "err": "Not found"}),
            ErrorKind::ApiError,
            &["Not found", "not shared"],
        ),
        (
            429,
            json!({"message": "Rate limit exceeded"}),
            ErrorKind::ApiError,
            &["Rate limit exceeded", "Retry-After"],
        ),
        (
            500,
            json!({"status": 500, "err": "Internal Server Error"}),
            ErrorKind::ApiError,
            &["Figma server error", "Internal Server Error"],
        ),
        (
            400,
            json!({"status": 400, "err": "Invalid version"}),
            ErrorKind::ApiError,
            &["Invalid version"],
        ),
    ];
    for (status, body, kind, fragments) in &cases {
        // Distinguish the mocks by a per-status version query param.
        Mock::given(method("GET"))
            .and(path(format!("/v1/files/{KEY}")))
            .and(query_param("version", status.to_string()))
            .respond_with(ResponseTemplate::new(*status).set_body_json(body))
            .mount(&server)
            .await;
        let args = file_args(json!({"file": KEY, "version": status.to_string()}));
        let err = get_file(&ctx, &args).await.unwrap_err();
        assert_eq!(err.status_code, Some(*status));
        assert_eq!(err.kind, *kind, "{status}: {}", err.message);
        for fragment in *fragments {
            assert!(err.message.contains(fragment), "{status}: {}", err.message);
        }
        assert!(err.original.is_some());
    }

    // Non-JSON bodies (a proxy's HTML/text page) fall back to the raw text.
    Mock::given(method("GET"))
        .and(path(format!("/v1/files/{KEY}/comments")))
        .respond_with(ResponseTemplate::new(502).set_body_string("bad gateway upstream"))
        .mount(&server)
        .await;
    let args: FigmaListCommentsArgs = serde_json::from_value(json!({"file": KEY})).unwrap();
    let err = list_comments(&ctx, &args).await.unwrap_err();
    assert_eq!(err.status_code, Some(502));
    assert!(err.message.contains("bad gateway upstream"));
}

#[tokio::test]
async fn vendor_sections_aliases_and_secret_registration() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("configs.json");
    for alias in ["figma", "mcp-server-figma"] {
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({alias: {"environments": {
                "FIGMA_TOKEN": "scoped-token"
            }}}))
            .unwrap(),
        )
        .unwrap();
        let cfg = Config::load_from_sources(Some(&file), None, &HashMap::new());
        assert_eq!(
            FigmaVendor::new().token(&cfg).await.unwrap(),
            "scoped-token"
        );
    }
    assert!(mcp_server_devtools::auth::secrets::lookup("figma", "FIGMA_TOKEN").is_some());
}
