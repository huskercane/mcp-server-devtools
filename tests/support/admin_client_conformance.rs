//! The `AdminClient` adapter conformance suite (plan §3.10.1, WP D.0): the
//! same assertions against every adapter, so the console's in-process
//! client and the CLI's HTTP client are proven to see the same boundary.
//!
//! `admin` must carry `mcp:admin`, `tools` only `mcp:tools`. Returns the
//! `GET policy` body so a caller can assert two adapters agree byte for
//! byte.

use mcp_server_devtools::ports::{AdminClient, AdminMethod, AdminRequest};
use serde_json::{Value, json};

pub async fn conformance(client: &dyn AdminClient, admin: &str, tools: &str) -> Value {
    let get = |operation: &'static str| AdminRequest {
        method: AdminMethod::Get,
        operation,
        body: None,
    };

    // A read as an administrator: the boundary's own `data` envelope.
    let policy = client.call(admin, get("policy")).await.unwrap();
    assert_eq!(policy.status, 200);
    assert!(policy.is_success());
    assert!(policy.body["data"]["document"].is_string());
    assert_eq!(policy.body.as_object().unwrap().len(), 1);

    // The bearer boundary is in the path: no token, and the wrong scope.
    let anonymous = client.call("", get("policy")).await.unwrap();
    assert_eq!(anonymous.status, 401);
    assert!(anonymous.body["error"].is_string());
    let forbidden = client.call(tools, get("policy")).await.unwrap();
    assert_eq!(forbidden.status, 403);
    assert!(forbidden.body["error"].is_string());

    // Dispatch errors come back as responses, never as client errors.
    let missing = client.call(admin, get("no-such-operation")).await.unwrap();
    assert_eq!(missing.status, 404);
    assert_eq!(missing.body["error"], "not_found");
    let wrong_method = client
        .call(
            admin,
            AdminRequest {
                method: AdminMethod::Put,
                operation: "policy",
                body: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(wrong_method.status, 405);
    assert_eq!(wrong_method.body["error"], "method_not_allowed");

    // A JSON body reaches the operation.
    let validate = client
        .call(
            admin,
            AdminRequest {
                method: AdminMethod::Post,
                operation: "policy/validate",
                body: Some(&json!({"document": "version: 2\nrules: []\n"})),
            },
        )
        .await
        .unwrap();
    assert_eq!(validate.status, 200, "{}", validate.body);
    assert_eq!(validate.body["data"]["valid"], true);
    let invalid = client
        .call(
            admin,
            AdminRequest {
                method: AdminMethod::Post,
                operation: "policy/validate",
                body: Some(&json!({"document": "x", "extra": 1})),
            },
        )
        .await
        .unwrap();
    assert_eq!(invalid.status, 400);
    assert_eq!(invalid.body["error"], "invalid_request");

    // The boundary's body limit applies through either adapter.
    let oversized = json!({"document": "#".repeat(1_000_001)});
    let too_large = client
        .call(
            admin,
            AdminRequest {
                method: AdminMethod::Post,
                operation: "policy/validate",
                body: Some(&oversized),
            },
        )
        .await
        .unwrap();
    assert_eq!(too_large.status, 413);
    assert_eq!(too_large.body["error"], "body_too_large");

    policy.body
}
