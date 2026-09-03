//! `mcp-devtools policy explain`: the gateway's decision for a call, and
//! why (WP B.2).
//!
//! Given a policy document, a tool name with its JSON arguments, and a
//! principal (subject, groups, scopes), this builds the `ActionContext`
//! **exactly** as `call_tool` does — the same extractor
//! (`extractors::for_tool`), the same server-declared risk for unmapped
//! tools, the same environment-from-configuration — evaluates it, and
//! prints the decision together with every rule: matched, or the first key
//! it failed on. A policy author uses it to answer "why was this denied?"
//! and "what would this rule let alice do?" before a gateway ever runs it.
//!
//! The upstream identity is labelled from the credential registry the way
//! the broker labels it, with `authority: shared` — the only authority the
//! v1 credential model has — so `upstream_authority` rules explain as they
//! would enforce.

use std::path::PathBuf;

use clap::Args;

use crate::error::McpError;
use crate::policy::extractors::for_tool;
use crate::policy::{
    ActionContext, ClientIdentity, CredentialLabel, EnvironmentClass, Explanation, FilePolicy,
    Principal, PrincipalAuthority, RequestRisk, UpstreamAuthority, UpstreamIdentity, VerifyingKey,
};

#[derive(Debug, Args)]
pub struct ExplainOpts {
    /// The policy document.
    pub file: PathBuf,
    /// Verify the document's signature against this public key first.
    #[arg(long, value_name = "BASE64")]
    pub public_key: Option<String>,
    /// The tool the call names, e.g. `slack_channel_history`.
    #[arg(long)]
    pub tool: String,
    /// The tool's arguments as a JSON object, e.g. `'{"channelId":"C0INCIDENTS"}'`.
    #[arg(long, default_value = "{}")]
    pub arguments: String,
    /// The caller's subject (`sub`).
    #[arg(long, default_value = "someone@example")]
    pub subject: String,
    /// A group the caller belongs to (repeatable).
    #[arg(long = "group")]
    pub groups: Vec<String>,
    /// A scope the token carries (repeatable; default `mcp:tools`).
    #[arg(long = "scope")]
    pub scopes: Vec<String>,
    /// The vendor account's environment (`MCP_VENDOR_ENVIRONMENT`):
    /// `prod`, `staging`, `qa`, `dev`; unclassified when omitted.
    #[arg(long)]
    pub environment: Option<String>,
    /// Tenant label (`MCP_TENANT`).
    #[arg(long, default_value = "tenant")]
    pub tenant: String,
    /// Print the explanation as JSON instead of text.
    #[arg(long)]
    pub json: bool,
}

fn failure(message: impl std::fmt::Display) -> McpError {
    crate::error::unexpected(message.to_string(), None)
}

/// Build the context the gateway would, evaluate, and print.
///
/// # Errors
///
/// When the document cannot be loaded, the arguments are not a JSON
/// object, the tool name is unknown, or the environment does not parse.
pub fn run(opts: &ExplainOpts) -> Result<(), McpError> {
    let policy = match &opts.public_key {
        Some(text) => FilePolicy::load_verified(
            &opts.file,
            VerifyingKey::from_base64(text)
                .map_err(|error| failure(format!("--public-key: {error}")))?,
        ),
        None => FilePolicy::load(&opts.file),
    }
    .map_err(failure)?;
    let arguments: serde_json::Value = serde_json::from_str(&opts.arguments)
        .map_err(|error| failure(format!("--arguments is not JSON: {error}")))?;
    let arguments = arguments
        .as_object()
        .ok_or_else(|| failure("--arguments must be a JSON object"))?;
    let declared_risk = crate::tools::DevtoolsServer::declared_tool_risk(&opts.tool)
        .ok_or_else(|| failure(format!("unknown tool {:?}", opts.tool)))?;
    let vendor = crate::tools::vendor_for_tool(&opts.tool).unwrap_or("unknown");
    let environment = match &opts.environment {
        Some(value) => EnvironmentClass::parse(value).ok_or_else(|| {
            failure(format!(
                "--environment {value:?} is not one of prod, staging, qa, dev"
            ))
        })?,
        None => EnvironmentClass::Unclassified,
    };
    let (context, declared_risk) =
        build_context(opts, vendor, environment, arguments, declared_risk);
    let explanation = policy.explain(&context);
    if opts.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "policy_version": crate::ports::PolicyDecisionPoint::version(&policy),
                "action": context,
                "explanation": explanation,
            }))
            .map_err(|error| failure(error.to_string()))?
        );
    } else {
        print_text(&context, &explanation, declared_risk);
    }
    Ok(())
}

fn build_context(
    opts: &ExplainOpts,
    vendor: &str,
    environment: EnvironmentClass,
    arguments: &serde_json::Map<String, serde_json::Value>,
    declared_risk: RequestRisk,
) -> (ActionContext, RequestRisk) {
    let mut scopes = opts.scopes.clone();
    if scopes.is_empty() {
        scopes.push(crate::server::auth::DEFAULT_REQUIRED_SCOPE.to_owned());
    }
    let principal = Principal {
        tenant: opts.tenant.clone(),
        subject: opts.subject.clone(),
        groups: opts.groups.clone(),
        scopes,
        authority: PrincipalAuthority::Okta,
    };
    let label = crate::auth::secrets::for_vendor(vendor).next().map_or_else(
        || CredentialLabel::unconfigured(vendor),
        CredentialLabel::slot,
    );
    let upstream = UpstreamIdentity {
        label,
        vendor: vendor.to_owned(),
        environment,
        authority: UpstreamAuthority::Shared,
    };
    let details = for_tool(&opts.tool, Some(arguments), declared_risk);
    (
        ActionContext::assemble(
            principal,
            ClientIdentity::default(),
            None,
            opts.tool.clone(),
            details,
            None,
            upstream,
        ),
        declared_risk,
    )
}

fn label<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn print_text(context: &ActionContext, explanation: &Explanation, declared_risk: RequestRisk) {
    let verdict = if explanation.decision.is_allow() {
        "ALLOW"
    } else {
        "DENY"
    };
    println!(
        "{verdict}: {} (policy {})",
        explanation.decision.reason,
        explanation
            .decision
            .policy_version
            .as_deref()
            .unwrap_or("unversioned")
    );
    println!(
        "call: tool={} vendor={} environment={} action={} risk={} (declared {}) resource={} scope={}",
        context.tool_name(),
        context.vendor(),
        label(&context.environment()),
        label(&context.normalized_action()),
        label(&context.request_risk()),
        label(&declared_risk),
        label(&context.resource_type()),
        serde_json::to_string(context.resource_scope()).unwrap_or_default(),
    );
    println!(
        "principal: subject={} groups=[{}] scopes=[{}]",
        context.principal().subject,
        context.principal().groups.join(", "),
        context.principal().scopes.join(", ")
    );
    if explanation.unclassified {
        println!(
            "the resource could not be classified, so no rule was consulted (an extractor \
             declined this call: check the arguments — a malformed id, an unmapped endpoint)"
        );
    }
    println!("rules:");
    for trace in &explanation.rules {
        let effect = label(&trace.effect);
        match (trace.mismatch, trace.decisive) {
            (None, true) => println!("  ✓ {} ({effect}) — decisive", trace.id),
            (None, false) => println!(
                "  ✓ {} ({effect}) — matched, not decisive{}",
                trace.id,
                if explanation.unclassified {
                    " (unclassified calls are denied before rules)"
                } else {
                    ""
                }
            ),
            (Some(key), _) => println!("  ✗ {} ({effect}) — fails on `{key}`", trace.id),
        }
    }
}
