//! `mcp-devtools policy explain`: the gateway's decision for a call, and
//! why (WP B.2).
//!
//! Given a policy document, a tool name with its JSON arguments, and a
//! principal (subject, groups, scopes), this builds the `ActionContext`
//! **exactly** as `call_tool` does — through the same
//! [`ActionContext::for_tool_call`], with the same server-declared risk for
//! unmapped tools, and the upstream identity the same credential broker
//! would choose under the configuration in force (the standard cascade:
//! environment, `.env`, `~/.mcp/configs.json`) — evaluates it, and prints
//! the decision together with every rule: matched, or the first key it
//! failed on. A policy author uses it to answer "why was this denied?" and
//! "what would this rule let alice do?" before a gateway ever runs it.
//!
//! Only the principal and the reporting client are the operator's to
//! supply, because they arrive with a request; everything the gateway
//! reads from configuration is read from configuration here too.
//! `--environment` overrides the configured `MCP_VENDOR_ENVIRONMENT` for a
//! what-if ("the same call in prod"), and says so in the output.

use std::path::PathBuf;

use clap::Args;

use crate::error::McpError;
use crate::policy::{
    ActionContext, ClientIdentity, EnvironmentClass, Explanation, FilePolicy, Principal,
    PrincipalAuthority, RequestRisk, VerifyingKey,
};
use crate::ports::{ConfigCredentialBroker, CredentialBroker as _};

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
    /// Override the configured environment (`MCP_VENDOR_ENVIRONMENT`) for a
    /// what-if: `prod`, `staging`, `qa`, `dev`. Without it the environment
    /// is the one the gateway would read from configuration.
    #[arg(long)]
    pub environment: Option<String>,
    /// Tenant label of the principal; default `MCP_TENANT` from
    /// configuration, or the issuer host as the gateway derives it.
    #[arg(long)]
    pub tenant: Option<String>,
    /// The client name the caller would report in `initialize`
    /// (telemetry only, never an authorization input).
    #[arg(long)]
    pub client_name: Option<String>,
    /// The client version the caller would report.
    #[arg(long)]
    pub client_version: Option<String>,
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
pub async fn run(opts: &ExplainOpts) -> Result<(), McpError> {
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
    let environment_override = opts
        .environment
        .as_deref()
        .map(|value| {
            EnvironmentClass::parse(value).ok_or_else(|| {
                failure(format!(
                    "--environment {value:?} is not one of prod, staging, qa, dev"
                ))
            })
        })
        .transpose()?;
    // The configuration the gateway would read, read the same way. The
    // broker predicts the upstream identity exactly as `call_tool` asks it
    // to (keychain probe included), so the label, environment, and
    // authority are what the journal would carry.
    let config = crate::config::load();
    let mut upstream = ConfigCredentialBroker
        .upstream_identity(&config, vendor)
        .await;
    let configured_environment = upstream.environment;
    if let Some(environment) = environment_override {
        upstream.environment = environment;
    }
    let context = ActionContext::for_tool_call(
        principal(opts, &config),
        ClientIdentity::reported(opts.client_name.as_deref(), opts.client_version.as_deref()),
        &opts.tool,
        Some(arguments),
        declared_risk,
        upstream,
    );
    let explanation = policy.explain(&context);
    if opts.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "policy_version": crate::ports::PolicyDecisionPoint::version(&policy),
                "action": context,
                "configured_environment": configured_environment,
                "explanation": explanation,
            }))
            .map_err(|error| failure(error.to_string()))?
        );
    } else {
        print_text(
            &context,
            &explanation,
            declared_risk,
            environment_override.map(|_| configured_environment),
        );
    }
    Ok(())
}

/// The principal as the bearer middleware would build it from a token
/// with these claims: tenant from configuration the way the Okta settings
/// derive it, the default required scope when none is given.
fn principal(opts: &ExplainOpts, config: &crate::config::Config) -> Principal {
    let mut scopes = opts.scopes.clone();
    if scopes.is_empty() {
        scopes.push(crate::server::auth::DEFAULT_REQUIRED_SCOPE.to_owned());
    }
    let tenant = opts.tenant.clone().unwrap_or_else(|| {
        crate::auth::okta::OktaSettings::from_config(config).map_or_else(
            |_| {
                config
                    .get(crate::auth::okta::TENANT_KEY)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map_or_else(|| "tenant".to_owned(), str::to_owned)
            },
            |settings| settings.tenant,
        )
    });
    Principal {
        tenant,
        subject: opts.subject.clone(),
        groups: opts.groups.clone(),
        scopes,
        authority: PrincipalAuthority::Okta,
    }
}

fn label<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn print_text(
    context: &ActionContext,
    explanation: &Explanation,
    declared_risk: RequestRisk,
    overridden_environment: Option<EnvironmentClass>,
) {
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
    if let Some(configured) = overridden_environment {
        println!(
            "environment overridden by --environment (configuration says {})",
            label(&configured)
        );
    }
    println!(
        "principal: subject={} groups=[{}] scopes=[{}] tenant={}",
        context.principal().subject,
        context.principal().groups.join(", "),
        context.principal().scopes.join(", "),
        context.principal().tenant
    );
    println!(
        "upstream: {} ({})",
        label(&context.upstream_identity().label),
        label(&context.upstream_identity().authority)
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
