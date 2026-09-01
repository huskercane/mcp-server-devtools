# Jira scoped API-token support

## Status

`mcp-devtools` supports Atlassian classic API tokens by sending HTTP Basic authentication to a site-specific Jira base URL:

```text
https://{ATLASSIAN_SITE_NAME}.atlassian.net/rest/api/3/...
```

It also supports Atlassian scoped API tokens through the API gateway URL:

```text
https://api.atlassian.com/ex/jira/{ATLASSIAN_CLOUD_ID}/rest/api/3/...
```

Using a scoped token against the site-specific URL can return `401 Unauthorized` even when Atlassian records the token as having been used. The Jira base URL is therefore selected from the configured token mode and Cloud ID.

References:

- <https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/>
- <https://support.atlassian.com/atlassian-cloud/kb/401-unauthorized-error-when-service-account-accesses-jira-or-confluence-api/>
- <https://developer.atlassian.com/platform/forge/manifest-reference/scopes-product-jira/>

## Requirements

### Configuration

Use explicit Jira token-mode configuration. Token mode is not inferred from token prefix or length because Atlassian API-token lengths vary.

Suggested settings:

```json
{
  "jira": {
    "environments": {
      "ATLASSIAN_USER_EMAIL": "user@example.com",
      "ATLASSIAN_API_TOKEN": "keychain",
      "ATLASSIAN_SITE_NAME": "example",
      "ATLASSIAN_API_TOKEN_MODE": "scoped",
      "ATLASSIAN_CLOUD_ID": "00000000-0000-0000-0000-000000000000"
    }
  }
}
```

Supported modes:

- `classic`: use `https://{site}.atlassian.net` and preserve current behavior.
- `scoped`: require `ATLASSIAN_CLOUD_ID` and use `https://api.atlassian.com/ex/jira/{cloudId}`.

For backward compatibility, an omitted mode should initially mean `classic`. Missing or blank `ATLASSIAN_CLOUD_ID` in scoped mode must produce an actionable configuration error before an HTTP request is sent.

If automatic Cloud ID discovery is added later, it must be separately tested and cached by site. The initial implementation should prefer an explicit Cloud ID to keep authentication deterministic.

### Authentication

Continue to construct HTTP Basic authentication from the Atlassian account email and API token:

```text
Authorization: Basic base64(email:token)
```

The configured email must be the Atlassian account that created the token. Never log the token, encoded authorization header, or complete credential pair.

### Scope guidance

Atlassian recommends staying below 50 scopes and using classic scopes where available to avoid a large granular-scope set. This matters for `mcp-devtools` because `jira_get`, `jira_post`, `jira_put`, `jira_patch`, and `jira_delete` are generic REST tools rather than a fixed set of Jira operations.

No static granular list can authorize every arbitrary Jira REST path safely within a 50-scope budget. Document and support capability profiles instead of claiming universal coverage.

#### Recommended standard profile

For normal issue and project work, select these classic scopes on the scoped token:

- `read:jira-work` — read projects, issues, search results, attachments, comments, and worklogs.
- `read:jira-user` — read user profiles needed for assignee, reporter, watcher, and requester data.
- `write:jira-work` — create and update issues, comments, and worklogs, and perform supported deletion operations.

This three-scope profile should be the documented default for the generic Jira tools. Jira permissions still restrict what the token owner can see or change.

#### Optional administration scopes

Add only when the user intends to call administrative endpoints:

- `manage:jira-project` — manage project settings, versions, and components.
- `manage:jira-configuration` — manage global Jira configuration such as projects, custom fields, workflows, and issue-link types.
- `manage:jira-webhook` — manage Jira webhooks.

These scopes are not needed to read NBSERV issues, search with JQL, create or edit ordinary issues, or add comments.

#### Read-only profile

For an MCP server that must not mutate Jira, use:

- `read:jira-work`
- `read:jira-user`

The server should also disable or omit `jira_post`, `jira_put`, `jira_patch`, and `jira_delete`; token scopes are defense in depth, not a replacement for limiting the exposed tool surface.

#### Granular-only profile

Use granular scopes only when organizational policy disallows the broader classic scopes. Build the list from the exact Jira endpoints that will be allowed. A typical issue-oriented starting set may need scopes for:

- issues and issue metadata;
- projects and project roles;
- fields, issue types, statuses, priorities, resolutions, and labels;
- users, groups, avatars, and application roles;
- comments and comment properties;
- attachments;
- worklogs and worklog properties;
- issue links, watchers, changelogs, transitions, and security levels;
- JQL reading and validation.

Read, write, and delete are separate granular scopes for many resource types. This can approach or exceed 50 scopes quickly. Before adding any granular scope:

1. Inventory the allowed endpoint and HTTP-method pairs.
2. Read the scope section for each endpoint in the Jira REST API documentation.
3. Deduplicate implied and repeated scopes.
4. Keep the final count below 50.
5. Split materially different capabilities into separate tokens or MCP profiles rather than creating an over-broad token.

Do not publish a purported universal granular list. The generic Jira tool surface can call endpoints whose required scopes are not known until the requested path and method are selected.

### Error handling and diagnostics

When Jira returns `401`, the error should identify the selected token mode and sanitized base URL and suggest:

- verify the token owner email;
- verify that the token has not expired or been revoked;
- use the site URL for classic tokens;
- use the `api.atlassian.com/ex/jira/{cloudId}` URL for scoped tokens;
- verify required scopes.

Do not translate authentication failures into missing-project or missing-issue conclusions. Jira may return `404` for resources when the request is anonymous or the account lacks Browse Projects permission. The recommended diagnostic sequence is:

1. `GET /rest/api/3/myself`
2. `GET /rest/api/3/project/{projectKey}`
3. `GET /rest/api/3/issue/{issueKey}`

Only investigate Jira project permissions after `/myself` succeeds.

### Tests

Add tests covering:

1. Classic mode resolves `https://{site}.atlassian.net`.
2. Scoped mode resolves `https://api.atlassian.com/ex/jira/{cloudId}`.
3. Scoped mode without a Cloud ID fails before dispatch.
4. Omitted mode preserves classic behavior.
5. Whitespace is trimmed from mode, site, and Cloud ID configuration.
6. Invalid mode values return an actionable error.
7. The normalized REST path is appended correctly in both modes.
8. Basic authentication is applied in both modes without logging credentials.
9. Jira and Confluence configuration fallbacks do not accidentally select the wrong product gateway or Cloud ID.
10. Error messages never include the token or authorization header.

## Acceptance criteria

- A classic token can authenticate against the existing site-specific URL.
- A scoped token can authenticate against the Atlassian API gateway using an explicit Jira Cloud ID.
- `/rest/api/3/myself` succeeds in both modes with valid credentials.
- Existing classic-token configurations continue to work without changes.
- Configuration and runtime errors distinguish authentication, scope, and Jira-permission failures where the upstream response permits it.
- Documentation explains the less-than-50-scope guidance and recommends the standard three-scope profile for normal issue work.
