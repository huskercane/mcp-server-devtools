Partially update Bitbucket resources. Returns TOON format by default.

**IMPORTANT - Cost Optimization:** Use `jq` param to filter response fields.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`)

**Important:** Bitbucket's pull-request update endpoint does not accept PATCH.
Use `bb_put` for `/repositories/{workspace}/{repo}/pullrequests/{id}`. Calling
that endpoint with `bb_patch` can produce the misleading response "This
endpoint does not support token-based authentication."

**Common operations:**

1. **Update repository properties:** `/repositories/{workspace}/{repo}`
   body: `{"description": "New description"}`

2. **Update comment:** `/repositories/{workspace}/{repo}/pullrequests/{pr_id}/comments/{comment_id}`
   body: `{"content": {"raw": "Updated comment"}}`

The `/2.0` prefix is added automatically. API reference: https://developer.atlassian.com/cloud/bitbucket/rest/
