Replace Bitbucket resources (full update). Returns TOON format by default.

**IMPORTANT - Cost Optimization:**
- Use `jq` param to extract only needed fields from response
- Example: `jq: "{uuid: uuid, name: name}"`

**Output format:** TOON (default) or JSON (`outputFormat: "json"`)

**Common operations:**

1. **Update PR title, description, or reviewers:** `/repositories/{workspace}/{repo}/pullrequests/{id}`
   body: `{"title": "New title", "description": "Updated description", "reviewers": [{"uuid": "{user-uuid}"}]}`
   API tokens need `read:pullrequest:bitbucket` and `write:pullrequest:bitbucket`.

2. **Update repository:** `/repositories/{workspace}/{repo}`
   body: `{"description": "...", "is_private": true, "has_issues": true}`

3. **Create/update file:** `/repositories/{workspace}/{repo}/src`
   Note: Use multipart form data for file uploads (complex - prefer PATCH for metadata)

4. **Update branch restriction:** `/repositories/{workspace}/{repo}/branch-restrictions/{id}`
   body: `{"kind": "push", "pattern": "main", "users": [{"uuid": "..."}]}`

The `/2.0` prefix is added automatically. API reference: https://developer.atlassian.com/cloud/bitbucket/rest/
