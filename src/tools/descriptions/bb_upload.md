Upload files to a Bitbucket repository's **Downloads** section (`POST /repositories/{workspace}/{repo}/downloads`, multipart). Use this instead of `bb_post` for anything that is a file: Postman collections, HTTP test files, reports, archives. Returns TOON by default (`outputFormat: "json"` for JSON).

**Sending content:** the server cannot read paths on your machine. Send each file as `filename` + `contentBase64` (standard base64 of the bytes) with an optional `mimeType`, or set `artifactId` to upload a temporary artifact another tool returned (for example `circleci_logs`) without moving its bytes through the client.

**Collisions:** Bitbucket silently replaces an artifact that has the same name. This tool lists the repository's artifacts first and refuses the whole upload (HTTP 409, nothing sent) when any name already exists, unless you pass `onConflict: "replace"`. The check and the upload are two requests, so an artifact created by someone else in between is still replaced.

**Limits:** up to 20 files per call; per-file and per-call decoded size limits are set by the server (`UPLOAD_MAX_FILE_BYTES`, default 10 MiB; `UPLOAD_MAX_TOTAL_BYTES`, default 25 MiB). Over streamable HTTP the whole tool call must also fit the server's request body cap (`HTTP_REQUEST_BODY_LIMIT_BYTES`, 1 MB by default), so prefer `artifactId` for large files there unless the operator raised it. Filenames are one path segment: no `/`, `\`, `:`, `*`, `?`, `"`, `<`, `>`, `|`, control characters, or `..`.

**Failures:** permission (403), rate limit (429), and validation errors are returned without retrying and state that nothing was uploaded. A timeout or 5xx after the body was sent is reported as an *unknown outcome*: list the Downloads with `bb_get` before retrying, because a retry replaces whatever did land.

**Example — publish a Postman collection, then link it from a PR comment:**

1. `bb_upload` with `repoSlug: "project-api"`, `files: [{"filename": "project-api.postman_collection.json", "mimeType": "application/json", "contentBase64": "<base64 of the collection>"}]`
   → result includes `files[0].browserUrl`, e.g. `https://bitbucket.org/myteam/project-api/downloads/project-api.postman_collection.json`
2. `bb_post` to `/repositories/myteam/project-api/pullrequests/42/comments` with body `{"content": {"raw": "Postman collection for this change: https://bitbucket.org/myteam/project-api/downloads/project-api.postman_collection.json"}}`

Each result entry has `name`, `size`, `mimeType`, `downloadUrl` (API link, redirects to the bytes), `browserUrl`, and `replaced`. The `/2.0` prefix is added automatically. API reference: https://developer.atlassian.com/cloud/bitbucket/rest/api-group-downloads/
