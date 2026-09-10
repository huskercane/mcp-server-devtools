Read one **file** from a GitLab repository at an explicit ref (branch, tag, or commit SHA), returning its metadata and decoded text content. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /projects/{project}/repository/files/{path}?ref={ref}`. GitLab returns the body base64-encoded; this tool decodes it. When the bytes are valid UTF-8 the response carries `content` as plain text with `encoding: "utf-8"`; otherwise `content` is dropped and `contentOmitted` explains that the file is binary or non-UTF-8, leaving `file_name`, `size`, `blob_id`, `commit_id`, and `last_commit_id`. No archive, LFS object, or attachment download happens.

Authenticates with a GitLab access token (`GITLAB_TOKEN`, scopes `read_api` **and** `read_repository`) sent as `Authorization: Bearer`.

**Parameters:**
- `project` (required): numeric project id (`42`) or namespace path (`group/subgroup/project`). Find it with `gitlab_list_projects`.
- `path` (required): file path inside the repository, e.g. `src/main.rs` or `.gitlab-ci.yml`. No leading slash, no `.`/`..` segments.
- `ref` (required): branch, tag, or SHA, e.g. `main`. GitLab has no implicit default here — pass the project's `default_branch` if unsure.

**Limits:** responses over 10 MiB are refused by the transport; a decoded file larger than the output budget is truncated and spilled to a resumable artifact (`artifact_read`). Large source files are better read with a `jq` projection or in the MR diff.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `{path: file_path, size: size, content: content}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.gitlab.com/api/repository_files/#get-file-from-repository
