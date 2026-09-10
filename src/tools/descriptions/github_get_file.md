Read a file's text, or list a directory, in a GitHub repository at a branch, tag, or commit. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /repos/{owner}/{repo}/contents/{path}?ref=…`. GitHub returns files base64-encoded; this tool decodes them, so a UTF-8 file comes back with `content` as plain text and `encoding: "utf-8"`. When the bytes are not UTF-8 (images, archives, compiled artifacts) `content` is dropped and `contentOmitted` explains why — only metadata (`name`, `path`, `size`, `sha`, `download_url`) is returned. GitHub does not inline files between 1 MB and 100 MB; those also come back with `contentOmitted` and their `size`. Files above 100 MB are not served by this endpoint at all. A `path` that names a directory returns the array of its entries (`name`, `path`, `type`, `size`, `sha`) without any content.

Authenticates with a personal access token (`GITHUB_TOKEN`) sent as `Authorization: Bearer`. Fine-grained tokens need **Contents: read** (and **Metadata: read**) on the repository.

**Parameters:**
- `owner` (required) and `repo` (required): from `full_name`, e.g. `octocat` / `hello-world`.
- `path` (required): file or directory path inside the repository, e.g. `src/main.rs`. `..` segments are rejected.
- `ref`: branch, tag, or commit SHA. Omit for the default branch.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need — `content` for just the text, or `[*].{name: name, type: type}` for a directory.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`). For source code, `outputFormat: "json"` with `jq: "content"` returns the text verbatim.

API reference: https://docs.github.com/en/rest/repos/contents#get-repository-content
