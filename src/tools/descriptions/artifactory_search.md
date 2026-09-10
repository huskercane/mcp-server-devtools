Search JFrog Artifactory **items** (files or folders) with structured filters — find a specific artifact, every version of a package, what changed since a date, or where a binary with a known checksum is stored. Returns TOON format by default (30-60% fewer tokens than JSON).

The filters are compiled server-side into a single bounded AQL query (`items.find({...}).include(...).sort(...).limit(N)`) and sent to `POST /api/search/aql`. You never write AQL yourself, and every value is escaped — a `name` of `"x"` is searched literally.

**Result fields** (in `results[]`): `repo`, `path` (folder inside the repo), `name` (file name), `type`, `size` (bytes), `modified`, `created`, `sha256`, `actual_sha1`. `range` reports `total` matched versus `end_pos` returned. Combine `repo/path/name` to address an item in `artifactory_get_file_info`.

**Parameters** — at least one of `repo`, `name`, `path`, `sha256` is required:
- `repo`: one repository key (exact), e.g. `libs-release-local`.
- `name`: file name. With `*` it is a wildcard pattern (`my-app-*.jar`), otherwise exact.
- `path`: folder path inside the repo, no leading slash. With `*` it is a wildcard pattern (`com/example/*`), otherwise exact.
- `type`: `file` (default), `folder`, or `any`.
- `modifiedAfter`: ISO-8601 timestamp, e.g. `2024-06-01T00:00:00.000Z` — only items modified after it.
- `sha256`: 64-hex checksum; finds every copy of that exact binary.
- `limit`: 1–500, default 100. **Results are cut at `limit`** — nothing beyond it is returned, so narrow the filters or sort (`sortBy: "modified", sortOrder: "desc"`) to reach the items you want.
- `sortBy`: `name`, `modified`, `size`, or `path`; `sortOrder`: `asc` (default) or `desc`.

Read-only. Downloads are not performed by this tool.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `results[*].{repo: repo, path: path, name: name, size: size, modified: modified}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

AQL reference: https://jfrog.com/help/r/jfrog-artifactory-documentation/artifactory-query-language
