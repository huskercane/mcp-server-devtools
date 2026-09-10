Get JFrog Artifactory **item metadata** for one file or folder — size, checksums (`md5`, `sha1`, `sha256`), created/modified timestamps and who last modified it, or the child listing of a folder. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /api/storage/{repo}/{path}`. For a **file** the response carries `repo`, `path`, `size`, `created`, `createdBy`, `lastModified`, `modifiedBy`, `mimeType`, `checksums`, `originalChecksums`, `downloadUri`, and `uri`. For a **folder** it carries `children[]` (each `{uri: "/name", folder: true|false}`) instead of size/checksums — call again with the child appended to `path` to descend.

Authenticates with a JFrog **access token** (`ARTIFACTORY_TOKEN`) sent as `Authorization: Bearer`; `ARTIFACTORY_URL` sets the base.

**Parameters:**
- `repo` (required): repository key, e.g. `libs-release-local`.
- `path` (required): file or folder path inside the repo, e.g. `com/example/my-app/1.4.2/my-app-1.4.2.jar`. A leading slash is optional; `..` segments are rejected.

Read-only: this returns metadata only and never downloads the file's bytes. `downloadUri` is informational.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `{size: size, sha256: checksums.sha256, modified: lastModified}` or `children[*].uri`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://jfrog.com/help/r/jfrog-rest-apis/file-info
