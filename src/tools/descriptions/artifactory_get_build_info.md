Get JFrog Artifactory **build information** for one build run — the modules it produced, their published artifacts (name, type, checksums) and resolved dependencies, plus agent, VCS revision, start time, duration, and properties. Use it to answer "what exactly did build N publish, and from which commit?". Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /api/build/{buildName}/{buildNumber}`. The response is wrapped in `buildInfo` (with `name`, `number`, `started`, `durationMillis`, `agent`, `buildAgent`, `vcs[]`, `modules[]`, `properties`) and `uri`.

Authenticates with a JFrog **access token** (`ARTIFACTORY_TOKEN`) sent as `Authorization: Bearer`; `ARTIFACTORY_URL` sets the base.

**Parameters:**
- `buildName` (required): the build name as published, e.g. `my-app-release`. Spaces are allowed and encoded for you.
- `buildNumber` (required): the build number string, e.g. `142`.
- `project`: JFrog project key when the build was published into a project; omit for the global scope.

Read-only. Build promotion and deletion are not available.

**IMPORTANT - Cost Optimization:** build info can be large — use `jq`, e.g. `buildInfo.modules[*].{id: id, artifacts: artifacts[*].name}` or `buildInfo.vcs[*].revision`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://jfrog.com/help/r/jfrog-rest-apis/build-info
