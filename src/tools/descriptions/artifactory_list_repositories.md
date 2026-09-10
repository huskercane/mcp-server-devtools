List the JFrog Artifactory **repositories** the token can see — the first step to find where a package or build output lives. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /api/repositories`. Each entry carries `key`, `type` (`LOCAL`, `REMOTE`, `VIRTUAL`, `FEDERATED`, `DISTRIBUTION`), `packageType` (`Maven`, `Npm`, `Docker`, `Generic`, …), `description`, and `url`. Use the `key` as `repo` in `artifactory_search` and `artifactory_get_file_info`.

Authenticates with a JFrog **access token** (`ARTIFACTORY_TOKEN`) sent as `Authorization: Bearer`; `ARTIFACTORY_URL` sets the base (an origin such as `https://mycorp.jfrog.io` gains the `/artifactory` context automatically). No per-call auth is needed.

**Parameters (all optional):**
- `type`: repository class — `local`, `remote`, `virtual`, `federated`, or `distribution`.
- `packageType`: e.g. `maven`, `npm`, `docker`, `pypi`, `generic`, `nuget`, `helm`.

Read-only. The full list is returned in one call (Artifactory does not page this endpoint); on large instances filter by `type`/`packageType` and use `jq`.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `[*].{key: key, type: type, packageType: packageType}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://jfrog.com/help/r/jfrog-rest-apis/get-repositories
