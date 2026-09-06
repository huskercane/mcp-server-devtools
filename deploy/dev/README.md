# Local development stack

Install Docker with Docker Compose v2 (supporting `up --wait`), Git, and Bash.
On Windows, run these commands in WSL2 with Docker Desktop integration enabled.
No host Rust, Node, identity-provider account, or vendor credentials are needed.
Allow several GB of disk and at least 6 GB of Docker memory. The first start
downloads images and compiles Rust; later starts reuse named build caches.

From the repository root:

```sh
./scripts/dev up
```

Open **https://localhost:8443/console**. Accept the local self-signed certificate
for this development site, choose **Sign in**, and use either account:

| User | Password | Purpose |
|---|---|---|
| `alice` | `alice-password` | First administrator / proposer |
| `bob` | `bob-password` | Second administrator / approver |

After login, click **Continue** on the signed-in landing page. Use `localhost`
exactly: the callback registration is `https://localhost:8443/console/callback`.
Keycloak administration is at **http://localhost:8080**, using `admin` /
`local-admin-password`; select the `mcp` realm.

This is a disposable development environment with known passwords and a local
certificate. Published ports bind only to host loopback. Do not deploy this
configuration publicly or populate it with production credentials.

## What starts

- Keycloak 26.5.7 imports a realm with two users, a public S256 PKCE client,
  admin/tool scopes, a `basic` subject mapper, and audience/group mappers. Its
  development database persists. The subject mapper is explicit because this
  realm supplies its own client scopes; omitting it produces tokens without `sub`.
- The pinned Rust toolchain compiles this checkout with `console`, `wrds` and
  `secrets-vault`, without the host OS keychain feature. The server runs `all`.
- First startup generates policy/audit keys, a signed deny-all policy, a signed
  empty revocation list, and a certificate. Policies, journal and SQLite usage
  survive stop/start. Two-person approval is enabled.
- nginx serves the console over HTTPS so its Secure cookies work. The server
  shares Keycloak's network namespace: both browser and server can use the same
  `http://localhost:8080/realms/mcp` issuer without DNS or hosts-file changes.

This uses Keycloak's documented [development mode and realm import](https://www.keycloak.org/server/containers)
and Compose's [service network namespace](https://docs.docker.com/reference/compose-file/services/#network_mode).
The production image and production Compose configuration remain separate.
The server starts from its state directory so it does not load a host checkout's
`.env` vendor credentials. Configure any intentional development integrations
explicitly in this stack.

## Development loop

```sh
./scripts/dev logs          # Build output and service logs; Ctrl-C stops tailing
./scripts/dev status
./scripts/dev smoke         # Real Keycloak login, console pages, CSRF and logout
./scripts/dev restart       # Recompile host edits, restart server and proxy
./scripts/dev test          # Tests inside the toolchain container
./scripts/dev test --test console_tests
./scripts/dev shell         # Container shell in /workspace
./scripts/dev down          # Stop containers, preserve data and build caches
./scripts/dev up            # Start again
```

Edit on the host; the container mounts the checkout read-only. `restart`
recompiles it, including embedded console templates/assets. It does not watch
files automatically. Browser sessions are in memory, so sign in again after
restarting. Format or edit files on the host; commands that rewrite source or
Cargo.lock cannot do so through the read-only mount.

The default policy denies tool calls. You can browse administration, explain
denials, and author policies without connecting any real vendors. Activity,
usage and proposals begin empty; MCP session/artifact pages do not list browser
sessions. Real vendor integration tests require separately configured services.
The tenant label for development identities is `local-dev`.
The smoke command uses an HTTP cookie client against the real provider; it does
not replace a browser check of SameSite cookies, rendering or upload JavaScript.

## Try two-person policy approval

1. Sign in as Alice, open Policy → Author a policy change, edit the policy and
   download the validated candidate (for example `~/Downloads/policy-candidate.yaml`).
   Keep the deny-all rules for an initial exercise.
2. Sign the downloaded bytes with the development key:

   ```sh
   ./scripts/dev sign ~/Downloads/policy-candidate.yaml
   ```

   This writes `policy-candidate.yaml.sig` next to your download.
3. Upload the candidate and its signature as Alice; it becomes a pending proposal.
4. In another browser profile or private window, sign in as Bob. Open Proposals,
   review the candidate digest against the signed handoff, and approve. Alice
   cannot approve her own proposal. If the token is stale, sign out and back in.

Development keeps the signing key in the container for convenience; production
uses the offline signing procedure in the [console runbook](../../docs/console-runbook.md).
Remove downloaded test files when finished; never commit generated keys.

## Troubleshooting and reset

- Ports 3000, 8080 and 8443 must be free. `scripts/dev logs` shows startup failures.
- On the first build, `up` waits up to 30 minutes. If it times out, inspect logs;
  the containers continue running. Start again after resolving the failure.
- If Docker runs out of memory, increase its allocation or reduce
  `CARGO_BUILD_JOBS` in Compose. Build/test caches live in Docker volumes, not
  the host `target` directory.
- Keycloak imports the realm only when it does not already exist. Changes to
  `realm.json` need a fresh development identity database.
- If Keycloak is recreated, use `down` then `up` to recreate the shared network
  namespace too. `restart` is for source changes, not Compose changes.

To delete **all this stack's data and caches** and start fresh:

```sh
./scripts/dev reset --yes
./scripts/dev up
```

Reset removes development users, policies, audit history, keys, certificates and
build caches. It does not remove files in the checkout or other Compose projects.

## Validation recorded September 6, 2026

On Linux amd64 with Docker 29.2.1, the fresh realm import and signed-state
initialization ran successfully. `scripts/dev smoke` passed for both users:
actual Keycloak PKCE login, all nine console pages, Origin refusal and logout.
Chrome 152.0.7977.82 also completed sign-in, the Strict-cookie Continue
navigation, and policy-authoring rendering. The signing helper produced a
signature for a filename containing spaces. Container recreation preserved
signed state and reused the build cache (3.7 seconds for the unchanged build).
`scripts/dev test --test console_tests` passed all 19 console integration tests
inside the development container.
Other browsers, architectures and identity providers were not exercised here.
