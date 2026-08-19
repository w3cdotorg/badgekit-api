# Security Notes

This file tracks known, accepted dependency risks for `badgekit-api` and
records what was checked as part of the Task 4.4 security pass (production
secrets fail-fast + `npm audit`).

## `npm audit --omit=dev` — result

As of this pass, `npm audit --omit=dev` reports **10 vulnerabilities**
(1 low, 1 moderate, 6 high, 2 critical), all requiring a breaking major-version
bump to resolve. `npm audit fix` (no `--force`) was run and made **no
changes** — every proposed fix in this tree requires `--force` and pulls in a
breaking upgrade. None qualify as a "minor/patch bump resolves it" fix, so
none were applied. Each item is listed below with the reasoning for accepting
the risk as-is for now.

### restify chain — `find-my-way`, `send`, `uuid` (high/moderate)

`restify@4.3.1 - 11.1.0` (we're on the upper end of that range) depends on
vulnerable versions of `find-my-way` (ReDoS, HTTP/2 DoS), `send` (template
injection XSS), and `uuid` (buffer bounds check). The only fix is
`restify@9.1.0` via `npm audit fix --force`, which is a breaking change to
the HTTP framework underpinning every route in this app — out of scope for
this pass. **Mitigation in place:** the app is not exposed to arbitrary
HTTP/2 traffic directly (fronted by a reverse proxy/load balancer in
deployment), and routes are fixed (not user-defined "multiparametric"
patterns), which limits exposure to the `find-my-way` ReDoS. Revisit as a
dedicated restify-major-version upgrade task.

### `db-migrate` 0.6.x pin — `moment`, `semver` (high)

`db-migrate` is intentionally pinned to `~0.6.3` (see `package.json`) because
later `db-migrate` majors changed the migration API/config format in ways
that would require rewriting the existing migration files under
`migrations/`. This pin transitively drags in vulnerable `moment` (ReDoS,
path traversal in `moment.locale`) and `semver` (ReDoS). **Accepted risk:**
`db-migrate` only runs at deploy/ops time against trusted, operator-supplied
input (migration file names, DB config) — it is not part of the request-serving
path and is not reachable by untrusted/external input. Fixing requires
`db-migrate@0.11.14` (`npm audit fix --force`) and a migration-tooling
upgrade, tracked separately from this security pass.

### `optimist` — via `minimist` (critical)

`optimist` (a direct dependency, `~0.6.1`, used for CLI arg parsing) depends
on vulnerable `minimist` (prototype pollution). **Accepted risk:** `optimist`
is only exercised for local/CLI argument parsing, not on any code path that
processes untrusted network input, so the prototype-pollution vector (crafted
CLI args) is not attacker-reachable in this app's deployment model. A fix
requires `optimist@0.5.2` (a *downgrade*, not even a real fix) via
`--force`, so no safe automated remediation exists; replacing `optimist`
outright is the real fix and is out of scope here.

### `minimatch` (high, ReDoS)

Flagged via `bunyan` → `mv` → `rimraf` → `glob@6.0.4` (production path) and
also via `jshint`/`tap` (dev tooling). `npm audit fix` cannot bump it without
forcing a `jshint@0.5.9` downgrade (a much older, less capable version),
because `jshint`'s own dependency range pins the hoisted `minimatch` install.
**Accepted risk:** the ReDoS requires an attacker-controlled glob *pattern*
being matched, not attacker-controlled input being matched against a fixed
pattern; `bunyan`'s use of `glob` (via `mv`/`rimraf`, used during log file
rotation) does not take pattern input from requests.

### Vendored `streamsql` (`file:./vendor/streamsql`)

`streamsql` is vendored directly in `vendor/streamsql` (not resolved from the
registry, so it never shows up in `npm audit` output at all). It has not
been updated/reaudited as part of this pass — **accepted/tracked risk**:
because it's vendored, it receives no upstream security patches
automatically. It should be reviewed for hand-applied patches or replaced
with a maintained MySQL client wrapper in a future pass.

## What changed in this pass

- `app/index.js`: added a fail-fast check — when `NODE_ENV=production`,
  `MASTER_SECRET` must not be unset, empty, or one of the known
  weak/placeholder dev values (`devsecret`, `dev-cookie-secret`,
  `dev-api-secret`, `blah`). The app throws immediately at boot instead of
  silently accepting a weak signing secret for master-key JWT auth. This
  only applies to `NODE_ENV=production`, so `test`/`development` flows
  (including the `tap` suite, which forces `NODE_ENV=test`) are unaffected.
- `Dockerfile`: added `ENV NODE_ENV=production`. The fail-fast check above
  is gated on `NODE_ENV === 'production'`, so it previously never actually
  ran in a built image (Node defaults to no `NODE_ENV`, which is not the
  string `'production'`) — the image now defaults into the hardened
  posture instead of silently skipping the check. Deployments that
  genuinely need dev/test behavior in a container (e.g. `badgekit-stack`'s
  local `docker compose`) must explicitly override with
  `NODE_ENV: development` — see that repo's `compose.yaml`.
- `.dockerignore`: added `.env`, so a locally-populated `.env` file (which
  may contain real secrets) is never baked into the built image via
  `COPY . .`.
- `app/models/image.js` / `app/routes/badge-instances.js`: fixed a
  live-URL bug — `Image.toUrl()` returned `/images/<slug>` for BLOB-stored
  images, but the actual served route is `/public/images/:imageId`, so
  every uploaded (non-remote-URL) badge image produced a broken link.
  `makeBadgeClass()` also computed an absolute `imageUrl` but then
  returned the original unresolved relative one. Both are now fixed at
  the source; see the git history for the exact diff and the new test
  assertion in `test/badges.test.js` that pins the correct absolute
  `/public/images/:imageId` URL for a BLOB-backed badge class image.
