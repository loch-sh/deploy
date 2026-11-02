# Security model and known risks

This document describes the trust model of `deploy-server`, the controls in place, the assumptions the deployment must satisfy, and the residual risks that remain. Configuration and API details are in [README.md](README.md).

## Table of contents

- [Trust model](#trust-model)
- [The server runs as root with the Docker socket](#the-server-runs-as-root-with-the-docker-socket)
- [Authentication and authorisation](#authentication-and-authorisation)
- [Stack isolation](#stack-isolation)
- [Controls in place](#controls-in-place)
- [Deployment assumptions](#deployment-assumptions)
- [Residual risks](#residual-risks)
- [Reporting](#reporting)

## Trust model

`deploy-server` holds the Docker socket and runs `docker compose` stacks on behalf of CI pipelines. Its callers are GitLab CI jobs authenticated by a short-lived ID token.

| Actor | Trust | What it can do |
|---|---|---|
| GitLab instance | Fully trusted | Signs the tokens. Whoever controls it, or its signing key, controls every stack |
| Pipeline of an allowed project | Trusted for its own stacks only | Deploy any compose file that passes the policy, run any command in its containers, create directories in its bind-mount tree, stop its stacks |
| Containers of a stack | Untrusted | Run arbitrary images; can write into the stack's bind-mount directories |
| Network clients | Untrusted | Reach the server through the reverse proxy only |

A valid token for an allowed project gives full control of that project's stacks: any image, any command through `/exec`, any environment name chosen in `.gitlab-ci.yml` (each name is a separate stack). The server is designed so that this control does **not** extend to the host or to other projects' stacks: compose commands are pinned to the caller's project name, and the [deployment policy](README.md#deployment-policy) refuses the compose features that grant host access. That boundary is not complete; the gaps are listed under [Residual risks](#residual-risks).

Who can obtain such a token depends on GitLab, not on this server: anyone able to run a pipeline in a project under `ALLOWED_NAMESPACES` can target any non-protected environment of that project. Protected environments additionally require a protected branch or tag, i.e. push or merge rights on it.

## The server runs as root with the Docker socket

The process runs as root inside its container ([Dockerfile](Dockerfile)). This is deliberate:

- it holds the Docker socket, which is already root-equivalent on the host: dropping to an unprivileged user would not reduce what a compromise yields;
- `POST /directories` must `chown` bind-mount directories to arbitrary numeric ids, which requires root (or `CAP_CHOWN`);
- the host-mounted `/data/compose` and `/data/websites` trees are typically root-owned.

[docker-compose.example.yml](docker-compose.example.yml) reduces the container to the capabilities the server uses (`cap_drop: [ALL]`, then `CHOWN`, `FOWNER`, `DAC_OVERRIDE`), sets `no-new-privileges` and a read-only root filesystem. This limits what a compromised process can do inside its container, not through the Docker socket.

The consequence must be stated plainly: **any exploitable bug in deploy-server (in its request handling, its policy checks or its dependencies) is a root compromise of the host.** The security boundary is the API itself: OIDC verification, claim-based authorisation, claim-derived identity, the ownership registry, input validation and the deployment policy. The policy is a deny-list over a large and evolving compose specification, so it must be reviewed whenever Docker Compose is upgraded.

## Authentication and authorisation

Authentication is delegated to GitLab via OpenID Connect (the `id_tokens` CI feature). Each request carries an ID token signed by the GitLab instance. `middleware/oidc.go` verifies its signature, `iss`, `aud` and `exp` against the instance's JWKS, requires an `iat` no older than 10 minutes and no more than 30 seconds in the future, and tolerates 30 seconds of clock skew on `exp`. Requests to GitLab (discovery, JWKS) time out after 10 seconds. There is **no static fallback token**. `GITLAB_ISSUER` must be an `https://` URL, so the JWKS is never fetched over plain HTTP.

The 10 minute age limit bounds the replay window of a leaked token (for instance one printed in a job log) independently of the `exp` GitLab sets. Within that window a leaked token can be replayed by anyone who can reach the server and passes `ALLOWED_IPS`.

Authorisation is applied uniformly to `/deploy`, `/stack`, `/directories` and `/exec` (`middleware/authz.go`):

- **Namespace allowlist:** the `namespace_path` claim must equal an entry of `ALLOWED_NAMESPACES` or be a sub-path of one, compared on whole path segments. Disabled when the variable is empty.
- **Protected environments:** for an environment listed in `PROTECTED_ENVS`, `ref_protected` must be `true`, and `environment_protected` must be `true` when the token carries it.

The target stack is **derived from the verified claims** (`project_path`, `environment`), never from client-supplied request fields. Every operation then checks the ownership registry: the stack key must be owned by the caller's `project_id` (`/exec`, `DELETE /stack`), or be unclaimed or owned by the caller (`/deploy`, `/directories`). Only a successful `/deploy` claims a key.

## Stack isolation

What now prevents a caller from acting on another project's stack:

- **Identity:** the stack key comes from the signed `project_path` and `environment`; ownership is keyed on the signed `project_id`.
- **Compose project pinning:** every `docker compose` command runs with `-p {key} --project-directory {dir}`. A `name:` in the compose file different from the key is refused, and `COMPOSE_*` / `DOCKER_*` variables in an uploaded `.env` are refused.
- **Resource names:** explicit `container_name` must start with `{key}-`; explicit volume and network names must start with `{key}_`; external volumes, configs and secrets are refused; external networks must be listed in `ALLOWED_EXTERNAL_NETWORKS`; `external_links` and `volumes_from: container:` are refused.
- **Filesystem:** a bind source must be exactly `WEBSITES_BASE/{key}/{service}/{name}`, each of the three components an existing real directory (no symlink, no file), so no container can write to a path component of a bind source (see [A2](#a2--symlink-race-on-bind-sources)); a deploy is refused (`409`) while an existing container of the stack, started by an older deployment, has a bind outside that layout; env files, configs and secrets must be files uploaded with the deploy; `include`, `extends` and `label_file` are refused before compose renders the file. `/directories` works through an `os.Root` confined to `WEBSITES_BASE/{key}/` and refuses symlinks.
- **Traefik:** routers must be restricted to explicit `Host()` names outside `FORBIDDEN_TRAEFIK_HOSTS`; `priority`, TCP and UDP routers are refused.

What it does **not** prevent is listed in [Residual risks](#residual-risks): slug collisions ([A1](#a1--slug-key-collision-between-distinct-deployments)), Traefik host hijacking between stacks ([A5](#a5--traefik-routing-between-stacks)), `container_name` squatting ([A6](#a6--container_name-collision)), and host escapes through the gaps of the policy ([A9](#a9--deny-list-policy), and the legacy containers the pre-deploy check cannot see, [A2](#a2--symlink-race-on-bind-sources)).

## Controls in place

| Control | Where |
|---|---|
| GitLab OIDC verification (signature, `iss`, `aud`, `exp`) via JWKS; `iat` at most 10 min old; 30 s clock skew; 10 s timeout towards GitLab | `middleware/oidc.go` |
| `GITLAB_ISSUER` must be `https://`; `MAX_UPLOAD_MB` bounded to 1..1024; `PROTECTED_ENVS` slugified like the claim | `config/config.go` |
| Namespace allowlist on `namespace_path` (segment-wise prefix match) | `middleware/authz.go` |
| Protected environments require `ref_protected` (and `environment_protected` when present) on every protected endpoint | `middleware/authz.go` (and a redundant check in `handlers/stack.go` for `/deploy`) |
| Namespace/environment derived from signed claims, not from the request | `handlers/stack.go`, `internal/slug` |
| Ownership registry keyed on `project_id`; strict verification on `/exec` and `DELETE /stack`; claim only after a successful deploy; exact `project_path` / `environment` stored to detect slug collisions | `registry/registry.go`, `handlers/deploy.go`, `handlers/stop.go` |
| IP allowlist with spoof-resistant, proxy-aware client IP resolution (all `X-Forwarded-For` lines, strict refusal of unparsable entries) | `middleware/ipallow.go` |
| No shell: every Docker command is an argv slice; every compose command pinned with `-p {key} --project-directory {dir}`; container IDs passed to `docker inspect` / `stop` / `rm` checked against `^[0-9a-f]{12,64}$` and given after `--` | `compose/runner.go`, `compose/containers.go` |
| Deployment policy on the raw file, the uploaded `.env` and the rendered model | `compose/policy.go`, `handlers/deploy.go` |
| Staging directory: nothing replaces the running stack before validation succeeds | `handlers/deploy.go` |
| Bind sources pinned to the `{key}/{service}/{name}` layout: clean absolute path, exact depth, segment regexes shared with `/directories`, `Lstat` of each component (real directory, not a symlink, must exist) | `compose/policy.go` |
| Pre-deploy check of the existing containers (every state, found by compose project label `{key}` or by a `{key}-` / `{key}_` name): a bind mount outside the layout (`{key}/`, `{key}/{service}/`, outside `WEBSITES_BASE/{key}/`, symlink or file component) refuses the deploy with `409` before anything is written; inspection failures fail closed (`500` / `503` / `504`); refused mounts audited as `legacy_mounts` | `handlers/legacy.go`, `compose/containers.go`, `compose/policy.go` (`CheckBindSourcePath`) |
| `DELETE /stack` and auto-stop remove every container of the stack: `docker compose down --remove-orphans`, then `docker stop` + `docker rm --force` of the containers still found (legacy stack without compose file, unlabelled containers named after the key) | `handlers/deploy.go` (`stopStack`), `compose/containers.go` |
| `/directories` confined by `os.Root`, symlinks and non-directories refused (`409`), numeric ids only, mode at most `0777`, mode and ownership applied to the `{name}` leaf only, all entries validated before the first write | `handlers/directories.go` |
| Path-traversal guard (`safeChild`), slug regex, strict env-file and directory name validation | `handlers/validate.go` |
| Body size caps: `MAX_UPLOAD_MB` on `/deploy`, 1 MiB on JSON bodies, 64 KiB of headers | `handlers/deploy.go`, `main.go` |
| Server timeouts: `ReadHeaderTimeout` 10 s, `ReadTimeout` 5 min, `WriteTimeout` 16 min, `IdleTimeout` 60 s | `main.go` |
| Per-operation docker timeouts (container inspection 30 s, config 1 min, pull 7 min, up 7 min, down 10 min, container removal 2 min, exec 5 min), output capped at 1 MiB per stream, at most 4 concurrent docker processes | `compose/runner.go`, `compose/containers.go` |
| Per-stack lock: deploy, stop and auto-stop never run concurrently on one stack | `handlers/lock.go` |
| Atomic, fsynced state writes (temp file, rename, directory fsync), mutex-guarded | `registry/registry.go`, `scheduler/autostop.go` |
| Client error messages redact server paths; compose output is only logged | `handlers/deploy.go`, `handlers/legacy.go`, `compose/policy.go` |
| Audit log: one entry per protected request (identity, action, outcome, client IP, `auth_error`, `authz_error`, refused `legacy_mounts`), rejections included | `middleware/audit.go`, `handlers/legacy.go` |

## Deployment assumptions

The controls above only hold if the deployment satisfies the following. Each one is a precondition, not a recommendation.

1. **Private GitLab instance.** Anyone who can create a project, or run a pipeline, under an allowed namespace can deploy containers on the host. On an instance with open sign-up, every user owns a namespace.
2. **`ALLOWED_NAMESPACES` is set** to the groups that are meant to deploy on this host. When it is empty, the server logs a warning at startup and accepts every project of the GitLab instance.
3. **Legacy stacks are imported** with `-import-registry` before pipelines are allowed to call the server. An unclaimed key is claimed by the first successful deploy that reaches it, and that deploy replaces the containers of the compose project of the same name (unless one of them has a bind mount outside the layout, which refuses the deploy with `409`).
4. **Legacy containers are visible to the server, or gone.** The [pre-deploy check](README.md#pre-deploy-check-of-existing-containers) only sees containers labelled `com.docker.compose.project={key}` or named `{key}-…` / `{key}_…`. A stack started under another compose project name (a `name:` in the legacy file, `-p` or `COMPOSE_PROJECT_NAME` in the SSH script) and with other container names is stopped by hand before the stack's first deploy through the server ([migration runbook](README.md#migration-runbook), step 10). See [A2](#a2--symlink-race-on-bind-sources).
5. **Only the reverse proxy reaches the server.** `:8080` is never published on the host, and the deploy-server container is not attached to a network that stacks can join (in particular not to a network listed in `ALLOWED_EXTERNAL_NETWORKS`). A stack container that can reach `:8080` directly bypasses TLS and Traefik. In the example, deploy-server only sits on `deploy-internal`, shared with Traefik alone.
6. **Traefik is isolated from stacks.** Stacks reach Traefik only through the networks of `ALLOWED_EXTERNAL_NETWORKS` (`web` in the example), never through `deploy-internal` or the socket-proxy network. The example also:
   - declares the deploy-server route in Traefik's **file provider**, on a dedicated entrypoint (`:8443`) and towards a fixed IP, so tenant Docker labels can neither shadow nor break it ([A5](#a5--traefik-routing-between-stacks)); tenant routers only attach to the default entrypoints `web` and `websecure`;
   - gives Traefik a read-only Docker API through a socket proxy instead of the raw socket;
   - sets `exposedByDefault=false`, so only containers labelled `traefik.enable=true` are routed;
   - does not enable Traefik's dashboard or API (a stack could otherwise route a host of its own to `api@internal`);
   - never lists `deploy-internal` or `socket-proxy` in `ALLOWED_EXTERNAL_NETWORKS`.

   `FORBIDDEN_TRAEFIK_HOSTS` contains at least the deploy server's public host name, and every other host that matters (GitLab, monitoring) if the same Traefik routes it. The `:8443` entrypoint should be firewalled down to the CI runner addresses on the host.
7. **`TRUSTED_PROXIES` is exact.** It lists the proxy's address (the example uses Traefik's fixed IP on `deploy-internal`), never a whole Docker address pool such as `172.16.0.0/12`. Any peer inside `TRUSTED_PROXIES` can forge `X-Forwarded-For` and therefore choose the client IP checked against `ALLOWED_IPS`.
8. **`ALLOWED_IPS` is set** to the CI runner egress addresses. It does not replace OIDC, but it limits who can replay a leaked token.
9. **The server environment is minimal** (see [A3](#a3--interpolation-reads-the-server-environment)): no secret, no `DOCKER_*` or `COMPOSE_*` variable beyond what is required.
10. **Host and container paths match** for `COMPOSE_BASE` and `WEBSITES_BASE`: the policy checks bind sources on the container's filesystem, while the host daemon mounts them.
11. **The intermediate levels of `WEBSITES_BASE` are root's.** `WEBSITES_BASE`, `WEBSITES_BASE/{key}/` and `WEBSITES_BASE/{key}/{service}/` are writable by root only (no other host user, no shared or network filesystem where another machine writes). `/directories` creates them `root:root 0755` and never changes them; directories left by an older layout (e.g. a service directory `chown`ed to the application uid by the SSH workflow) should be reset to `root:root 0755`. See [A2](#a2--symlink-race-on-bind-sources).

## Residual risks

Severity reflects the impact under the trust model above, assuming the [deployment assumptions](#deployment-assumptions) hold.

| ID | Risk | Severity |
|---|---|---|
| [A1](#a1--slug-key-collision-between-distinct-deployments) | Slug key collision between distinct deployments | Medium |
| [A2](#a2--symlink-race-on-bind-sources) | Symlink race on bind sources between validation and `up` | Low (formerly High) |
| [A3](#a3--interpolation-reads-the-server-environment) | Interpolation reads the server environment | Low to Medium |
| [A4](#a4--published-ports-are-allowed) | Published ports are allowed | Medium |
| [A5](#a5--traefik-routing-between-stacks) | Traefik routing between stacks | Medium |
| [A6](#a6--container_name-collision) | `container_name` collision | Low |
| [A7](#a7--no-resource-quotas) | No resource quotas | Medium |
| [A8](#a8--semaphore-wait-outside-the-time-budget) | Semaphore wait outside the time budget | Low |
| [A9](#a9--deny-list-policy) | Deny-list policy | Low |
| [A10](#a10--server-compromise-is-host-root) | Server compromise is host root | High impact |
| [A11](#a11--tenant-routers-on-the-deploy-entrypoint) | Tenant routers on the deploy entrypoint | Low |

### A1 — Slug key collision between distinct deployments

**Severity: Medium.**

The registry key, the compose project name and the on-disk directories are all derived from `{namespace}-{environment}`, where both parts are GitLab slugs. Slugging is lossy (every non-alphanumeric character becomes `-`, and slugs are truncated to 63 bytes), so distinct deployments can map to the same key:

| `project_path` | `environment` | Key |
|---|---|---|
| `foo/bar` | `baz` | `foo-bar-baz` |
| `foo` | `bar-baz` | `foo-bar-baz` |
| `acme-shop/api` | `staging` | `acme-shop-api-staging` |
| `acme/shop-api` | `staging` | `acme-shop-api-staging` |

**Mechanism in place:**

- ownership is keyed on the signed `project_id`; a key owned by another `project_id` is refused with `403` on every endpoint;
- each entry stores the exact `project_path` and `environment` it was claimed with. When the caller's exact tuple differs from the owner's, the request is refused with a distinct `403` (`ErrKeyCollision`) and a `registry: key collision between distinct deployments` warning naming both tuples is logged. Entries imported in the legacy format (bare `project_id`) have no tuple until their owner's next deploy, so only `ErrOwnerMismatch` is reported for them;
- ownership is recorded only after a successful deploy, so a rejected or failed deploy does not squat a key.

**What remains:**

- **Squatting / DoS.** Whichever project deploys a key first owns it; the other is locked out until an operator edits the registry. Since environment names are chosen freely in `.gitlab-ci.yml`, a member of an allowed project can deliberately pick an environment name that collides with another project's future key.
- **Pre-creating directories under an unclaimed key.** `/directories` accepts an unclaimed key without claiming it, so a colliding project can create directories under it, or change the mode and ownership of existing ones (for instance those of a legacy stack not yet imported). Everything stays confined to `WEBSITES_BASE/{key}/`, and the legitimate project's first deploy still claims the key.
- **Takeover of an unclaimed stack.** A stack that runs on the host but is not in the registry (legacy SSH deployment not imported, or a stack whose first deploy failed after `up` had started containers) is claimed by the first successful deploy reaching its key, which replaces its containers. The pre-deploy check refuses that deploy (`409`) when one of the containers has a bind outside the `{key}/{service}/{name}` layout, which is typical of an SSH deployment, but not otherwise. [Deployment assumption 3](#deployment-assumptions) addresses the legacy case.
- **Renamed or moved projects** derive a new key: the old stack keeps running under the old key, with its ownership entry, until it is stopped.

**Fix if the trust model changes** (e.g. semi-trusted tenants): align registry, compose project name and filesystem on an unambiguous key (a separator that cannot appear in a slug, or a hashed key including `project_id`), and reject ambiguous inputs.

### A2 — Symlink race on bind sources

**Severity: Low** (formerly High: a container could redirect a bind source to any host path).

**The race.** The policy checks each bind source when the compose file is validated, but the Docker daemon resolves the path again when `up` creates the containers, after `pull` (up to 7 minutes later), and follows every symlink on the way. Before the fix any source below `WEBSITES_BASE/{key}/` was accepted, so a running container of the same stack with a writable bind on a parent directory could replace a component of another source by a symlink (`api -> /`) after validation: the new container then got a host bind mount, i.e. root on the host. Verified with Docker 29 / Compose v5: a bind source `{key}/evil/etc` where `evil -> /` mounts the host's `/etc`; compose renders sources without cleaning them (`x/../y` and trailing `/` are passed as is), and a missing source is created by the daemon (`root:root 0755`).

**The fix** (`compose/policy.go`, `checkBindSource`) does not pin the path; it makes sure no container can write to any component of a source:

- a bind source must be exactly `WEBSITES_BASE/{key}/{service}/{name}`, the layout `/directories` creates. `{key}` alone, `{key}/{service}` and anything deeper than `{name}` are refused, as is a non-clean path (`.`, `..`, `//`, trailing `/`). `{service}` must match the slug rule and `{name}` the directory-name rule of `/directories` (same regexes). `{service}` is only a layout segment: it does not have to be a service of the compose file;
- `{key}`, `{key}/{service}` and `{key}/{service}/{name}` are checked with `Lstat`: each must exist and be a real directory, not a symlink and not a file (files cannot be bind-mounted). Existence is required because a missing path cannot be vouched for, and the daemon would create it, following whatever symlink appeared in the meantime; CI calls `/directories` before `/deploy`. Levels above `{key}` belong to the operator and may be symlinks;
- consequently a container only ever has write access to a `{name}/` directory. Every accepted source stops at depth 2, so nothing a container writes inside `{name}/` (symlinks included) is a path component of an accepted source; `{key}/` and `{key}/{service}/` are mounted by no container and stay `root:root 0755` (`/directories` applies mode and ownership to the `{name}` leaf only). Verified with Docker: a root container with a bind on `{name}` cannot rename, remove or replace its mount point (`Resource busy`), cannot unmount or remount it (`Operation not permitted`), and its `/m/..` is the container's own root, not `{service}/`;
- containers left by an older layout are detected (`handlers/legacy.go`, `compose/containers.go`). A container started from a compose file validated before the fix (bind on `{key}/` or `{key}/{service}/`), or by the SSH workflow, keeps that writable mount until it is removed, and could swap a component during the next deploy's `pull`. Every deploy therefore first inspects the stack's existing containers, in any state, found by the label `com.docker.compose.project={key}` or a `{key}-` / `{key}_` name; each bind mount must pass the same layout rule (`CheckBindSourcePath`, which tolerates a component that no longer exists). A bind on `{key}/`, `{key}/{service}/`, deeper, through a symlink or a file, or outside `WEBSITES_BASE/{key}/` (a host path, the Docker socket) refuses the deploy with `409` before anything is written; a failed inspection refuses it too (`500`, `503` / `504`). `DELETE /stack` removes such containers, also for a legacy stack without a compose file (`docker compose down --remove-orphans`, then `docker stop` + `docker rm --force` of what remains). Verified with Docker 29: a running container labelled with the key and bound on `{key}/`, and a never-started unlabelled `{key}_…` container mounting the Docker socket, are both reported and the deploy refused; once imported, `DELETE /stack` removes both, and the next deploy succeeds.

**What remains:**

- **Legacy containers the check cannot see.**
  - containers neither labelled `com.docker.compose.project={key}` nor named `{key}-…` / `{key}_…`: a legacy stack started under another compose project name (`name:` in the file, `-p` or `COMPOSE_PROJECT_NAME` in the SSH script) with default container names, or a container run by hand under another name ([deployment assumption 4](#deployment-assumptions));
  - a container named `{key}-{x}-…` and labelled with the project `{key}-{x}`, which is treated as a container of the stack `{key}-{x}` (otherwise every deploy of `{key}` would be blocked by that other stack's legitimate mounts);
  - a container created after the inspection, by a host user or tool other than this server (deploy, stop and auto-stop of one stack are serialised by the stack lock, and a container of the stack cannot create containers without a Docker socket mount, which the check refuses);
  - a legacy bind that is lexically conforming (`{key}/{service}/{name}`) but was created through a symlink since replaced by a real directory: Docker reports the source as it was given, and only the current state of each component can be checked.
- **Intermediate directories of an older layout.** Directories `chown`ed to an application uid by an older workflow are not reset by `/directories` ([deployment assumption 11](#deployment-assumptions)): containers cannot reach them, but a host user with that uid could. The [migration runbook](README.md#migration-runbook) resets them.
- **Symlinks inside `{name}/`.** A container can still create symlinks (to `/`, to another stack's tree) inside its own `{name}/` directory. They have no effect on bind mounts or on `/directories` (`os.Root`, leaf only), but any host-side tool that walks `WEBSITES_BASE` (backups, copy scripts, an operator's `chown -R`) must not follow symlinks.
- **Host-side writers.** The fix assumes nothing other than root writes to `WEBSITES_BASE/{key}/` and `{key}/{service}/` ([deployment assumption 11](#deployment-assumptions)); a host process that does reopens the race.

### A3 — Interpolation reads the server environment

**Severity: Low to Medium**, depending on what the server's environment holds.

`docker compose` inherits the deploy-server process environment. A compose file can copy any of its variables into a container through `${VAR}` interpolation, through a value-less `environment:` entry (`- VAR`), or through a secret or config with an `environment:` source. The policy validates the rendered model but cannot tell which values came from the server.

Recommendation: run the server with a filtered environment holding only the variables of [Configuration](README.md#configuration) and `PATH`. Do not pass secrets to the server through its environment, and do not set `DOCKER_*` / `COMPOSE_*` variables beyond what is required.

### A4 — Published ports are allowed

**Severity: Medium.**

`ports:` is not restricted. A stack can publish container ports on every host interface, which:

- bypasses the reverse proxy, TLS, and any Traefik middleware;
- exposes services that were meant to stay internal (databases, admin interfaces);
- conflicts with ports used by the host or other stacks: whichever binds first wins, and the other `up` fails (DoS). A stack started while Traefik is down could take `80` or `443`.

Mitigation outside the server: a host firewall that only lets the expected ports through.

### A5 — Traefik routing between stacks

**Severity: Medium.**

The policy forces every router onto explicit `Host()` names and refuses `FORBIDDEN_TRAEFIK_HOSTS`, but it does not bind host names to stacks. A stack can therefore:

- declare a router on another stack's host name. Traefik's default priority is the rule length, so a longer rule such as ``Host(`app.example.com`) && PathPrefix(`/`)`` takes precedence over the legitimate router and captures its traffic;
- reuse another stack's router, service or middleware name. These names are global within Traefik's Docker provider; conflicting definitions make Traefik reject the objects (DoS on the other stack). A deploy-server router declared with Docker labels would be exposed to the same DoS; the example declares it in the file provider instead, whose names live in the `@file` namespace.

Mitigations: list in `FORBIDDEN_TRAEFIK_HOSTS` every host that must not be taken over, keep the deploy-server route out of the Docker provider, prefix Traefik object names with the stack key by convention, and monitor Traefik's logs for conflicting definitions. A server-side fix would be a per-namespace host allowlist.

### A6 — `container_name` collision

**Severity: Low (DoS only).**

`container_name` must start with `{key}-`, but a key may be a prefix of another key: stack `foo-bar` may name a container `foo-bar-baz-web`, which is in the default name space of stack `foo-bar-baz`. Docker refuses duplicate container names, so the second `up` fails. No access to the other stack's container is gained.

The [pre-deploy check](README.md#pre-deploy-check-of-existing-containers) and `DELETE /stack` also match containers by name. A container named `{key}-…` or `{key}_…` that does not carry the compose label of a project its name starts with counts as part of the stack `{key}`: if it has a bind mount outside the layout it blocks the stack's deploys (`409`), and `DELETE /stack` removes it. Containers created by this server never match another stack that way (their name starts with their own project name, which excludes them); an operator container named after a stack key does.

### A7 — No resource quotas

**Severity: Medium.**

The policy does not impose CPU, memory, PID, disk or log limits, and does not restrict the number of stacks: every environment name in `.gitlab-ci.yml` creates a new stack. An allowed project can exhaust the host's resources. Images are pulled from any registry; if the server has registry credentials (a mounted `/root/.docker/config.json`, which compose forwards to the daemon), every stack can pull the images they grant access to.

### A8 — Semaphore wait outside the time budget

**Severity: Low.**

At most 4 `docker` processes (`docker compose`, and the `ps`, `inspect`, `stop` and `rm` calls on a stack's containers) run at once. The wait for a free slot is bounded by the request, not by the per-operation timeouts (container inspection 30 s, config 1 min, pull 7 min, up 7 min, 15.5 min in total), so under load a deploy can exceed the server's 16 minute `WriteTimeout`. The client then sees a failed request although `up`, detached from the request once started, may complete and the stack be claimed. A retried deploy is harmless (it redeploys the same files).

### A9 — Deny-list policy

**Severity: Low** (formerly High: lifecycle hooks were not inspected).

`ValidatePolicy` now refuses `privileged` in the service lifecycle hooks (`post_start`, `pre_stop`) as well as at the service level. The other hook fields (`command`, `user`, `working_dir`, `environment`) stay allowed: a hook runs inside the service container, which gives no more than `/exec` already does. What remains is structural: the policy is a deny-list, so any compose attribute introduced after it was written is allowed by default. Review it against the Compose version shipped in the image at every upgrade.

### A10 — Server compromise is host root

**Severity: High impact, inherent to the design.**

See [The server runs as root with the Docker socket](#the-server-runs-as-root-with-the-docker-socket). A bug in request handling, in the policy, in `docker compose` itself or in a dependency (`go-oidc`, `go-jose`, `yaml.v3`) is a host compromise. Keep dependencies and the Docker CLI up to date, keep `ALLOWED_IPS` set, and keep the server off any network stacks can join.

### A11 — Tenant routers on the deploy entrypoint

**Severity: Low.**

In the [example deployment](README.md#routing-of-the-deploy-api), tenant routers attach by default to `web` and `websecure` only, but the policy does not restrict `traefik.http.routers.*.entrypoints`. A stack can set `entrypoints=deploy` and expose its own services on `:8443`, behind the host firewall rule meant for the CI runners. This does not affect deploy-server itself: its host is in `FORBIDDEN_TRAEFIK_HOSTS`, and its route lives in the file provider. `providers.docker.constraints` would not close the gap, since constraints match container labels that the policy lets tenants set.

## Reporting

Security issues should be reported privately to the maintainers rather than filed as public issues.
