# deploy-server

A minimal HTTP server that replaces the SSH-based deployment workflow used by GitLab CI.

Instead of granting CI runners broad SSH access with `sudo` privileges, pipelines authenticate with a **short-lived GitLab OIDC ID token** and send scoped HTTP requests to this server, which runs `docker compose` on the host Docker daemon. There is no long-lived shared secret and no shell access: the target stack is derived from the verified token, and every uploaded compose file is checked against a deployment policy before it is run.

The trust model, the controls and the residual risks are described in [SECURITY.md](SECURITY.md). Read it before exposing the server.

---

## Table of contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [Security model](#security-model)
- [Deployment policy](#deployment-policy)
- [API reference](#api-reference)
- [Auto-stop](#auto-stop)
- [Importing legacy stacks](#importing-legacy-stacks)
- [Migration runbook](#migration-runbook)
- [Running the server](#running-the-server)
- [GitLab CI integration](#gitlab-ci-integration)
- [Running tests](#running-tests)
- [Directory layout](#directory-layout)

---

## How it works

| Before (SSH) | After (deploy-server) |
|---|---|
| CI runner SSHs into the host | CI runner sends HTTPS requests to `https://host/deploy`, `/stack`, `/directories`, `/exec` |
| Broad sudo access to create dirs, copy files, run compose | Four endpoints, each acting on one stack |
| Long-lived SSH key stored in CI variables | Per-job OIDC ID token, minted by GitLab, accepted for at most 10 minutes after issuance |
| Caller asserts which project/environment it is | Project and environment are read from the **signed token**, not from the request |
| Any compose file is run as is | The rendered compose model must pass a [deployment policy](#deployment-policy) |

Each CI job requests an ID token through the `id_tokens` block. GitLab signs it with the instance key. deploy-server verifies it against the instance's published JWKS, applies the claim-based authorisation rules (namespace allowlist, protected environments), then derives the target stack `{namespace}-{environment}` from the token's `project_path` and `environment` claims. Every `docker compose` command is pinned to that stack with `-p {namespace}-{environment}`.

Request processing, from outer to inner layer (`main.go`, `newMux`):

1. Audit log (`middleware/audit.go`): one entry per request, rejections included.
2. IP allowlist (`middleware/ipallow.go`): `403` when the client IP is not allowed.
3. Token verification (`middleware/oidc.go`): `401` when the token is missing or invalid.
4. Namespace allowlist (`middleware/authz.go`): `403` when `namespace_path` is not allowed.
5. Protected-environment rule (`middleware/authz.go`): `403` when the ref is not protected.
6. Handler: stack identity, ownership registry, input validation, then the operation.

---

## Requirements

- Go 1.26+ (to build)
- Docker with the Compose plugin (`docker compose`). The server relies on `docker compose config --format json --no-env-resolution`, so the plugin must be recent enough to support these flags. It also runs a few plain `docker` commands on the stack's containers (`ps`, `inspect`, `stop`, `rm`, see [Pre-deploy check of existing containers](#pre-deploy-check-of-existing-containers)). The [Dockerfile](Dockerfile) ships the docker CLI 29.9.0 with Docker Compose v5.6.0.
- A reverse proxy (Traefik recommended) to terminate TLS. The server listens in plain HTTP: `:8080` must **never be exposed directly**.
- A GitLab instance (15.7+) that issues OIDC ID tokens. See [SECURITY.md](SECURITY.md#deployment-assumptions) for the assumptions made about that instance.

---

## Configuration

All settings are read from environment variables (`config/config.go`). Invalid values make the server exit at startup with status `1`.

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `COMPOSE_BASE` | `/data/compose` | Root directory for compose stacks |
| `WEBSITES_BASE` | `/data/websites` | Root directory for bind-mount data |
| `MAX_UPLOAD_MB` | `10` | Maximum size of a `POST /deploy` request body, in MB. Must be between `1` and `1024` |
| `DATA_DIR` | `./data` | Directory for server state (`registry.json`, `autostop.json`), created with mode `0700` |
| `GITLAB_ISSUER` | *(required)* | GitLab OIDC issuer URL. Must be an absolute `https://` URL with a host, e.g. `https://gitlab.example.com` |
| `GITLAB_AUDIENCE` | *(required)* | Required `aud` claim; must match the `id_tokens` `aud` in CI |
| `PROTECTED_ENVS` | `production` | Comma-separated environment names that require a protected branch/tag. Names are slugified like the token's `environment` claim (`Production` and `production` are equivalent); a name whose slug is empty is rejected |
| `ALLOWED_NAMESPACES` | *(empty: all projects allowed)* | Comma-separated GitLab namespace paths (groups, subgroups or user namespaces). A token is accepted only when its `namespace_path` claim equals one of them or is a sub-path of one: `apps/atmosphere` allows `apps/atmosphere/api` but not `apps/atmosphere-evil`. Case-insensitive; surrounding slashes are stripped. When empty, a warning is logged at startup and every project of the GitLab instance may call the server |
| `FORBIDDEN_TRAEFIK_HOSTS` | *(empty)* | Comma-separated host names that no stack may claim in a Traefik `Host()` rule. Should at least contain this server's own public host name (and GitLab's, if it is routed by the same Traefik). A port or trailing dot is stripped; entries are lowercased and must be valid DNS names or IP addresses |
| `ALLOWED_EXTERNAL_NETWORKS` | *(empty: none)* | Comma-separated Docker networks that stacks may join with `external: true`, typically Traefik's shared network. Case-sensitive. When empty, every external network is refused |
| `ALLOWED_IPS` | *(empty: disabled)* | Comma-separated IP/CIDR allowlist (e.g. the GitLab runner egress IP). Non-matching clients get `403`. `/health` is exempt. A warning is logged at startup when empty |
| `TRUSTED_PROXIES` | *(empty)* | Comma-separated IP/CIDR of the reverse proxies allowed to set `X-Forwarded-For`. Required for `ALLOWED_IPS` to work behind a proxy, see [IP allowlist](#ip-allowlist-defence-in-depth). Keep it as narrow as possible |

Bare IPs in `ALLOWED_IPS` and `TRUSTED_PROXIES` are treated as `/32` (IPv4) or `/128` (IPv6).

At startup the server performs OIDC discovery against `GITLAB_ISSUER`; it fails fast if the instance is unreachable or misconfigured.

### HTTP server limits

Fixed in `main.go` and `compose/runner.go`:

| Limit | Value | Purpose |
|---|---|---|
| `ReadHeaderTimeout` | 10 s | Slowloris protection |
| `ReadTimeout` | 5 min | Whole request, body included (a `MAX_UPLOAD_MB` upload must fit in it) |
| `WriteTimeout` | 16 min | Whole request handling; above the 15.5 min of docker time a deploy may use (inspection 30 s, `config` 1 min, `pull` 7 min, `up` 7 min) |
| `IdleTimeout` | 60 s | Keep-alive connections |
| `MaxHeaderBytes` | 64 KiB | Request headers (an ID token is a few KiB) |
| Graceful shutdown | 30 s | Wait for in-flight requests on `SIGINT` / `SIGTERM` |
| JSON body (`/exec`, `/directories`) | 1 MiB | `http.MaxBytesReader` |
| Multipart body (`/deploy`) | `MAX_UPLOAD_MB` | `http.MaxBytesReader` on the whole body, so uploads cannot spill to unbounded temp files |

---

## Security model

This section summarises the controls. The threat model, the residual risks and the deployment assumptions are in [SECURITY.md](SECURITY.md).

### Authentication: GitLab OIDC

Every protected request must carry a GitLab ID token:

```
Authorization: Bearer <id_token>
```

The token is verified by `middleware/oidc.go`:

- signature against the GitLab JWKS, `iss`, `aud` and `exp`;
- `iat` is required: the token is refused when it was issued more than 10 minutes ago, or more than 30 seconds in the future;
- a clock skew of 30 seconds is tolerated on `exp` and `iat`;
- every HTTP request to GitLab (discovery at startup, JWKS fetch and refresh at runtime) has a 10 second timeout.

There is **no static fallback token**. A missing or invalid token is rejected with `401`; the precise reason is written to the audit log (`auth_error`), not sent to the client.

### Namespace allowlist

When `ALLOWED_NAMESPACES` is set, a token whose `namespace_path` claim is absent, or is neither an allowed path nor a sub-path of one, is rejected with `403` on every protected endpoint (audit field `authz_error`). Leaving it empty lets any project of the GitLab instance deploy containers on the host: see [SECURITY.md](SECURITY.md#deployment-assumptions).

### Protected environments

For a token whose environment (slugified) is listed in `PROTECTED_ENVS`, every protected endpoint (`/deploy`, `/stack`, `/directories`, `/exec`) requires:

- `ref_protected` to be `true` (the pipeline runs on a protected branch or tag);
- when the token carries the `environment_protected` claim, that claim to be `true` as well. A protected environment on the server that GitLab reports as unprotected is a configuration mismatch and is refused. An absent claim is not held against the caller.

Violations are rejected with `403` (audit field `authz_error`).

### Identity is derived, not asserted

The target stack is **never** taken from the request body. It is derived server-side from the verified claims:

- `namespace` = GitLab `CI_PROJECT_PATH_SLUG`, reproduced from the `project_path` claim (`internal/slug`);
- `environment` = the `environment` claim, slugified with the same algorithm.

The slug is lowercased, every character other than `a-z` and `0-9` becomes `-`, leading and trailing hyphens are trimmed, and the result is truncated to 63 bytes. Consecutive hyphens are not collapsed. A token without `project_path`, `project_id` or `environment`, or whose slugs are not valid, is rejected with `400`.

The stack key is `{namespace}-{environment}`. The compose files live in `COMPOSE_BASE/{key}/`, bind-mount data in `WEBSITES_BASE/{key}/`, and `{key}` is the compose project name passed with `-p`.

> The `environment` claim is the environment **name**. For simple names (letters and digits, at most 24 characters, starting with a letter, e.g. `staging`, `recette`, `production`) the derived slug equals `CI_ENVIRONMENT_SLUG`. Names for which GitLab appends a hash suffix to `CI_ENVIRONMENT_SLUG` produce a different slug here.

### Ownership registry

Each stack key is owned by one GitLab `project_id`, recorded in `DATA_DIR/registry.json` (`registry/registry.go`):

- `POST /deploy` and `POST /directories` are allowed on an unclaimed key or on a key owned by the caller's `project_id`. `/directories` never claims a key: CI may create bind-mount directories before the first deploy, which then claims it. Ownership is recorded **only after** `docker compose up` has succeeded, so a rejected or failed first deploy does not squat the key.
- `POST /exec` and `DELETE /stack` require the key to be **already claimed** by the caller's `project_id`. An unclaimed key (never deployed through this server, already stopped, or a legacy stack not yet [imported](#importing-legacy-stacks)) is rejected with `403`.
- A key owned by another `project_id` is rejected with `403`.
- An auto-stop keeps the ownership entry; `DELETE /stack` releases it.
- A first deploy that fails during `pull` or `up` is not claimed. If `up` had already started containers, they keep running without an owner: `DELETE /stack` is refused until a deploy of the stack succeeds.

Each entry also stores the exact, unslugged `project_path` and `environment` it was claimed with. Slugging is lossy (`acme-shop/api` and `acme/shop-api` both become `acme-shop-api`), so when a different project whose exact tuple also differs reaches the same key, the request is rejected with a distinct `403` message (`ErrKeyCollision`) and a `registry: key collision between distinct deployments` warning is logged. See [SECURITY.md, A1](SECURITY.md#a1--slug-key-collision-between-distinct-deployments).

### IP allowlist (defence in depth)

When `ALLOWED_IPS` is set, only requests whose resolved client IP falls inside one of the listed networks are served; everything else gets `403`. This is an extra layer on top of OIDC, typically scoped to the CI-runner egress address.

Behind a reverse proxy, the socket peer is the proxy, so the real client IP must be read from `X-Forwarded-For`. That header is trusted **only** when the direct peer is in `TRUSTED_PROXIES`:

- Direct connection from a peer outside `TRUSTED_PROXIES`: the socket IP is used and `X-Forwarded-For` is ignored.
- Connection from a trusted proxy: all `X-Forwarded-For` header lines are joined in order, and the right-most address that is not itself a trusted proxy is used. Entries may be bare IPs or `ip:port` / `[ipv6]:port`.
- An entry that cannot be parsed while walking from the right makes the client IP unresolvable, and the request is refused: skipping it would hand the decision to an entry further left, which the client controls.
- A header that is absent or only lists proxies falls back to the socket peer.

Behind Traefik you must therefore set **both** `ALLOWED_IPS` and `TRUSTED_PROXIES`. `TRUSTED_PROXIES` must contain only the proxy's address: any other peer inside that range (for instance a tenant container on the same Docker network) could forge `X-Forwarded-For`. `/health` is always exempt.

### Audit log

All server logs are written to stderr as JSON lines (`log/slog`), each with `time`, `level` and `msg` plus structured fields.

Every protected request produces exactly **one** `audit` entry, including requests rejected by the IP allowlist, the token check or the authorisation rules. Filter them with `"msg":"audit"`:

```json
{"time":"2026-10-16T10:12:03.418+02:00","level":"INFO","msg":"audit","method":"POST","path":"/exec","status":200,"client_ip":"203.0.113.10","duration_ms":412,"project_path":"group/app","namespace_path":"group","project_id":"42","environment":"staging","ref":"main","ref_protected":true,"user_login":"alice","sha":"3f2c9e1","service":"api","command":["php","bin/console","app:client:install","acme"]}
```

| Field | Present | Content |
|---|---|---|
| `method`, `path`, `status`, `client_ip`, `duration_ms` | always | `client_ip` is resolved exactly like the allowlist; it is empty when it cannot be resolved |
| `error` | status >= 400 | First 256 bytes of the response body |
| `auth_error` | token rejected | Precise verification failure (expired, wrong audience, token too old...), not sent to the client |
| `authz_error` | namespace or protected-environment rule violated | Reason of the `403` |
| `project_path`, `namespace_path`, `project_id`, `environment`, `ref`, `ref_protected`, `user_login`, `sha` | token verified | Identity from the signed claims (`user_email` is deliberately not logged) |
| `environment_protected` | token carries the claim | Logged only when present, so its absence stays distinguishable from `false` |
| `auto_stop_days`, `env_files` | `POST /deploy` with valid form fields | Requested auto-stop and uploaded env file **names** (never their content) |
| `legacy_mounts` | `POST /deploy` refused with `409` by the [pre-deploy check](#pre-deploy-check-of-existing-containers) | One object per refused bind mount: `container` (name), `target` (path in the container), `source` (full host path, never sent to the client), `rw` |
| `service`, `command` | `POST /exec` with a valid body | Target service and full command |
| `directories` | `POST /directories` with a valid JSON body | `service/name` of each requested directory |

Level is `INFO` for success, `WARN` for 4xx and `ERROR` for 5xx. `GET /health` is not audited.

> `POST /exec` logs the command arguments verbatim: do not pass secrets as command-line arguments. When the command fails (`422`, `503`, `504`), the response body holds the command's stdout and stderr, so its first 256 bytes end up in the `error` field of the audit entry.

### No shell interpolation

All `docker` calls are built as `[]string` argument slices passed to `exec.CommandContext("docker", ...)`. Every compose call is `docker compose -p {key} --project-directory {dir} -f {dir}/docker-compose.yml <subcommand>`: `-p` takes precedence over a `name:` in the compose file and over `COMPOSE_PROJECT_NAME`, so a stack cannot act on another compose project's containers, networks or volumes. The plain `docker ps`, `inspect`, `stop` and `rm` calls of the [pre-deploy check](#pre-deploy-check-of-existing-containers) and of [`DELETE /stack`](#delete-stack) take filters built from the stack key and container IDs read from `docker ps`, checked against `^[0-9a-f]{12,64}$` and passed after `--`.

---

## Deployment policy

Every compose file uploaded to `POST /deploy` is validated before it replaces the running stack (`compose/policy.go`). Violations are all collected and returned in one `400` response (at most 20 are listed).

### Validation pipeline

1. The existing containers of the stack are inspected; a bind mount outside the `{key}/{service}/{name}` layout refuses the deploy with `409` ([pre-deploy check](#pre-deploy-check-of-existing-containers)). Nothing has been written yet.
2. The compose file and env files are written to a private staging directory `COMPOSE_BASE/.staging-{key}-*`.
3. `CheckSource` inspects the raw YAML and refuses `include`, and `extends` and `label_file` in any service: they would make `docker compose config` read other server files.
4. `CheckDotEnv` refuses `COMPOSE_*` and `DOCKER_*` variables in an uploaded `.env` (compose would honour them as settings).
5. `docker compose -p {key} ... config --format json --no-env-resolution` renders the canonical model (interpolation, merges, path resolution) from the staging directory. A non-zero exit is a `400`.
6. `ValidatePolicy` checks the rendered model against the rules below.
7. The validated files are renamed into `COMPOSE_BASE/{key}/`, and files from a previous deploy that were not re-uploaded are removed.
8. `docker compose pull`, then `docker compose up -d --remove-orphans --no-build`.
9. Ownership is recorded, then the auto-stop is scheduled or cancelled.

### Rules

| Scope | Refused |
|---|---|
| Top level | `include`; a `name:` different from the stack key |
| Service fields (any non-empty value) | `build`, `cap_add`, `cgroup`, `cgroup_parent`, `credential_spec`, `device_cgroup_rules`, `devices`, `extends`, `external_links`, `gpus`, `ipc`, `label_file`, `pid`, `privileged`, `provider`, `runtime`, `security_opt`, `sysctls`, `use_api_socket`, `userns_mode`, `uts` |
| Lifecycle hooks (`post_start`, `pre_stop`) | `privileged` in any hook entry (the other hook fields are allowed) |
| `network_mode` | Anything other than empty, `none`, `bridge`, `default` or `service:<name>` (so `host` and `container:<id>` are refused) |
| `volumes_from` | `container:<name>` entries |
| `container_name` | A name that does not start with `{key}-` |
| `deploy.resources.reservations.devices` | Any value |
| Service volumes | Types other than `bind`, `volume`, `tmpfs`, `image`. A `bind` source must be exactly `WEBSITES_BASE/{key}/{service}/{name}`, as created by [`POST /directories`](#post-directories): an absolute, clean path (no `.`, `..`, `//` or trailing `/`), `{service}` and `{name}` following the `/directories` rules, and `{key}`, `{service}` and `{name}` each an existing real directory (not a symlink, not a file). `{key}` alone, `{key}/{service}`, deeper paths, relative sources and missing directories are refused. `{service}` does not have to be a service of the compose file |
| `env_file` | Any path that is not a file uploaded with the deploy (directly in the project directory) |
| Top-level volumes | `external`; a driver other than `local`; `driver_opts`; a `name` that does not start with `{key}_` |
| Top-level networks | `external` networks not listed in `ALLOWED_EXTERNAL_NETWORKS` (matched on `name`, or on the key when there is no `name`); for other networks, a driver other than `bridge`, `driver_opts`, or a `name` that does not start with `{key}_` |
| Top-level configs and secrets | `external`; a `file` that is not a file uploaded with the deploy |
| Labels | `com.docker.compose.*` (reserved); `traefik.tcp.*` and `traefik.udp.*`; `traefik.http.routers.*.priority` |
| Traefik router rules (`traefik.http.routers.*.rule`) | A rule that does not restrict every match to explicit `Host()` names (e.g. `PathPrefix(...)` alone, `HostRegexp(...)`, or any negation `!`); an empty `Host()` name; a host listed in `FORBIDDEN_TRAEFIK_HOSTS`. Rules longer than 4096 bytes or nested deeper than 32 levels are refused |

Traefik label keys are compared case-insensitively. `Host(...) && PathPrefix(...)` is accepted (the conjunction is host-restricted); `Host(...) || PathPrefix(...)` is not.

### What the policy does not restrict

`ports:` (published host ports), resource limits, the image source, `user:`, and `${VAR}` interpolation from the server's own environment are not restricted. The consequences are listed in [SECURITY.md](SECURITY.md#residual-risks).

### Writing a compliant compose file

- Use registry images only (`image:`); `build:` is refused and `up` runs with `--no-build`.
- Bind-mount sources must be exactly `WEBSITES_BASE/{key}/{service}/{name}`, e.g. `/data/websites/group-app-staging/api/storage`, and must have been created by `POST /directories` before the deploy. Mount a whole `{name}` directory: neither the stack or service directory, nor a subdirectory or a single file inside `{name}` (`/data/websites/group-app-staging/api/storage/app.conf`) is accepted; ship single files as `configs` instead. Relative sources such as `./data` are refused. Why: a container can write to its own bind directory, and the Docker daemon follows symlinks when `up` creates the containers; with this layout no container can write to a path component of any bind source ([SECURITY.md A2](SECURITY.md#a2--symlink-race-on-bind-sources)).
- Reference env files by their plain uploaded name (`env_file: api.env`).
- Join the Traefik network as an external network listed in `ALLOWED_EXTERNAL_NETWORKS`.
- Give each router an explicit `Host()` rule, without `priority`.

```yaml
services:
  api:
    image: registry.example.com/group/app/api:1.4.2
    env_file: api.env
    volumes:
      # {key}/{service}/{name}, created by POST /directories
      # ({"service":"api","name":"storage"}) before the deploy
      - /data/websites/group-app-staging/api/storage:/app/storage
    networks: [default, web]
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.group-app-staging-api.rule=Host(`app-staging.example.com`)"
      - "traefik.http.routers.group-app-staging-api.entrypoints=websecure"
      - "traefik.http.routers.group-app-staging-api.tls=true"
      - "traefik.http.services.group-app-staging-api.loadbalancer.server.port=8080"
  worker:
    image: registry.example.com/group/app/api:1.4.2
    command: ["php", "bin/console", "messenger:consume"]
    volumes:
      # {service} is a layout segment: another service may mount api/storage
      - type: bind
        source: /data/websites/group-app-staging/api/storage
        target: /app/storage
      # Refused: /data/websites/group-app-staging (depth 0),
      #          /data/websites/group-app-staging/api (depth 1),
      #          /data/websites/group-app-staging/api/storage/cache (depth 3)

networks:
  web:
    external: true   # "web" must be listed in ALLOWED_EXTERNAL_NETWORKS
```

Prefixing router and service names with the stack key avoids collisions with other stacks' Traefik objects, whose names are global within the Docker provider.

---

## API reference

All endpoints below require `Authorization: Bearer <id_token>`. The namespace, environment and project identity come from the token; they are not part of any request body. Error responses are `text/plain`.

Status codes common to every protected endpoint:

| Status | Cause |
|---|---|
| `400` | Token without `project_path` / `project_id` / `environment`, invalid derived slug, invalid body |
| `401` | Missing or invalid token |
| `403` | IP not allowed, namespace not allowed, protected-environment rule, ownership (see each endpoint) |

### `GET /health`

Liveness probe. **No authentication, exempt from the IP allowlist, not audited.** Returns `200 OK` with `{"status":"ok"}`.

### `POST /deploy`

Upload a compose stack, validate it against the [deployment policy](#deployment-policy) and bring it up.

**Content-Type:** `multipart/form-data`

| Field | Type | Required | Description |
|---|---|---|---|
| `compose_file` | file | yes | `docker-compose.yml` content |
| `env_files` | file (0-N) | no | Additional env files (e.g. `api.env`, `.env`). Sent as the field `env_files` or `env_files[]` (both are accepted and merged), repeated once per file. File names must match `^\.?[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`; `docker-compose.yml` and `*.tmp` are reserved; a name may not be uploaded twice, across both field names |
| `auto_stop_days` | int | no | Auto-stop the stack after N days, `1` to `365` |

**Responses:**

| Status | Cause |
|---|---|
| `204 No Content` | Stack deployed |
| `400` | Invalid multipart form or body over `MAX_UPLOAD_MB`, invalid `auto_stop_days`, invalid or duplicated env file name, missing `compose_file`, `include` / `extends` / `label_file`, reserved `.env` variable, `docker compose config` failure, policy violation |
| `403` | Protected-environment rule, key owned by another project (`ErrOwnerMismatch`) or colliding deployment (`ErrKeyCollision`) |
| `409 Conflict` | An existing container of the stack has a bind mount outside the `WEBSITES_BASE/{key}/{service}/{name}` layout ([pre-deploy check](#pre-deploy-check-of-existing-containers)) |
| `500` | Server misconfiguration or filesystem error, inspection of the existing containers failed (`docker ps` / `docker inspect`), `docker compose config` that could not run, `pull` or `up` failure, ownership not recorded after a successful `up` |
| `503` | Request cancelled: while waiting for another operation on the same stack, or during the inspection, `config` or `pull` (`up` is detached from the request once started) |
| `504` | The inspection (30 s), `docker compose config` (1 min), `pull` (7 min) or `up` (7 min) exceeded its timeout |

Failure messages include a short, redacted excerpt of docker compose's stderr (last 400 bytes, server paths replaced by `<stack>`); the full output (last 64 KiB) is logged.

Behaviour:

- Every input is validated before the running stack is touched: invalid fields, a `409` of the pre-deploy check, policy violations and `docker compose config` errors leave the running stack and its compose directory as they were.
- The compose directory mirrors exactly what this deploy uploaded: env files from a previous deploy that are not re-uploaded are removed.
- Deploy, stop and auto-stop on the same stack are serialised by a per-stack lock; a second request waits for the first.
- `pull` is bound to the request: a cancelled pipeline aborts it and leaves the running stack untouched. Once started, `up` is detached from the request so a cancelled pipeline cannot leave a half-applied deployment behind.
- Per-operation timeouts: inspection of the existing containers 30 s (in total), `config` 1 min, `pull` 7 min, `up` 7 min. A command that exceeds its timeout is interrupted, then killed after 10 s.
- At most 4 `docker` processes (`docker compose`, `ps`, `inspect`, `stop`, `rm`) run at once, server-wide; further calls wait for a free slot. That wait is not counted in the per-operation timeouts.
- Captured stdout and stderr are capped at 1 MiB each.

```bash
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $DEPLOY_JWT" \
  -F "compose_file=@docker-compose.yml" \
  -F "env_files=@api.env" \
  -F "auto_stop_days=7" \
  "$DEPLOY_URL/deploy"
```

#### Pre-deploy check of existing containers

Containers started before the `{key}/{service}/{name}` layout rule (by the SSH workflow, or by an older version of this server) may still run with a writable bind on `WEBSITES_BASE/{key}/` or `WEBSITES_BASE/{key}/{service}/`. They keep running during the next deploy's `pull`, and could replace a component of a bind source the policy has just validated with a symlink before `up` creates the new containers ([SECURITY.md A2](SECURITY.md#a2--symlink-race-on-bind-sources)). Every deploy therefore checks the existing containers first, after the ownership check and before anything is written (`handlers/legacy.go`, `compose/containers.go`):

- **What is inspected.** Every container of the stack, in any state (running, exited, created, paused): a stopped container can be restarted with its mounts. A container belongs to the stack when its `com.docker.compose.project` label is `{key}`, or when its name starts with `{key}-` or `{key}_`, unless that name is explained by another compose project of its own (`{key}-api-web-1` labelled `{key}-api` belongs to the stack `{key}-api`). The server runs `docker ps --all --no-trunc --filter label=com.docker.compose.project={key}`, `docker ps --all --no-trunc --filter name=^/?{key}[-_]`, then `docker inspect` on the union, 30 s in total.
- **What is refused.** Every mount of type `bind` must pass the same rule as a bind source of the compose file: a clean absolute path, exactly `WEBSITES_BASE/{key}/{service}/{name}`, no symlink and no file in place of a component (a component that no longer exists is tolerated). A bind on `{key}/` or `{key}/{service}/`, deeper than `{name}`, or outside `WEBSITES_BASE/{key}/` altogether (another stack's data, a host path, `/var/run/docker.sock`) refuses the deploy with `409 Conflict`, read-only or not. Named volumes, `tmpfs` and image mounts are not concerned.
- **The `409` message** lists each refused mount (at most 20) by container name and target path, with the source shown relative to the key or as `outside the stack data directory`; server paths are never returned. The full sources are in the audit entry (`legacy_mounts`) and the server log. Example:

  ```
  existing containers of this stack, started by an older deployment, have bind mounts the deployment policy no longer allows (sources must be exactly WEBSITES_BASE/group-app-staging/<service>/<name>); while they exist they could tamper with this deploy's bind sources: container "group-app-staging-api-1", target "/app/storage": source "group-app-staging/" is not at the <service>/<name> depth; container "group-app-staging_backup_1", target "/var/run/docker.sock": source outside the stack data directory. Remove them with DELETE /stack (move their data to the <service>/<name> layout), then deploy again
  ```

- **Fail closed.** When the inspection itself fails (Docker unreachable, unexpected output, a container removed between `ps` and `inspect`), the deploy is refused with `500` (`503` / `504` on cancellation or timeout) and never proceeds unchecked; a retry is safe.
- **Getting out of a `409`.** Remove the listed containers with [`DELETE /stack`](#delete-stack) (which also handles a legacy stack without a compose file), move their data to the `{service}/{name}` layout, then deploy again. The complete procedure is the [migration runbook](#migration-runbook).

### `DELETE /stack`

Stop and remove the caller's stack, remove its compose directory, release its ownership entry and cancel any pending auto-stop (`stopStack` in `handlers/deploy.go`):

1. when `COMPOSE_BASE/{key}/docker-compose.yml` exists, `docker compose -p {key} ... down --remove-orphans` (timeout 10 min) stops and removes the project's containers and networks, including containers of services no longer in the compose file;
2. every container of the stack still found by the [pre-deploy check's inspection](#pre-deploy-check-of-existing-containers) is then stopped (`docker stop --timeout 10`) and removed (`docker rm --force`), 2 min in total. This covers a stack running without a compose file in `COMPOSE_BASE/{key}/` (started from another directory by an older workflow, or whose directory was removed), and containers named after the key without the compose project label. Their networks and anonymous volumes are left in place;
3. `COMPOSE_BASE/{key}/` is removed.

Bind-mount data under `WEBSITES_BASE` is preserved. The ownership rule is unchanged: the key must be claimed by the caller's `project_id`, so a legacy stack must first be [imported](#importing-legacy-stacks) into the registry, otherwise the request is refused with `403` and nothing is touched.

| Status | Cause |
|---|---|
| `204 No Content` | Stack stopped and removed |
| `403` | Key not claimed (`ErrNotClaimed`), or owned by another project |
| `500` | `docker compose down`, the inspection or removal of the remaining containers, or the directory removal failed (ownership and compose directory are kept; retry) |
| `503` | Request cancelled while waiting for another operation on the same stack |

```bash
curl --fail-with-body -sS -X DELETE \
  -H "Authorization: Bearer $DEPLOY_JWT" \
  "$DEPLOY_URL/stack"
```

### `POST /directories`

Create bind-mount directories with optional ownership and permissions.

**Content-Type:** `application/json` (at most 1 MiB)

```json
{
  "entries": [
    { "service": "api", "name": "storage", "user": "1000", "group": "1000", "mode": "0750" }
  ]
}
```

| Field | Required | Description |
|---|---|---|
| `service` | yes | First layout segment, usually the compose service name: lowercase letters, digits and hyphens, at most 63 characters, starting and ending with a letter or digit |
| `name` | yes | Subdirectory name: letters, digits, `.`, `_`, `-`, at most 128 characters; cannot start with a dot (no `.`, `..` or hidden directories) |
| `user` | no | Numeric UID, `0` to `2147483647`. User names are **not** resolved |
| `group` | no | Numeric GID, `0` to `2147483647`. Group names are **not** resolved |
| `mode` | no | Octal permission string (e.g. `"0750"`, optional `0o` prefix), at most `0777`: setuid, setgid and sticky bits are refused |

Names are refused because they would be resolved against the deploy-server container's `/etc/passwd`, not against the image that uses the directory.

Creates `WEBSITES_BASE/{key}/{service}/{name}/` (mode `0755` unless `mode` is given), the only layout the [deployment policy](#rules) accepts as a bind source. `{service}` is a layout segment, conventionally the compose service using the directory; it is not checked against the compose file. `mode`, `user` and `group` apply to the `{name}` directory only: `{key}/` and `{key}/{service}/` are created `root:root 0755` and never changed, which keeps them out of reach of the stack's containers ([SECURITY.md A2](SECURITY.md#a2--symlink-race-on-bind-sources)). Every entry is validated before the first write. All filesystem access goes through an `os.Root` opened on `WEBSITES_BASE/{key}`, and the stack directory, the service directory and the target must each be a real directory: a symlink or a file in their place is refused.

| Status | Cause |
|---|---|
| `204 No Content` | Directories created (also for an empty `entries` list) |
| `400` | Invalid JSON, invalid entry |
| `403` | Key owned by another project |
| `409 Conflict` | A symlink or a non-directory is in the way, or a path escapes the stack directory |
| `500` | Other filesystem errors |

An unclaimed key is accepted and stays unclaimed. Existing directories are not recreated, but `mode`, `user` and `group` are applied to an existing `{name}` directory.

### `POST /exec`

Run a command inside a running service container (`docker compose exec -T`).

**Content-Type:** `application/json` (at most 1 MiB)

```json
{
  "service": "api",
  "command": ["php", "/app/bin/console", "app:client:install", "acme"]
}
```

`service` follows the same rule as in `/directories`; `command` must not be empty. The command is passed as an argument vector, without a shell.

| Status | Body | Cause |
|---|---|---|
| `200 OK` | `{"stdout": "...", "stderr": "..."}` | Command exited with status 0 |
| `400` | text | Invalid JSON, invalid service, empty command |
| `403` | text | Key not claimed, or owned by another project |
| `422 Unprocessable Entity` | `{"stdout": "...", "stderr": "..."}` | Command (or `docker compose exec`) exited non-zero |
| `503 Service Unavailable` | `{"stdout": "...", "stderr": "..."}` | Request cancelled; the command is interrupted |
| `504 Gateway Timeout` | `{"stdout": "...", "stderr": "..."}` | Command exceeded the 5 minute timeout |

stdout and stderr are each capped at 1 MiB; truncated output ends with `[truncated]`. `/exec` is not serialised with deploys.

```bash
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $DEPLOY_JWT" \
  -H "Content-Type: application/json" \
  -d "{\"service\":\"api\",\"command\":[\"php\",\"/app/bin/console\",\"app:client:install\",\"$CLIENT\"]}" \
  "$DEPLOY_URL/exec"
```

---

## Auto-stop

When `auto_stop_days` is provided on a deploy, the server schedules an automatic stop, replacing any previous schedule. A deploy **without** `auto_stop_days` cancels any pending auto-stop: each successful deploy fully defines the stack's auto-stop state. `DELETE /stack` also cancels it.

The scheduler (`scheduler/autostop.go`) checks deadlines at startup and then every 5 minutes. At the deadline it takes the stack lock, re-checks that the deadline has not been changed by a concurrent deploy, then stops the stack like [`DELETE /stack`](#delete-stack) does (`docker compose down --remove-orphans`, removal of the remaining containers) and removes the compose directory. Bind-mount data under `WEBSITES_BASE` is **not** touched, and the ownership entry is **kept**, so the same project can redeploy. Each auto-stop is bounded by 10 minutes, at most 2 run concurrently, and a failed stop is retried on the next tick.

The schedule survives restarts: it is persisted atomically to `DATA_DIR/autostop.json`, keyed `{namespace}/{environment}`.

---

## Importing legacy stacks

Stacks deployed before the ownership registry existed (for instance by the SSH workflow) are unclaimed: `/exec` and `DELETE /stack` reject them with `403`, `/directories` can change the mode and ownership of their directories, and the first `/deploy` that reaches their key claims them (unless one of their containers fails the [pre-deploy check](#pre-deploy-check-of-existing-containers)). Import them before opening the server to pipelines; once imported, `DELETE /stack` can stop them even though they have no compose file in `COMPOSE_BASE/{key}/`:

```bash
# With the server stopped
DATA_DIR=/app/data deploy-server -import-registry legacy.json
```

The file uses the `registry.json` format: a JSON object keyed by stack key (`{namespace}-{environment}`), whose values are either entry objects or bare `project_id` strings.

```json
{
  "group-app-staging": {
    "project_id": "42",
    "project_path": "group/app",
    "environment": "staging"
  },
  "other-production": "7"
}
```

- Keys must be valid stack keys, and each entry must carry a non-empty `project_id`. `project_path` and `environment` are optional but enable collision detection; `claimed_at` defaults to the import time.
- The import is all-or-nothing: a key already owned by a different `project_id` aborts it and nothing is changed. A key owned by the same `project_id` is kept, and missing `project_path` / `environment` are filled in.
- Only `DATA_DIR` is read from the environment; the OIDC settings are not needed.
- Exit status: `0` on success (a `registry import done` log line lists the changed keys), `1` on failure, `2` on invalid arguments.

Run it while the server is **stopped**: a running server keeps the registry in memory and would overwrite the import on its next write.

---

## Migration runbook

From the SSH workflow, an older version of this server or the previous example deployment, to the current server and the `{key}/{service}/{name}` bind layout. Run the steps in order: each one is a precondition of the next. `{key}` is `{CI_PROJECT_PATH_SLUG}-{environment slug}` (e.g. `group-app-staging`), paths assume `WEBSITES_BASE=/data/websites` and `COMPOSE_BASE=/data/compose`, and host commands run as root.

### Part 1: the server (once)

1. Create the shared network: `docker network create web`.
2. Deploy the server as in [docker-compose.example.yml](docker-compose.example.yml): no Traefik labels on the deploy-server service, the file-provider route, the `deploy` entrypoint (`:8443`) and the `asDefault` entrypoints `web` and `websecure`.
3. Add the `docker-socket-proxy` service and the `socket-proxy` network; point Traefik's Docker provider at `tcp://docker-socket-proxy:2375` instead of the raw socket.
4. Attach deploy-server and Traefik to `deploy-internal` with their fixed IPs, and set `TRUSTED_PROXIES` to Traefik's IP.
5. Set `ALLOWED_NAMESPACES`, `ALLOWED_IPS`, `FORBIDDEN_TRAEFIK_HOSTS` and `ALLOWED_EXTERNAL_NETWORKS`. Keep `:8443` closed on the host firewall for now: no pipeline may reach the server before step 8.

### Part 2: inventory and ownership (once)

6. **Inventory the legacy stacks** and their compose project names:

   ```bash
   docker ps -a --format '{{.Label "com.docker.compose.project"}}\t{{.Names}}\t{{.Status}}' | sort
   ```

   The server finds a stack's containers by the label `com.docker.compose.project={key}` (or by a name starting with `{key}-` / `{key}_`). A stack the SSH workflow ran from `COMPOSE_BASE/{key}/docker-compose.yml` has the directory name, i.e. the key, as default compose project name. A stack whose project name differs (a `name:` in the legacy file, `-p` or `COMPOSE_PROJECT_NAME` in the script) is invisible to the server: note it, it must be stopped by hand at step 10. Then list each stack's bind mounts:

   ```bash
   for id in $(docker ps -aq --filter label=com.docker.compose.project=<key>); do
     docker inspect --format '{{.Name}}{{range .Mounts}}{{if eq .Type "bind"}} {{.Source}} -> {{.Destination}}{{end}}{{end}}' "$id"
   done
   ```

   Every source that is not exactly `/data/websites/<key>/<service>/<name>` is data to move at step 11, and would make the stack's next deploy fail with `409` until its container is gone.
7. **Import the ownership registry**, server stopped: write `legacy.json` with one entry per stack (`project_id`, `project_path`, `environment`) and run `deploy-server -import-registry legacy.json` ([Importing legacy stacks](#importing-legacy-stacks)). Start the server.
8. **Open `:8443`** on the host firewall for the CI runner addresses only, and set `DEPLOY_URL` in the pipelines. Imported keys can now only be used by their owner.

### Part 3: each stack (downtime from step 10 to step 13)

9. **Adapt the compose template and the pipeline** (see [Writing a compliant compose file](#writing-a-compliant-compose-file) and [examples/gitlab-ci.example.yml](examples/gitlab-ci.example.yml)): bind sources exactly `WEBSITES_BASE/{key}/{service}/{name}` (`.../<key>/jwt` becomes `.../<key>/api/jwt`), one `/directories` entry per `{service}/{name}` with numeric `user` / `group`, `web` declared `external: true`, explicit names prefixed with `{key}_` (volumes, networks) or `{key}-` (`container_name`), no `build:`. Disable the SSH deploy jobs.
10. **Stop the legacy stack**, with the pipeline's stop job (`DELETE /stack`). It runs `docker compose down --remove-orphans` when `COMPOSE_BASE/{key}/docker-compose.yml` exists, then stops and removes every remaining container of the stack (also when there is no compose file), and deletes `COMPOSE_BASE/{key}/`: back up the legacy compose and env files first if you need them. It also releases the ownership entry, so run steps 11 to 13 without delay: until the next successful deploy, the key is unclaimed ([SECURITY.md A1](SECURITY.md#a1--slug-key-collision-between-distinct-deployments)). If `down` fails on the legacy compose file (for instance an env file it references is missing), or to keep the entry, stop the stack on the host instead (`docker compose -p <key> down --remove-orphans` from `COMPOSE_BASE/<key>/`, then `docker rm -f` of what remains). Stacks noted at step 6 with another project name are stopped on the host (`docker compose -p <name> down`). Check that nothing is left, stopped containers included:

    ```bash
    docker ps -a --filter label=com.docker.compose.project=<key>
    docker ps -a --filter 'name=^/?<key>[-_]'
    ```
11. **Move the data to the `{service}/{name}` layout**, stack stopped:

    ```bash
    cd /data/websites/<key>
    mkdir -p api dolibarr
    mv jwt log storage api/        # was <key>/jwt, <key>/log, <key>/storage
    mv documents dolibarr/         # was <key>/documents
    ```

    Data that was mounted as `<key>/` or `<key>/<service>/` itself goes into a `{name}` directory of its own (e.g. `<key>/api/data/`).
12. **Reset the intermediate levels to `root:root 0755`** ([deployment assumption 11](SECURITY.md#deployment-assumptions)). Check for symlinks first: `chown` follows a symlink given as an argument.

    ```bash
    find /data/websites/<key> -maxdepth 2 -type l          # must print nothing
    chown root:root /data/websites /data/websites/<key> /data/websites/<key>/*/
    chmod 0755      /data/websites /data/websites/<key> /data/websites/<key>/*/
    ```

    Only `WEBSITES_BASE`, `{key}/` and `{key}/{service}/` are reset; the `{name}` directories keep their application owner, which `/directories` re-applies at the next step.
13. **First deploy** through the pipeline: `/directories` creates the missing directories and applies `mode`, `user` and `group` to the `{name}` leaves, then `/deploy` validates and starts the stack (`204`). A `409` means a container with a legacy mount is still there (back to step 10); a `400` lists the policy violations of the template (step 9).
14. **Verify**:

    ```bash
    # every bind source is /data/websites/<key>/<service>/<name>
    for id in $(docker ps -aq --filter label=com.docker.compose.project=<key>); do
      docker inspect --format '{{.Name}}{{range .Mounts}}{{if eq .Type "bind"}} {{.Source}}{{end}}{{end}}' "$id"
    done
    # root:root 755 on the intermediate levels
    stat -c '%U:%G %a %n' /data/websites/<key> /data/websites/<key>/*/
    # the key is owned by the project (./data is DATA_DIR in the example deployment)
    grep -A3 '"<key>"' ./data/registry.json
    ```

    In the server log, the deploy's audit entry (`"msg":"audit"`, `"path":"/deploy"`) has status `204` and no `legacy_mounts`. Then check the application itself, and that `/exec` works.

---

## Running the server

### Image

[Dockerfile](Dockerfile) builds a static binary (`CGO_ENABLED=0`) and runs it in an Alpine image. The `docker` CLI 29.9.0 and the Docker Compose v5.6.0 plugin are copied from the official `docker:29.9.0-cli` image rather than installed with `apk`; buildx is not installed (stacks are started with `--no-build` and `build:` is refused). Every base image is pinned by tag **and** digest; to upgrade one, bump the tag and refresh the digest with:

```bash
docker buildx imagetools inspect <image>:<tag> --format '{{json .Manifest.Digest}}'
```

The image declares a `HEALTHCHECK` on `GET /health` (every 30 s, with the port derived from `LISTEN_ADDR`, which must then bind all interfaces or loopback). The process runs as root; see [SECURITY.md](SECURITY.md#the-server-runs-as-root-with-the-docker-socket).

### Reference topology

[docker-compose.example.yml](docker-compose.example.yml) deploys deploy-server, Traefik and a Docker socket proxy (requires Docker Compose 2.23.1 or later, for the inline `configs.content`).

```
Internet --:80/:443--> traefik --(web, external, shared)--------------> tenant stacks
         --:8443------>   |
                          +--(deploy-internal, 172.31.250.0/29)-------> deploy-server (172.31.250.3)
                          +--(socket-proxy, internal)--> docker-socket-proxy --> /var/run/docker.sock
```

| Network | Members | Notes |
|---|---|---|
| `web` | Traefik, tenant stacks | External, created beforehand with `docker network create web`. The only entry of `ALLOWED_EXTERNAL_NETWORKS` |
| `deploy-internal` | Traefik (`172.31.250.2`), deploy-server (`172.31.250.3`) | Fixed subnet so `TRUSTED_PROXIES` and the file-provider URL name exact addresses. Not `internal: true`: the server must reach `GITLAB_ISSUER` for the JWKS |
| `socket-proxy` | Traefik, `tecnativa/docker-socket-proxy` | `internal: true`. The proxy only forwards read-only container endpoints (`CONTAINERS=1`, `POST=0`) |

Never list `deploy-internal` or `socket-proxy` in `ALLOWED_EXTERNAL_NETWORKS`: a stack joining them would reach deploy-server directly, or the Docker API.

### Routing of the deploy API

- The deploy-server route is **not** declared with Docker labels. Traefik's Docker provider reads the labels of every container, tenant ones included, so it is kept for tenant routing only. The route is declared in Traefik's **file provider** (inline `configs.content`), whose objects live in the `@file` namespace that tenant labels cannot alter.
- It points at the fixed IP `http://172.31.250.3:8080`, not at the service name: a tenant service named `deploy-server` on `web` would otherwise be a DNS candidate.
- It is served on a dedicated entrypoint `deploy` (`:8443`), to be filtered down to the CI runner addresses by the host firewall. An `ipAllowList` middleware on the router repeats `ALLOWED_IPS` at the Traefik level; keep both in sync.
- `web` and `websecure` are the `asDefault` entrypoints, so tenant routers that do not name an entrypoint never attach to `:8443`.
- `providers.docker.constraints` is not used to separate tenants from the deploy route: constraints are evaluated on container labels, and the deployment policy does not forbid tenants from setting the labels a constraint would match.

### Example configuration

| Variable | Example value | Why |
|---|---|---|
| `TRUSTED_PROXIES` | `172.31.250.2` | Traefik's single fixed IP. Never a Docker pool such as `172.16.0.0/12`, which would also trust tenant containers |
| `ALLOWED_IPS` | CI runner egress IPs | Same list as the Traefik `ipAllowList` middleware |
| `ALLOWED_NAMESPACES` | `apps/atmosphere,infra` | Only these groups may deploy |
| `FORBIDDEN_TRAEFIK_HOSTS` | `deploy.example.com,gitlab.example.com` | The deploy-server host, plus GitLab's if the same Traefik fronts it |
| `ALLOWED_EXTERNAL_NETWORKS` | `web` | Traefik's shared network only |

### Container hardening

The server keeps root (socket access, `chown` of bind directories) but only the capabilities it uses:

| Capability | Used for |
|---|---|
| `CHOWN` | `POST /directories` sets uid/gid |
| `FOWNER` | `chmod` of directories owned by another uid |
| `DAC_OVERRIDE` | Creating and removing entries in directories owned by another uid (e.g. `0750 1000:1000` bind directories, auto-stop cleanup) |

The rest of the example: `cap_drop: [ALL]`, `no-new-privileges`, `read_only: true` with a `tmpfs` on `/tmp` (deploys are staged in `COMPOSE_BASE/.staging-*`, on the compose volume), `mem_limit: 512m`, `pids_limit: 512`, `stop_grace_period: 40s` (the server waits up to 30 s for in-flight requests). The raw Docker socket is mounted without `:ro`: that flag only covers the socket inode, not the API behind it, so it would protect nothing. For private registries, mount a docker `config.json` read-only on `/root/.docker/config.json`; compose forwards these credentials to the daemon, so every stack can pull what they grant access to.

### Migrating from the previous example deployment

The changes to the deployment itself (shared `web` network, file-provider route on `:8443`, socket proxy, `deploy-internal`) are part 1 of the [migration runbook](#migration-runbook).

### Volume paths must match on host and container

When deploy-server runs `docker compose -f /data/compose/myapp-staging/docker-compose.yml`, paths in the compose model are resolved by the **host Docker daemon**, while the policy checks bind sources on the container's filesystem. Always mount the compose and websites directories at the same absolute path inside and outside the container:

```yaml
volumes:
  - /data/compose:/data/compose    # same path on both sides
  - /data/websites:/data/websites  # same path on both sides
```

### Server environment

`docker compose` inherits the server's environment, and compose interpolation (`${VAR}`) as well as value-less `environment:` entries read from it. Run the server with only the variables listed in [Configuration](#configuration) (plus `PATH`), and no secret in its environment. See [SECURITY.md, A3](SECURITY.md#a3--interpolation-reads-the-server-environment).

---

## GitLab CI integration

Request an ID token with the `id_tokens` block and pass it as the bearer. No `DEPLOY_TOKEN` / `DEPLOY_ID` secrets are needed. A complete pipeline migrated from the SSH workflow is in [examples/gitlab-ci.example.yml](examples/gitlab-ci.example.yml); its header summarises the compose policy contract the rendered `docker-compose.yml` must follow, with a minimal compliant service. Further points of that example:

- `DEPLOY_URL` targets the dedicated `:8443` entrypoint; the `aud` (`GITLAB_AUDIENCE`) is an identifier and does not change.
- Env files holding secrets (`API_ENV`, `DOLIBARR_ENV`) are decoded inside the deploy job that uploads them, not published as artifacts by a separate job. If they must come from another job, publish them with a short `expire_in` and `access: developer`.
- The provenance header written into `docker-compose.yml` carries the GitLab login and the job URL, not the user's e-mail address: the file is stored on the host.

```yaml
variables:
  # Dedicated Traefik entrypoint of the example deployment
  DEPLOY_URL: "https://deploy.example.com:8443"

.deploy-base:
  stage: deploy
  image: alpine:3.23
  id_tokens:
    DEPLOY_JWT:
      aud: "https://deploy.example.com"   # must match GITLAB_AUDIENCE
  before_script:
    - apk add --no-cache curl
  script:
    - |
      curl --fail-with-body -sS -X POST \
        -H "Authorization: Bearer $DEPLOY_JWT" \
        -F "compose_file=@docker-compose.yml" \
        -F "env_files=@api.env" \
        -F "auto_stop_days=7" \
        "$DEPLOY_URL/deploy"

deploy-staging:
  extends: .deploy-base
  environment:
    name: staging
  rules:
    - if: '$CI_COMMIT_BRANCH == "staging"'

deploy-production:
  extends: .deploy-base
  environment:
    name: production       # in PROTECTED_ENVS: requires a protected branch
  rules:
    - if: '$CI_COMMIT_BRANCH == "production"'

stop-env:
  stage: deploy
  image: alpine:3.23
  id_tokens:
    DEPLOY_JWT:
      aud: "https://deploy.example.com"
  before_script:
    - apk add --no-cache curl
  script:
    - curl --fail-with-body -sS -X DELETE -H "Authorization: Bearer $DEPLOY_JWT" "$DEPLOY_URL/stack"
  when: manual
  environment:
    name: $CI_COMMIT_BRANCH
    action: stop
```

Checklist:

- The `aud:` value must match the server's `GITLAB_AUDIENCE`.
- Every job that calls the server must declare an `environment:`, so the token carries the `environment` claim. This includes jobs that only call `/exec` or `/directories`.
- The project must live under one of the `ALLOWED_NAMESPACES`, and the runner egress IP must be in `ALLOWED_IPS`.
- Jobs targeting an environment of `PROTECTED_ENVS` must run on a protected branch or tag, for every endpoint, not only `/deploy`. If the environment is also protected in GitLab, the token's `environment_protected` claim is `true`; if it is explicitly unprotected in GitLab, the server refuses the request.
- Call the server shortly after the job starts: a token is refused 10 minutes after issuance.
- Use `curl --fail-with-body` (curl 7.76+) rather than `-f`: the job then fails on an error status **and** prints the server's message, such as the list of policy violations.
- Send env files with the field `env_files` (`-F "env_files=@api.env"`, repeated per file); `env_files[]` is accepted too.
- The compose file must comply with the [deployment policy](#writing-a-compliant-compose-file): bind sources exactly `WEBSITES_BASE/{key}/{service}/{name}` (created by `/directories` beforehand), the Traefik network declared `external: true` and listed in `ALLOWED_EXTERNAL_NETWORKS`, explicit `Host()` rules outside `FORBIDDEN_TRAEFIK_HOSTS`, no `build:`.
- Calling `/directories` before `/deploy` works on a stack's first deployment, so containers start with the right ownership. `/exec` and `DELETE /stack` need a stack already claimed by a successful deploy (or an [import](#importing-legacy-stacks)).
- A `409` on `/deploy` means containers left by an older deployment still have bind mounts outside the `{key}/{service}/{name}` layout: run the stop job (`DELETE /stack`), move the data, then deploy again ([pre-deploy check](#pre-deploy-check-of-existing-containers), [migration runbook](#migration-runbook)).

---

## Running tests

```bash
go test -race -cover ./...
```

The suite needs neither Docker nor a GitLab instance: `internal/testutil` provides a fake `docker` binary (a shell script put first in `PATH` that records its arguments; `docker ps` and `docker inspect` print fixture files, so tests can simulate existing containers and their mounts) and a fake GitLab OIDC issuer (discovery, JWKS and RS256-signed ID tokens). Handlers, the compose runner and policy, OIDC verification and server startup are exercised end to end. Every package is kept at **80 % coverage or more**.

---

## Directory layout

```
deploy-server/
├── main.go                    # Bootstrap (runMain, run), -import-registry, routing (newMux), server limits, graceful shutdown
├── config/config.go           # Environment-based configuration and validation
├── middleware/
│   ├── oidc.go                # GitLab OIDC verification, token age and clock skew, claims context
│   ├── authz.go               # Namespace allowlist and protected-environment rule
│   ├── ipallow.go             # IP allowlist with proxy-aware client IP resolution
│   └── audit.go               # One structured audit entry per protected request
├── handlers/
│   ├── stack.go               # Stack identity derived from verified claims
│   ├── validate.go            # Slug, file name, directory name and path validation helpers
│   ├── lock.go                # Per-stack lock serialising deploy, stop and auto-stop
│   ├── health.go              # GET /health
│   ├── deploy.go              # POST /deploy: staging, validation, install, pull/up, claim; stopStack
│   ├── legacy.go              # Pre-deploy check of the existing containers' bind mounts (409)
│   ├── stop.go                # DELETE /stack, ownership helpers
│   ├── directories.go         # POST /directories (os.Root confined)
│   └── exec.go                # POST /exec
├── compose/
│   ├── runner.go              # docker subprocess wrapper: compose -p pinning, timeouts, output cap, semaphore
│   ├── containers.go          # StackContainers (docker ps + inspect), RemoveContainers (docker stop + rm)
│   └── policy.go              # Deployment policy: CheckSource, CheckDotEnv, ValidatePolicy, CheckBindSourcePath, Traefik rule parser
├── registry/registry.go       # Ownership store (key -> project_id + exact tuple), collision detection, import
├── scheduler/autostop.go      # Auto-stop background goroutine
├── internal/
│   ├── slug/                  # GitLab slugification shared by config, middleware and handlers
│   └── testutil/              # Test doubles: fake docker binary, fake GitLab OIDC issuer
├── examples/
│   └── gitlab-ci.example.yml  # Pipeline migrated from the SSH workflow
├── Dockerfile                 # Multi-stage build, Alpine runtime with the docker CLI
├── docker-compose.example.yml # Example deployment behind Traefik
├── SECURITY.md                # Threat model, controls, residual risks
└── data/                      # Runtime state (gitignored)
    ├── registry.json          # Deployment ownership
    └── autostop.json          # Scheduled stops
```
