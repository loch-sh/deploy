# Every base image is pinned to an exact version AND a manifest-list digest, so
# a rebuild never silently picks up a different toolchain, libc or docker CLI.
# To upgrade: bump the tag, then refresh the digest with
#   docker buildx imagetools inspect <image>:<tag> --format '{{json .Manifest.Digest}}'

# ── docker CLI + compose plugin ───────────────────────────────────────────────
# Taken from the official docker CLI image rather than from apk: the Alpine
# packages cannot be pinned durably (old revisions leave the repository) and
# lag behind upstream. Both binaries are statically linked.
# docker 29.9.0 ships Docker Compose v5.6.0 (checked with `docker compose version`).
FROM docker:29.9.2-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb AS dockercli

# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.27.3-alpine3.23@sha256:8a5046497cda39860b832ffdbe8dd66018a0f05bb01352f533a36e7e2ced66a0 AS builder

WORKDIR /src

# Cache dependency downloads before copying source
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# VERSION is the release tag (set by the release workflow); TARGETARCH is
# provided by buildx for multi-platform builds (amd64, arm64).
ARG VERSION=dev
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /deploy-server .

# ── Runtime stage ─────────────────────────────────────────────────────────────
# Alpine is used (rather than scratch/distroless) because the server spawns
# the docker CLI as a subprocess and needs PATH lookup, and the healthcheck
# below needs busybox wget. Same Alpine branch as the CI example (3.23).
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

# `docker` client and the `docker compose` plugin the server invokes for stack
# management. buildx is deliberately not installed: stacks are started with
# `up --no-build` and the compose policy refuses `build:`.
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose

# Runs as root on purpose: the server needs the Docker socket (already
# root-equivalent) and must chown bind-mount directories to arbitrary users
# (POST /directories), which requires root. The capability set is reduced at
# run time instead (cap_drop/cap_add in docker-compose.example.yml). See
# SECURITY.md.

# Default data and compose directories — override via env vars or volume mounts.
# /root/.docker is created so it can be a tmpfs / read-only mount point when the
# root filesystem is mounted read-only.
RUN mkdir -p /data/compose /data/websites /app/data /root/.docker

WORKDIR /app

COPY --from=builder /deploy-server /usr/local/bin/deploy-server

# OCI labels (the release workflow adds org.opencontainers.image.version,
# revision, created and source from the git tag via docker/metadata-action).
LABEL org.opencontainers.image.title="deploy-server" \
      org.opencontainers.image.description="GitLab OIDC authenticated docker compose deployment server" \
      org.opencontainers.image.licenses="Apache-2.0"

# Documentation only: the port must NOT be published on the host; Traefik
# reaches it over a dedicated internal network.
EXPOSE 8080

# /health is unauthenticated and exempt from the IP allowlist. The port is
# derived from LISTEN_ADDR (":8080", "0.0.0.0:9000", …) so the probe follows a
# custom listen address; LISTEN_ADDR must then bind all interfaces or loopback
# (the probe targets 127.0.0.1). The ENV only restates the server's default.
ENV LISTEN_ADDR=":8080"
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null "http://127.0.0.1:${LISTEN_ADDR##*:}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/deploy-server"]
