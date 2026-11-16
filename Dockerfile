# Flare observability engine (self-contained build).
#
# Local build:
#   cd flare && docker build -t flare .
#
# CGO note: the analytics package uses marcboeker/go-duckdb (DuckDB columnar
# reads + Parquet cold tier), which needs CGO + glibc. The backend stage builds
# on golang:1.26.11-bookworm (glibc) and the runtime is debian:bookworm-slim,
# matching atomicsite's analyticsdb build.

# Stage 1: SvelteKit dashboard.
FROM oven/bun:1.3.9-alpine@sha256:9028ee7a60a04777190f0c3129ce49c73384d3fc918f3e5c75f5af188e431981 AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile
COPY frontend/ .
# These values are deliberately limited to public dashboard metadata. The DSN
# is an ingest-only credential; never pass member/API keys or provider secrets
# as build arguments because Vite/SvelteKit embeds them in the browser bundle.
ARG FLARE_DSN=""
ARG FLARE_ENVIRONMENT=production
ARG FLARE_RELEASE=v0.6.7
ARG FLARE_COMMIT=""
ENV PUBLIC_FLARE_DSN=${FLARE_DSN} \
    PUBLIC_FLARE_ENVIRONMENT=${FLARE_ENVIRONMENT} \
    PUBLIC_FLARE_RELEASE=${FLARE_RELEASE}
RUN if [ -n "${FLARE_COMMIT}" ]; then \
      export PUBLIC_FLARE_RELEASE="${FLARE_RELEASE}+g${FLARE_COMMIT}"; \
    fi; \
    bun run build --sourcemap hidden && bun scripts/stage-source-maps.mjs && \
    bun scripts/write-build-manifest.mjs
# CI may extract /app/frontend/source-maps from this named stage to upload maps
# for this exact bundle. They are outside /app/frontend/build, which is the
# only frontend directory copied into the served binary below. The small hash
# manifest is copied into the final image for exact-bundle verification; map
# bytes and member credentials never enter that image.

# Stage 2: Go server (CGO for go-duckdb). The frontend build is copied in for go:embed.
FROM golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS backend
WORKDIR /app
ARG FLARE_RELEASE=v0.6.7
ARG FLARE_COMMIT=""
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends git ca-certificates build-essential gcc g++ \
    && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
COPY --from=frontend /app/frontend/build ./cmd/server/frontend/build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w -X main.Version=${FLARE_RELEASE} -X main.Commit=${FLARE_COMMIT}" -o /flare ./cmd/server

# Build-only helpers use the SAME module, embedded DuckDB and CGO toolchain.
# Signed official extensions are installed while build egress exists, then
# qualified with the final image on an internal-only network.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=linux go build -o /duckdb-cache-installer ./cmd/duckdb-cache \
    && CGO_ENABLED=1 GOOS=linux go test -tags=imagequalification -c -o /image-qualification.test ./internal/analytics \
    && go version -m /flare > /go-buildinfo.txt \
    && sha256sum /flare > /flare.sha256
RUN /duckdb-cache-installer --directory /duckdb-cache --manifest /duckdb-cache-manifest.json

# CI extracts these build-only files; neither tool binary enters the runtime.
FROM scratch AS image-qualification-tools
COPY --from=backend /image-qualification.test /go-buildinfo.txt /flare.sha256 /

# Stage 3: runtime (debian-slim for glibc + libstdc++, which the duckdb static
# lib needs at runtime).
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime
ARG FLARE_RELEASE=v0.6.7
ARG FLARE_COMMIT=""
LABEL org.opencontainers.image.version="${FLARE_RELEASE}" \
      org.opencontainers.image.revision="${FLARE_COMMIT}"
RUN apt-get update -qq \
    && apt-get upgrade -y -qq \
    && apt-get install -y -qq --no-install-recommends \
       ca-certificates tzdata wget libstdc++6 libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 flare && useradd -u 1000 -g flare -m -d /app flare \
    && mkdir -p /app/data/parquet && chown -R flare:flare /app
COPY --from=backend /flare /usr/local/bin/flare
COPY --from=backend --chown=1000:1000 /duckdb-cache /app/.duckdb/extensions
COPY --from=backend /duckdb-cache-manifest.json /app/duckdb-cache-manifest.json
COPY --from=frontend /app/frontend/build-manifest.json /app/browser-build-manifest.json
USER flare
ENV HOME=/app FLARE_PARQUET_DIR=/app/data/parquet
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/livez || exit 1
ENTRYPOINT ["/usr/local/bin/flare"]
