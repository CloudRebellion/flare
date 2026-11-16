# Public image qualification

The `image-qualification` job is additional to the unchanged product and
browser job. It builds the exact checked-out Git commit for linux/amd64,
CGO_ENABLED=1, using the pinned Go 1.26.11 Bookworm builder, Bun 1.3.9 frontend
builder and Debian Bookworm runtime. The browser DSN build argument is empty;
this generic artifact does not select any installation or production profile.

The build-only `duckdb-cache` program uses the same go-duckdb module as Flare.
It installs and LOADs postgres and httpfs from official HTTPS with unsigned
extensions disabled, then records the actual DuckDB version/platform and
bounded file hashes. The runtime receives this cache at its normal HOME=/app
location. Neither the installer nor the image-test binary is shipped in the
runtime image.

The PostgreSQL fixture uses the pinned Alpine image's UID/GID 70 and waits on
TCP 127.0.0.1, not its temporary bootstrap Unix socket. Session/CSRF values are
64 random hex characters; the at-rest key encodes exactly 32 random bytes as
base64. These values remain only in disposable containers.

The native image test runs inside the actual loaded image, as UID 1000. Its
only network is a newly created internal bridge with a pinned, disposable
PostgreSQL 16 fixture. No host ports, host mounts, native databases, provider
configuration or installation credentials are used. It requires actual PG16,
strict readiness with DB and analytics healthy and export required, anonymous
API denial, a real DuckDB read-only attach, actual ExportDay, a future-day (2099-01-02) two-row Parquet
and successful durable export ledger, then a cold read after dropping only
the synthetic source table. It also LOADs the cached httpfs extension without
external egress. A hot-only server is a failure.

This small smoke is not a whole backup/restore, historical migration,
production-role policy, SSO acceptance, retention scheduler, S3 or provider
integration qualification. It creates no release, deployment or package
publication. The separate image vulnerability gate remains required before
release: fixed CRITICAL findings block, HIGH findings are advisory, and no
Flare ignore list or new exemptions are introduced here. The existing full
source govulncheck gate is unchanged.

The exact image.tar plus only five named metadata files may be uploaded for
seven days, at a combined maximum 1 GiB. The archive writer enforces an actual
byte cap. Metadata includes image/config/rootfs identity, source labels,
actual Go binary build information and matching binary hash, installed
runtime package versions, signed-cache hashes, synthetic test results and
cleanup evidence. BUILDX_METADATA_PROVENANCE=max requests full provenance and a nonempty
sidecar is required. Its actual parameters/materials schema remains pending
root review; mere presence is not verification of max-mode content. Attached image
attestations are disabled for compatibility with classic Docker --load.
This sidecar is not a provider-signed
release attestation. No full container inspect, environment, provider secret,
database dump, browser source map or command log is uploaded.

Python control tests exercise real bounded streams and metadata refusal but
are not native Docker evidence. Only the additional GitHub job establishes
the image smoke. Known created helpers are removed by exact CID and ownership
label; ambiguous create results are not retried by name. A failure does not
authorize a production change or grant release approval.

Failures emit only a fixed reason code and phase, never exception text or
container environment. Confirmed created CIDs enter cleanup custody before
inspection; cleanup still requires the exact image and ownership label.

The build-only cache installer bootstraps `httpfs` with Go's HTTPS client from
`extensions.duckdb.org` for the embedded DuckDB version/platform. It bounds both
the compressed download and decompressed file, rejects HTTPS downgrades and
foreign redirects, then requires DuckDB's signed local INSTALL/LOAD before the
remaining HTTPS extension installation. This avoids needing `httpfs` to download
itself. Unsigned extensions remain disabled.
