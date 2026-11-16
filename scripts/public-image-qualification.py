#!/usr/bin/env python3
"""Additional public image gate. No deployment, registry push or provider secrets."""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import selectors
import secrets
import signal
import subprocess
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
PG = "postgres@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"
MAX_METADATA = 8 << 20
MAX_ARTIFACT = 1 << 30
PHASE = "SOURCE_PREFLIGHT"
TEST = "TestImageRequiredPG16AnalyticsExportAndBoundaries"

REASON_CODES = frozenset({
    'ACTUAL_BINARY_MISMATCH',
    'ACTUAL_COMPILER_OR_CGO',
    'ACTUAL_KERNEL_PRINCIPAL',
    'APP_NOT_RUNNING',
    'IMAGE_TEST_BINARY_BOUND',
    'IMAGE_TEST_TRANSFER',
    'IMAGE_TEST_HASH',
    'IMAGE_TEST_EXECUTION_DENIED',
    'IMAGE_TEST_FAILED',
    'ARCHIVE_BOUND',
    'ARCHIVE_DEADLINE',
    'ARCHIVE_FAILED',
    'BUILDX_METADATA_BOUND',
    'BUILDX_SIDECAR_REQUIRED',
    'CACHE_HASH',
    'CACHE_PATH',
    'CLEANUP_ABSENCE_UNPROVEN',
    'CLEANUP_OWNERSHIP',
    'CLEAN_EXACT_SOURCE_REQUIRED',
    'COMMAND_FAILED',
    'COMMAND_OUTCOME_UNKNOWN',
    'COMMAND_OUTPUT_BOUND',
    'CREATE_OUTCOME_UNKNOWN',
    'EXACT_GIT_SOURCE_REQUIRED',
    'FILESYSTEM_ERROR',
    'FIXTURE_NETWORK_OR_MOUNT',
    'IMAGE_PLATFORM_OR_VOLUME',
    'IMAGE_PRINCIPAL',
    'IMAGE_SOURCE',
    'INTERNAL_NETWORK_REQUIRED',
    'INVALID_METADATA',
    'METADATA_BOUND',
    'OUTPUT_OUTSIDE_SOURCE_REQUIRED',
    'OWNED_CONTAINER_IDENTITY',
    'PG_NOT_READY',
    'PG_PLATFORM',
    'PUBLIC_PRODUCT_ROOT_REQUIRED',
    'REQUIRED_IMAGE_TEST_NOT_PASSED',
    'SIGNED_CACHE_REQUIRED',
    'TOTAL_ARTIFACT_BOUND',
    'UNEXPECTED_ERROR',
})


class QualificationFailure(RuntimeError):
    def __init__(self, code):
        self.code = code if code in REASON_CODES else "UNEXPECTED_ERROR"
        self.phase = PHASE
        super().__init__(self.code)


def failure_record(error):
    if isinstance(error, QualificationFailure):
        code, phase = error.code, error.phase
    else:
        phase = PHASE
        code = ("COMMAND_OUTCOME_UNKNOWN" if isinstance(error, subprocess.TimeoutExpired)
                else "FILESYSTEM_ERROR" if isinstance(error, OSError)
                else "INVALID_METADATA" if isinstance(error, json.JSONDecodeError)
                else "UNEXPECTED_ERROR")
    return {"status": "failed", "phase": phase, "reason_code": code,
            "release_approval": False}


def run(args, timeout=30, *, visible=False):
    try:
        p = subprocess.run(args, timeout=timeout, check=False,
                           stdout=None if visible else subprocess.PIPE,
                           stderr=None if visible else subprocess.PIPE)
    except subprocess.TimeoutExpired:
        raise QualificationFailure("COMMAND_OUTCOME_UNKNOWN") from None
    if p.returncode:
        raise QualificationFailure("COMMAND_FAILED")
    if not visible and (len(p.stdout) > MAX_METADATA or len(p.stderr) > MAX_METADATA):
        raise QualificationFailure("COMMAND_OUTPUT_BOUND")
    return b"" if visible else p.stdout


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    if len(raw) > MAX_METADATA:
        raise QualificationFailure("METADATA_BOUND")
    with path.open("xb") as stream:
        stream.write(raw)


def inspect(kind, name):
    return json.loads(run(["docker", kind, "inspect", name]))[0]


def image_metadata(v, source):
    c = v["Config"]
    if (v["Os"], v["Architecture"]) != ("linux", "amd64") or c.get("Volumes"):
        raise QualificationFailure("IMAGE_PLATFORM_OR_VOLUME")
    if c.get("User") not in ("flare", "1000", "1000:1000"):
        raise QualificationFailure("IMAGE_PRINCIPAL")
    labels = c.get("Labels") or {}
    if labels.get("org.opencontainers.image.revision") != source:
        raise QualificationFailure("IMAGE_SOURCE")
    return {"id": v["Id"], "os": v["Os"], "architecture": v["Architecture"],
            "rootfs_diff_ids": v["RootFS"]["Layers"], "size": v["Size"],
            "labels": {k: labels[k] for k in ("org.opencontainers.image.revision", "org.opencontainers.image.version")}}


def build_info(raw):
    text = raw.decode()
    if (not re.search(r"^/flare: go1\.26\.11$", text, re.M) or
            any(f"\tbuild\t{k}={v}" not in text for k, v in
                {"CGO_ENABLED": "1", "GOOS": "linux", "GOARCH": "amd64"}.items())):
        raise QualificationFailure("ACTUAL_COMPILER_OR_CGO")


def archive(image, path, limit=MAX_ARTIFACT-MAX_METADATA):
    """Hard cap the bytes actually written, including a slow/stalled producer."""
    p = subprocess.Popen(["docker", "image", "save", image], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    total = 0
    h = hashlib.sha256()
    deadline = time.monotonic()+180
    try:
        with path.open("xb") as output, selectors.DefaultSelector() as selector:
            selector.register(p.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() > deadline:
                    raise QualificationFailure("ARCHIVE_DEADLINE")
                for key, _ in selector.select(1):
                    data = os.read(key.fd, 1 << 20)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    if total+len(data) > limit:
                        raise QualificationFailure("ARCHIVE_BOUND")
                    output.write(data)
                    total += len(data)
                    h.update(data)
            if p.wait(timeout=5):
                raise QualificationFailure("ARCHIVE_FAILED")
        return {"bytes": total, "sha256": h.hexdigest()}
    finally:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGTERM)
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=5)
        p.stdout.close()


def required_image_smoke(args, timeout):
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise QualificationFailure("COMMAND_OUTCOME_UNKNOWN") from None
    if len(result.stdout) > MAX_METADATA or len(result.stderr) > MAX_METADATA:
        raise QualificationFailure("COMMAND_OUTPUT_BOUND")
    if result.returncode:
        # Only fixed public reason codes and test messages leave this process;
        # raw Docker/app errors may include a fixture DSN and are never emitted.
        allowed = {
            "strict readiness or analytics unavailable; hot-only startup is not a pass",
            "anonymous boundary request failed", "anonymous protected route was not denied",
            "PG fixture open failed", "actual PostgreSQL16 required",
            "synthetic cold fixture creation failed", "real DuckDB/PG attach failed",
            "actual analytics query failed", "actual cold exporter failed",
            "nonempty Parquet output required", "durable export ledger mismatch",
            "fixture drop failed", "cold Parquet roundtrip failed",
            "signed offline httpfs cache missing", "required image fixture inputs absent",
        }
        messages = []
        for line in result.stdout.decode(errors="replace").splitlines():
            match = re.match(r"\s*image_qualification_test\.go:[0-9]+: (.*)$", line)
            if match and match[1] in allowed:
                messages.append(match[1])
        denied = b"permission denied" in result.stderr.lower()
        code = "IMAGE_TEST_EXECUTION_DENIED" if denied else "IMAGE_TEST_FAILED"
        print(json.dumps({"phase": PHASE, "reason_code": code,
                          "test_exit": result.returncode, "fixed_test_messages": messages[:8]}), flush=True)
        raise QualificationFailure(code)
    return result.stdout


def copy_image_test(app, source):
    # Docker's archive-copy path can reject a read-only rootfs even when the
    # target is a writable tmpfs. Transfer as the existing unprivileged process.
    with source.open("rb") as stream:
        raw = stream.read((128 << 20) + 1)
    if not raw or len(raw) > 128 << 20:
        raise QualificationFailure("IMAGE_TEST_BINARY_BOUND")
    try:
        result = subprocess.run(["docker", "exec", "--interactive", "--user=1000:1000", app,
            "/bin/sh", "-ceu", "umask 077; cat > /run/image-qualification/image-qualification.test; chmod 0700 /run/image-qualification/image-qualification.test"],
            input=raw, capture_output=True, timeout=45)
    except subprocess.TimeoutExpired:
        raise QualificationFailure("COMMAND_OUTCOME_UNKNOWN") from None
    if result.returncode:
        raise QualificationFailure("IMAGE_TEST_TRANSFER")
    actual = run(["docker", "exec", "--user=1000:1000", app,
                  "sha256sum", "/run/image-qualification/image-qualification.test"]).decode().split()[0]
    if actual != digest(raw):
        raise QualificationFailure("IMAGE_TEST_HASH")


def fixture(image, source, tools, output):
    global PHASE
    request = uuid.uuid4().hex
    label = "flare.image-qualification="+request
    network = "flare-image-"+request
    known = []
    network_created = False
    result = {"status": "failed", "fixture_id": request, "known_helpers_absent": False}

    def create(name, arguments, expected):
        cid = run(["docker", "create", "--rm", "--pull=never", "--name", name,
                   "--label", label, "--network", network, "--cap-drop=ALL",
                   "--security-opt=no-new-privileges", *arguments]).decode().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", cid):
            raise QualificationFailure("CREATE_OUTCOME_UNKNOWN")
        known.append((cid, expected))
        v = inspect("container", cid)
        if v["Image"] != expected or (v["Config"].get("Labels") or {}).get("flare.image-qualification") != request:
            raise QualificationFailure("OWNED_CONTAINER_IDENTITY")
        return cid

    try:
        PHASE = "PULL_PG16"
        run(["docker", "pull", "--platform=linux/amd64", PG], 180, visible=True)
        pg_image = inspect("image", PG)
        if (pg_image["Os"], pg_image["Architecture"]) != ("linux", "amd64"):
            raise QualificationFailure("PG_PLATFORM")
        PHASE = "CREATE_INTERNAL_NETWORK"
        run(["docker", "network", "create", "--internal", "--label", label, network])
        network_created = True
        if not inspect("network", network)["Internal"]:
            raise QualificationFailure("INTERNAL_NETWORK_REQUIRED")
        # These are freshly generated disposable database/session fixture values.
        # They are neither provider credentials nor read from the caller's env.
        password = secrets.token_hex(24)
        PHASE = "CREATE_PG16"
        pg = create(network+"-pg", ["--user=70:70", "--read-only",
            "--memory=768m", "--memory-swap=768m", "--cpus=1", "--pids-limit=128",
            "--tmpfs=/var/lib/postgresql/data:rw,nosuid,nodev,uid=70,gid=70,mode=0700,size=536870912",
            "--tmpfs=/var/run/postgresql:rw,nosuid,nodev,uid=70,gid=70,mode=0755,size=16777216",
            "--tmpfs=/tmp:rw,nosuid,nodev,uid=70,gid=70,mode=1777,size=16777216",
            "--env=POSTGRES_USER=flare", "--env=POSTGRES_DB=flare",
            "--env=POSTGRES_PASSWORD="+password, PG], pg_image["Id"])
        PHASE = "START_PG16"
        run(["docker", "start", pg])
        PHASE = "WAIT_PG16_TCP"
        for attempt in range(60):
            p = subprocess.run(["docker", "exec", pg, "pg_isready", "-h", "127.0.0.1", "-U", "flare", "-d", "flare"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if p.returncode == 0:
                break
            time.sleep(1)
        else:
            raise QualificationFailure("PG_NOT_READY")
        dsn = "postgres://flare:"+password+"@"+network+"-pg:5432/flare?sslmode=disable"
        app_env = {"DATABASE_URL": dsn, "ENVIRONMENT": "production", "BASE_URL": "http://localhost:8080",
                   "SESSION_KEY": secrets.token_hex(32),
                   "CSRF_KEY": secrets.token_hex(32),
                   "FLARE_SECRET_KEY": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                   "FLARE_DSN": "", "FLARE_COMMIT": source,
                   "GOMAXPROCS": "2", "GOMEMLIMIT": "512MiB"}
        args = ["--user=1000:1000", "--read-only", "--memory=2g", "--memory-swap=2g",
                "--cpus=2", "--pids-limit=256", "--stop-timeout=30",
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,uid=1000,gid=1000,mode=1777,size=268435456",
                "--tmpfs=/run/image-qualification:rw,exec,nosuid,nodev,uid=1000,gid=1000,mode=0700,size=134217728",
                "--tmpfs=/app/data:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700,size=134217728"]
        for k, v in app_env.items():
            args.append("--env="+k+"="+v)
        PHASE = "CREATE_APP"
        app = create(network+"-app", args+[image], image)
        # Copy the build-only test binary into ONLY this disposable container's
        # tmpfs after start. It is not in the distributable runtime image.
        PHASE = "START_APP"
        run(["docker", "start", app])
        PHASE = "COPY_IMAGE_TEST"
        state = inspect("container", app)["State"]
        if not state["Running"] or state.get("OOMKilled"):
            raise QualificationFailure("APP_NOT_RUNNING")
        copy_image_test(app, tools/"image-qualification.test")
        PHASE = "VERIFY_FIXTURE_ISOLATION"
        for cid in (pg, app):
            v = inspect("container", cid)
            if (set(v["NetworkSettings"]["Networks"]) != {network} or
                    v["HostConfig"].get("PortBindings") or
                    any(m["Type"] == "bind" or m["Type"] == "volume" for m in v["Mounts"])):
                raise QualificationFailure("FIXTURE_NETWORK_OR_MOUNT")
        if run(["docker", "exec", app, "id", "-u"]).strip() != b"1000":
            raise QualificationFailure("ACTUAL_KERNEL_PRINCIPAL")
        PHASE = "VERIFY_BINARY_AND_SIGNED_CACHE"
        sha = run(["docker", "exec", app, "sha256sum", "/usr/local/bin/flare"]).decode().split()[0]
        if sha != (tools/"flare.sha256").read_text().split()[0]:
            raise QualificationFailure("ACTUAL_BINARY_MISMATCH")
        raw = run(["docker", "exec", app, "cat", "/app/duckdb-cache-manifest.json"])
        manifest = json.loads(raw)
        if manifest["allow_unsigned_extensions"] is not False or manifest["repository"] != "https://extensions.duckdb.org" or not 1 <= len(manifest["files"]) <= 32:
            raise QualificationFailure("SIGNED_CACHE_REQUIRED")
        for entry in manifest["files"]:
            rel = pathlib.PurePosixPath(entry["path"])
            if rel.is_absolute() or ".." in rel.parts:
                raise QualificationFailure("CACHE_PATH")
            actual = run(["docker", "exec", app, "sha256sum", "/app/.duckdb/extensions/"+str(rel)]).decode().split()[0]
            if actual != entry["sha256"]:
                raise QualificationFailure("CACHE_HASH")
        save(output/"duckdb-cache-manifest.json", raw)
        packages = run(["docker", "exec", app, "dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
        save(output/"runtime-packages.txt", packages)
        PHASE = "RUN_REQUIRED_IMAGE_SMOKE"
        test = required_image_smoke(["docker", "exec", "--user=1000:1000", "--env=FLARE_IMAGE_TEST_DATABASE_URL="+dsn,
                    "--env=FLARE_IMAGE_EXPECTED_COMMIT="+source, app, "/run/image-qualification/image-qualification.test",
                    "-test.v", "-test.run=^"+TEST+"$", "-test.timeout=180s"], 200)
        text = test.decode()
        if ("--- PASS: "+TEST not in text or "IMAGE_PG16_ANALYTICS_EXPORT_BOUNDARIES_PASSED" not in text or
                "--- SKIP:" in text or "--- FAIL:" in text):
            raise QualificationFailure("REQUIRED_IMAGE_TEST_NOT_PASSED")
        result.update(status="passed", actual_binary_sha256=sha, pg_image=pg_image["Id"],
                      internal_network_only=True, strict_readiness_and_analytics=True,
                      real_export_ledger_and_parquet_roundtrip=True, native_anonymous_boundaries=True,
                      actual_test_output_sha256=digest(test), image_test_skips=0,
                      scope="synthetic PG16 image smoke; not a production or full recovery qualification")
    except Exception as error:
        # Capture the failing work phase before finally moves into cleanup.
        if isinstance(error, QualificationFailure):
            raise
        raise QualificationFailure(failure_record(error)["reason_code"]) from None
    finally:
        # Every cleanup target is a syntactically confirmed own create; cleanup
        # independently rechecks its exact label AND expected image before removal.
        # A command with unknown create outcome is not blindly retried by name.
        PHASE = "CLEANUP_KNOWN_FIXTURES"
        for cid, expected_image in reversed(known):
            p = subprocess.run(["docker", "container", "inspect", cid], capture_output=True, timeout=10)
            if p.returncode == 0:
                v = json.loads(p.stdout)[0]
                if v["Id"] != cid or v["Image"] != expected_image or (v["Config"].get("Labels") or {}).get("flare.image-qualification") != request:
                    raise QualificationFailure("CLEANUP_OWNERSHIP")
                subprocess.run(["docker", "rm", "--force", cid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
            probe = subprocess.run(["docker", "ps", "-aq", "--no-trunc", "--filter", "id="+cid], capture_output=True, timeout=10)
            if probe.returncode or probe.stdout.strip():
                raise QualificationFailure("CLEANUP_ABSENCE_UNPROVEN")
        if network_created:
            run(["docker", "network", "rm", network])
        result["known_helpers_absent"] = True
    return result


def main():
    global PHASE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if pathlib.Path.cwd().resolve() != ROOT or (ROOT/"docker-compose.yml").exists():
        raise QualificationFailure("PUBLIC_PRODUCT_ROOT_REQUIRED")
    source = run(["git", "rev-parse", "HEAD"]).decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise QualificationFailure("EXACT_GIT_SOURCE_REQUIRED")
    if run(["git", "status", "--porcelain"]).strip():
        raise QualificationFailure("CLEAN_EXACT_SOURCE_REQUIRED")
    output = args.output_dir.resolve()
    if output == ROOT or ROOT in output.parents:
        raise QualificationFailure("OUTPUT_OUTSIDE_SOURCE_REQUIRED")
    output.mkdir(parents=True, exist_ok=False)
    image = "flare-image-qualification:"+source+"-"+uuid.uuid4().hex
    release = (ROOT/"VERSION").read_text().strip()
    build = ["docker", "buildx", "build", "--platform=linux/amd64", "--provenance=false",
             "--build-arg=FLARE_DSN=", "--build-arg=FLARE_ENVIRONMENT=production",
             "--build-arg=FLARE_COMMIT="+source, "--build-arg=FLARE_RELEASE="+release]
    # Request full provenance in the sidecar; actual parameters/materials
    # still require review. An attached attestation is
    # deliberately disabled: classic Docker --load cannot retain it, and this
    # read-only job neither pushes to a registry nor claims a signed attestation.
    os.environ["BUILDX_METADATA_PROVENANCE"] = "max"
    PHASE = "BUILD_RUNTIME_IMAGE"
    run(build+["--target=runtime", "--load", "--tag="+image,
               "--metadata-file="+str(output/"build-metadata.json"), "."], 1800, visible=True)
    PHASE = "VALIDATE_IMAGE_AND_SIDECAR"
    meta = output/"build-metadata.json"
    if meta.stat().st_size > MAX_METADATA:
        raise QualificationFailure("BUILDX_METADATA_BOUND")
    provenance = json.loads(meta.read_bytes()).get("buildx.build.provenance")
    if not isinstance(provenance, dict) or not provenance:
        raise QualificationFailure("BUILDX_SIDECAR_REQUIRED")
    result = {"source_commit": source, "image": image_metadata(inspect("image", image), source),
              "provenance": {"requested_mode": "max", "sidecar_present": True, "parameters_materials_schema_review": "pending", "provider_signed_attestation": False},
              "provider_credentials_used": False, "production_profile_selected": False,
              "image_vulnerability_scan": "not_run; the separate fixed-CRITICAL/HIGH-advisory image gate remains required before release"}
    with tempfile.TemporaryDirectory(prefix="flare-image-tools-") as directory:
        tools = pathlib.Path(directory)
        PHASE = "EXPORT_BUILD_ONLY_TOOLS"
        run(build+["--target=image-qualification-tools", "--output=type=local,dest="+str(tools), "."], 1800, visible=True)
        info = (tools/"go-buildinfo.txt").read_bytes()
        PHASE = "VERIFY_ACTUAL_COMPILER"
        build_info(info)
        save(output/"go-buildinfo.txt", info)
        result["fixture"] = fixture(result["image"]["id"], source, tools, output)
    PHASE = "EXPORT_BOUNDED_IMAGE_ARCHIVE"
    remaining = MAX_ARTIFACT-sum(p.stat().st_size for p in output.iterdir())-MAX_METADATA
    if remaining <= 0:
        raise QualificationFailure("TOTAL_ARTIFACT_BOUND")
    result["archive"] = archive(result["image"]["id"], output/"image.tar", limit=remaining)
    PHASE = "WRITE_ALLOWLISTED_PROVENANCE"
    save(output/"qualification.json", (json.dumps(result, sort_keys=True, indent=2)+"\n").encode())
    if sum(p.stat().st_size for p in output.iterdir()) > MAX_ARTIFACT:
        raise QualificationFailure("TOTAL_ARTIFACT_BOUND")
    print("Actual linux/amd64 CGO image and synthetic PG16 analytics/export smoke passed; no deployment performed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Command arguments and container env can contain synthetic credentials;
        # never print an exception repr, full inspect, or inherited environment.
        print(json.dumps(failure_record(error), sort_keys=True), flush=True)
        raise SystemExit(1) from None
