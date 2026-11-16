#!/usr/bin/env python3
"""Control regressions only. These never claim Docker/native qualification."""
import contextlib
import copy
import importlib.util
import io
import pathlib
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True

SPEC = importlib.util.spec_from_file_location("image_gate", pathlib.Path(__file__).with_name("public-image-qualification.py"))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class Controls(unittest.TestCase):
    def image(self):
        return {"Id": "sha256:"+"a"*64, "Os": "linux", "Architecture": "amd64", "Size": 5,
                "RootFS": {"Layers": ["sha256:"+"b"*64]},
                "Config": {"User": "flare", "Labels": {"org.opencontainers.image.revision": "c"*40,
                "org.opencontainers.image.version": "test"}}}

    def pg_image(self):
        image = self.image()
        image["Descriptor"] = {"digest": "sha256:"+"e"*64,
            "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 1234}
        return image

    def test_pg_named_child_pull_and_create_use_selected_platform_identity(self):
        selected = self.pg_image()
        reference = "docker.io/library/postgres@"+selected["Descriptor"]["digest"]
        cid = "f"*64
        calls = []

        def command(args, *unused, **kwargs):
            calls.append(args)
            if args[:2] == ["docker", "create"]:
                self.assertEqual(args[-1], reference)
                self.assertIn("--pull=never", args)
                self.assertIn("--platform=linux/amd64", args)
                return cid.encode()
            if args[:2] == ["docker", "start"]:
                raise GATE.QualificationFailure("PG_NOT_READY")
            return b""

        def metadata(kind, name):
            if kind == "image":
                self.assertIn(name, (GATE.PG, reference))
                return copy.deepcopy(selected)
            if kind == "network":
                return {"Internal": True}
            if kind == "container":
                created = next(args for args in calls if args[:2] == ["docker", "create"])
                request = created[created.index("--label")+1].split("=", 1)[1]
                return {"Image": selected["Id"],
                        "Config": {"Labels": {"flare.image-qualification": request}}}
            self.fail("unexpected inspect kind")

        absent = subprocess.CompletedProcess([], 1, b"", b"")
        empty = subprocess.CompletedProcess([], 0, b"", b"")
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(GATE, "run", side_effect=command), \
                    mock.patch.object(GATE, "inspect", side_effect=metadata), \
                    mock.patch.object(GATE.subprocess, "run", side_effect=[absent, empty]):
                # Stop the mocked flow at the first start command. Passing the
                # real create guard proves its expected Image remains the Id,
                # while the create reference itself is the named child digest.
                with self.assertRaisesRegex(RuntimeError, "PG_NOT_READY"):
                    GATE.fixture("runtime-image-untouched", "c"*40,
                                 pathlib.Path(directory), pathlib.Path(directory))
        pulls = [args for args in calls if args[:2] == ["docker", "pull"]]
        self.assertEqual(pulls, [["docker", "pull", "--platform=linux/amd64", GATE.PG],
                                ["docker", "pull", "--platform=linux/amd64", reference]])
        self.assertEqual(sum(args[:2] == ["docker", "create"] for args in calls), 1)
        self.assertEqual([args for args in calls if args[:2] == ["docker", "start"]],
                         [["docker", "start", cid]])

    def test_pg_named_child_identity_drift_refuses_before_fixture_creation(self):
        selected = self.pg_image()
        variants = []
        for key, value in (("Id", "sha256:"+"0"*64), ("Architecture", "arm64"),
                           ("Os", "windows"),
                           ("Descriptor", {**selected["Descriptor"], "size": 1235})):
            changed = copy.deepcopy(selected)
            changed[key] = value
            variants.append(changed)
        for changed in variants:
            with self.subTest(changed=changed):
                with mock.patch.object(GATE, "run") as command, \
                        mock.patch.object(GATE, "inspect", side_effect=[selected, changed]):
                    with self.assertRaisesRegex(RuntimeError, "PG_PLATFORM"):
                        GATE.pull_pg16()
                self.assertEqual(command.call_count, 2)
                self.assertTrue(all(call.args[0][:2] == ["docker", "pull"]
                                    for call in command.call_args_list))

    def test_exact_image_and_nonroot(self):
        self.assertEqual(GATE.image_metadata(self.image(), "c"*40)["architecture"], "amd64")
        for key, value in (("User", "root"), ("Volumes", {"/state": {}})):
            v = self.image(); v["Config"][key] = value
            with self.assertRaises(RuntimeError):
                GATE.image_metadata(v, "c"*40)

    def test_wrong_source_or_platform_refuses(self):
        with self.assertRaises(RuntimeError):
            GATE.image_metadata(self.image(), "d"*40)
        v = self.image(); v["Architecture"] = "arm64"
        with self.assertRaises(RuntimeError):
            GATE.image_metadata(v, "c"*40)

    def test_actual_compiler_and_cgo_not_labels(self):
        raw = b"/flare: go1.26.11\n\tbuild\tCGO_ENABLED=1\n\tbuild\tGOOS=linux\n\tbuild\tGOARCH=amd64\n"
        GATE.build_info(raw)
        for old, new in ((b"1.26.11", b"1.26.10"), (b"CGO_ENABLED=1", b"CGO_ENABLED=0"), (b"amd64", b"arm64")):
            with self.assertRaises(RuntimeError):
                GATE.build_info(raw.replace(old, new))

    def test_metadata_bound_refuses_before_file_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory)/"output"
            with mock.patch.object(GATE, "MAX_METADATA", 4), self.assertRaises(RuntimeError):
                GATE.save(target, b"12345")
            self.assertFalse(target.exists())

    def test_metadata_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory)/"output"
            target.write_bytes(b"preserved")
            with self.assertRaises(FileExistsError):
                GATE.save(target, b"replacement")
            self.assertEqual(target.read_bytes(), b"preserved")

    def test_archive_real_stream_exact_boundary(self):
        original = subprocess.Popen
        def producer(*args, **kwargs):
            return original(["python3", "-c", "import sys;sys.stdout.buffer.write(b'x'*32)"], **kwargs)
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(GATE.subprocess, "Popen", side_effect=producer):
            p = pathlib.Path(directory)/"image.tar"
            self.assertEqual(GATE.archive("synthetic", p, limit=32)["bytes"], 32)
            self.assertEqual(p.read_bytes(), b"x"*32)

    def test_archive_real_stream_cannot_exceed_bound(self):
        original = subprocess.Popen
        def producer(*args, **kwargs):
            return original(["python3", "-c", "import sys;sys.stdout.buffer.write(b'x'*33)"], **kwargs)
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(GATE.subprocess, "Popen", side_effect=producer):
            p = pathlib.Path(directory)/"image.tar"
            with self.assertRaisesRegex(RuntimeError, "ARCHIVE_BOUND"):
                GATE.archive("synthetic", p, limit=32)
            self.assertLessEqual(p.stat().st_size, 32)

    def test_image_test_transfer_real_binary_bytes_and_permissions(self):
        original = subprocess.run
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory)/"input"
            target = pathlib.Path(directory)/"output"
            raw = b"ELF\x00\xff\n"*1024
            source.write_bytes(raw)
            def transport(args, **kwargs):
                self.assertEqual(args[:5], ["docker", "exec", "--interactive", "--user=1000:1000", "owned"])
                self.assertEqual(args[5:7], ["/bin/sh", "-ceu"])
                script = args[7].replace("/run/image-qualification/image-qualification.test", shlex.quote(str(target)))
                return original(["/bin/sh", "-ceu", script], **kwargs)
            def installed_hash(args):
                return (GATE.digest(target.read_bytes())+"  /run/image-qualification/image-qualification.test\n").encode()
            with mock.patch.object(GATE.subprocess, "run", side_effect=transport), mock.patch.object(GATE, "run", side_effect=installed_hash):
                GATE.copy_image_test("owned", source)
            self.assertEqual(target.read_bytes(), raw)
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
            with mock.patch.object(GATE.subprocess, "run", side_effect=transport), mock.patch.object(GATE, "run", return_value=b"wrong  path"):
                with self.assertRaisesRegex(RuntimeError, "IMAGE_TEST_HASH"):
                    GATE.copy_image_test("owned", source)

    def test_image_smoke_failure_logs_only_fixed_messages(self):
        output = io.StringIO()
        fake = subprocess.CompletedProcess([], 1,
            b"    image_qualification_test.go:10: actual cold exporter failed\n    image_qualification_test.go:11: postgres://private-secret\n",
            b"private-container-secret")
        with mock.patch.object(GATE.subprocess,"run",return_value=fake), contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(RuntimeError,"IMAGE_TEST_FAILED"):
                GATE.required_image_smoke(["synthetic"],2)
        self.assertIn("actual cold exporter failed",output.getvalue())
        self.assertNotIn("private-secret",output.getvalue())
        self.assertNotIn("private-container-secret",output.getvalue())
        denied = subprocess.CompletedProcess([],126,b"",b"permission denied: private-path")
        with mock.patch.object(GATE.subprocess,"run",return_value=denied), contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(RuntimeError,"IMAGE_TEST_EXECUTION_DENIED"):
                GATE.required_image_smoke(["synthetic"],2)
        self.assertNotIn("private-path",output.getvalue())

    def test_image_smoke_timeout_never_repeats(self):
        with mock.patch.object(GATE.subprocess,"run",side_effect=subprocess.TimeoutExpired("synthetic",1)) as call:
            with self.assertRaisesRegex(RuntimeError,"COMMAND_OUTCOME_UNKNOWN"):
                GATE.required_image_smoke(["synthetic"],1)
            self.assertEqual(call.call_count,1)

    def test_image_test_transfer_timeout_never_repeats(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory)/"input"
            source.write_bytes(b"synthetic")
            with mock.patch.object(GATE.subprocess, "run", side_effect=subprocess.TimeoutExpired("synthetic",45)) as call:
                with self.assertRaisesRegex(RuntimeError,"COMMAND_OUTCOME_UNKNOWN"):
                    GATE.copy_image_test("owned",source)
                self.assertEqual(call.call_count,1)

    def test_command_timeout_is_unknown_and_never_retried(self):
        with mock.patch.object(GATE.subprocess, "run", side_effect=subprocess.TimeoutExpired("synthetic", 1)) as call:
            with self.assertRaisesRegex(RuntimeError, "COMMAND_OUTCOME_UNKNOWN"):
                GATE.run(["synthetic"])
            self.assertEqual(call.call_count, 1)
        with mock.patch.object(GATE, "PHASE", "BUILD_RUNTIME_IMAGE"):
            failure = GATE.QualificationFailure("COMMAND_FAILED")
        with mock.patch.object(GATE, "PHASE", "CLEANUP_KNOWN_FIXTURES"):
            self.assertEqual(GATE.failure_record(failure)["phase"], "BUILD_RUNTIME_IMAGE")
            redacted = GATE.failure_record(RuntimeError("postgres://private-value"))
        self.assertEqual(redacted["reason_code"], "UNEXPECTED_ERROR")
        self.assertNotIn("private-value", str(redacted))


if __name__ == "__main__":
    unittest.main(verbosity=2)
