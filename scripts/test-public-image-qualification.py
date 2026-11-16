#!/usr/bin/env python3
"""Control regressions only. These never claim Docker/native qualification."""
import importlib.util
import io
import pathlib
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
