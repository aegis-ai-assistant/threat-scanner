"""Incomplete scans stay out of the clean result, and extraction stays inside its limits."""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import py7zr

from aegis.archive import ArchiveError, ExtractBudget, extract_archive, extract_nested
from aegis.checkpoint import clear_checkpoint, set_checkpoint_path
from aegis.config import AppConfig, load_config
from aegis.intel import FileIntel
from aegis.intel.hybrid import query_hybrid_analysis
from aegis.intel.outcome import STATUS_API_ERROR, classify_virustotal
from aegis.intel.virustotal import (
    _parse_behaviour_summary,
    _wait_for_analysis,
    enrich_virustotal,
    parse_virustotal,
    query_virustotal,
)
from aegis.paths import cleanup_workspace, prepare_workspace
from aegis.rate_limit import RateLimiter
from aegis.report import ThreatRecord, render_html
from aegis.walker import PayloadFile
from aegis.scan import ScanPaused, run_scan, unknown_because


def _config(**overrides) -> AppConfig:
    values = dict(
        virustotal_api_key="vt-test",
        hybrid_analysis_api_key="hybrid-test",
        metadefender_api_key="",
        google_api_key="",
        secondary_engine="none",
        free_tier=False,
        request_delay_seconds=0,
        vt_auto_upload=True,
        vt_sandbox=True,
        vt_analysis_timeout_seconds=1,
        google_model="gemini-3.7-flash",
        report_format="html",
        open_report=False,
        config_path=Path("config.json"),
    )
    values.update(overrides)
    return AppConfig(**values)


class UploadAndVerdictTests(unittest.TestCase):
    def test_auth_failure_does_not_upload(self) -> None:
        class Response:
            status_code = 401
            text = "bad key"
            content = b"bad key"

            def json(self):
                return {}

        posts: list[object] = []

        def fake_post(*args, **kwargs):
            posts.append(args)
            raise AssertionError("upload should not run after an authentication failure")

        limiter = RateLimiter(0, enabled=False)
        with (
            patch("aegis.intel.virustotal.requests.get", lambda *a, **k: Response()),
            patch("aegis.intel.virustotal.requests.post", fake_post),
        ):
            result = query_virustotal("a" * 64, "key", limiter, lambda _line: None)
            intel = result.intel
            enrich_virustotal(
                intel,
                Path("sample.exe"),
                "key",
                limiter,
                lambda _line: None,
                auto_upload=True,
                sandbox=True,
                analysis_timeout=1,
            )
        self.assertEqual(result.status, STATUS_API_ERROR)
        self.assertEqual(posts, [])
        self.assertIn("401", intel.vt_error or "")
        self.assertFalse(intel.vt_uploaded)

    def test_malicious_sandbox_beats_an_earlier_harmless_one(self) -> None:
        payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "undetected": 69},
                    "sandbox_verdicts": {
                        "First": {"category": "harmless", "malware_classification": ["Benign"]},
                        "Second": {"category": "malicious", "malware_classification": ["Emotet"]},
                    },
                }
            }
        }
        intel = parse_virustotal("b" * 64, payload)
        self.assertEqual(intel.sandbox_verdict, "malicious")
        self.assertEqual(intel.sandbox_family, "Emotet")
        self.assertTrue(intel.is_threat)

    def test_zero_detections_ignore_sandbox_verdicts(self) -> None:
        payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 71},
                    "sandbox_verdicts": {
                        "Zenbox": {"category": "harmless"},
                        "C2AE": {"category": "undetected"},
                        "Yomi Hunter": {"category": "malicious", "malware_classification": ["MALWARE"]},
                    },
                }
            }
        }
        intel = parse_virustotal("d" * 64, payload)
        self.assertEqual(intel.malicious, 0)
        self.assertEqual(intel.engine_total, 71)
        self.assertIsNone(intel.sandbox_verdict)
        self.assertEqual(intel.sandbox_behaviors, [])
        self.assertFalse(intel.is_threat)
        self.assertEqual(classify_virustotal(intel), "clean")

    def test_unseen_hash_sandbox_virus_is_written_with_the_hash_miss(self) -> None:
        payload = PayloadFile(
            full_path=Path("oalinst.exe"),
            display_name="oalinst.exe",
            internal_path="oalinst.exe",
            extension=".exe",
        )
        intel = FileIntel(
            sha256="d" * 64,
            malicious=0,
            suspicious=0,
            undetected=0,
            hash_unseen=True,
            vt_uploaded=True,
            sandbox_verdict="malicious",
            sandbox_family="MALWARE",
        )
        self.assertTrue(intel.is_threat)
        page = render_html(Path("sample"), datetime.now(), 1, [ThreatRecord(payload, intel)])
        self.assertIn("No record of this file was found", page)
        self.assertIn("sandbox test", page)
        self.assertIn("malicious", page)

    def test_later_behaviour_summary_does_not_downgrade_malicious(self) -> None:
        intel = FileIntel(sha256="c" * 64, sandbox_verdict="malicious", sandbox_family="Emotet")
        _parse_behaviour_summary(
            intel,
            {"data": {"attributes": {"threat_severity": "harmless", "malware_families": ["Other"]}}},
        )
        self.assertEqual(intel.sandbox_verdict, "malicious")
        self.assertEqual(intel.sandbox_family, "Emotet")

    def test_analysis_poll_sleeps_when_the_rate_limit_is_off(self) -> None:
        sleeps: list[float] = []
        clock = {"now": 0.0}

        def monotonic() -> float:
            return clock["now"]

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock["now"] += seconds

        class Response:
            status_code = 200

            def json(self):
                return {"data": {"attributes": {"status": "queued"}}}

        with (
            patch("aegis.intel.virustotal.time.monotonic", monotonic),
            patch("aegis.intel.virustotal.time.sleep", sleep),
            patch("aegis.intel.virustotal.requests.get", lambda *a, **k: Response()),
        ):
            _wait_for_analysis("analysis", "key", RateLimiter(0, enabled=False), lambda _line: None, 5)
        self.assertGreaterEqual(len(sleeps), 1)
        self.assertTrue(all(item >= 2 for item in sleeps))

    def test_hybrid_overview_auth_error_is_raised(self) -> None:
        class Response:
            def __init__(self, code: int, body: bytes = b"{}") -> None:
                self.status_code = code
                self.content = body
                self.text = body.decode()

            def json(self):
                return {}

        class Session:
            def __init__(self) -> None:
                self.headers = _Headers()

            def post(self, url, **kwargs):
                return Response(400, b"validation")

            def get(self, url, **kwargs):
                return Response(401, b"unauthorized")

        intel = FileIntel(sha256="d" * 64)
        with patch("aegis.intel.hybrid.requests.Session", Session):
            result = query_hybrid_analysis(intel, "key", RateLimiter(0, enabled=False), lambda _line: None)
        self.assertEqual(result.status, STATUS_API_ERROR)
        self.assertIn("401", result.detail)
        self.assertIsNone(intel.hybrid_verdict)

    def test_upload_defaults_to_on(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"virustotal_api_key": "vt-test-key"}), encoding="utf-8")
            loaded = load_config(path)
        self.assertTrue(loaded.vt_auto_upload)


class _Headers:
    def clear(self) -> None:
        return None


class ExtractionTests(unittest.TestCase):
    def test_each_scan_gets_its_own_temp_directory(self) -> None:
        first = prepare_workspace()
        second = prepare_workspace()
        self.addCleanup(lambda: cleanup_workspace(first))
        self.addCleanup(lambda: cleanup_workspace(second))
        self.assertNotEqual(first, second)
        self.assertTrue(first.is_dir())
        self.assertFalse(first.is_symlink())

    def test_symlink_archive_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real.zip"
            with zipfile.ZipFile(real, "w") as handle:
                handle.writestr("a.exe", b"hello")
            link = root / "link.zip"
            link.symlink_to(real)
            with self.assertRaises(ArchiveError):
                extract_archive(link, root / "out")

    def test_zip_slip_and_byte_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            slip = root / "slip.zip"
            with zipfile.ZipFile(slip, "w") as handle:
                handle.writestr("../outside.exe", b"bad")
            with self.assertRaises(ArchiveError):
                extract_archive(slip, root / "out")
            self.assertFalse((root / "outside.exe").exists())

            bomb = root / "bomb.zip"
            with zipfile.ZipFile(bomb, "w") as handle:
                handle.writestr("a.exe", b"x" * 50)
            with self.assertRaises(ArchiveError):
                extract_archive(bomb, root / "bomb-out", ExtractBudget(max_files=10, max_bytes=10))
            self.assertFalse((root / "bomb-out" / "a.exe").exists())

    def test_file_count_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "many.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("a.exe", b"a")
                handle.writestr("b.exe", b"b")
            with self.assertRaises(ArchiveError):
                extract_archive(archive, root / "out", ExtractBudget(max_files=1, max_bytes=1000))
            self.assertTrue((root / "out" / "a.exe").is_file())
            self.assertFalse((root / "out" / "b.exe").exists())

    def test_stored_member_and_ignore_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "stored.zip"
            payload = b"x" * 1200
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as handle:
                handle.writestr("a.exe", payload)
            info = zipfile.ZipFile(archive).infolist()[0]
            self.assertEqual(info.file_size, info.compress_size)

            extract_archive(archive, root / "ok", ExtractBudget(max_bytes=1200))
            self.assertEqual((root / "ok" / "a.exe").read_bytes(), payload)

            asked: list[str] = []
            with self.assertRaises(ArchiveError):
                extract_archive(
                    archive,
                    root / "stopped",
                    ExtractBudget(max_bytes=1199),
                    on_limit=lambda message: asked.append(message) or False,
                )
            self.assertFalse((root / "stopped" / "a.exe").exists())
            self.assertTrue(asked)
            self.assertIn("1199", asked[0])

            extract_archive(
                archive,
                root / "ignored",
                ExtractBudget(max_bytes=1199),
                on_limit=lambda _message: True,
            )
            self.assertEqual((root / "ignored" / "a.exe").read_bytes(), payload)

    def test_ignore_does_not_bypass_symlink_or_zip_slip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real.zip"
            with zipfile.ZipFile(real, "w") as handle:
                handle.writestr("a.exe", b"hello")
            link = root / "link.zip"
            link.symlink_to(real)
            asked: list[str] = []

            def allow(message: str) -> bool:
                asked.append(message)
                return True

            with self.assertRaises(ArchiveError) as caught:
                extract_archive(link, root / "out", on_limit=allow)
            self.assertIn("symlink", str(caught.exception).lower())

            slip = root / "slip.zip"
            with zipfile.ZipFile(slip, "w") as handle:
                handle.writestr("../outside.exe", b"bad")
            with self.assertRaises(ArchiveError):
                extract_archive(slip, root / "slip-out", on_limit=allow)
            self.assertFalse((root / "outside.exe").exists())
            self.assertEqual(asked, [])

    def test_shared_stem_and_7z_symlink_member(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "bundle"
            folder.mkdir()
            with zipfile.ZipFile(folder / "payload.zip", "w") as handle:
                handle.writestr("fromzip.exe", b"zip")
            source = root / "from7z.exe"
            source.write_bytes(b"seven")
            with py7zr.SevenZipFile(folder / "payload.7z", "w") as archive:
                archive.write(source, "from7z.exe")
            skipped = extract_nested(folder, lambda _line: None)
            self.assertEqual(skipped, [])
            self.assertEqual((folder / "payload.zip_extracted" / "fromzip.exe").read_bytes(), b"zip")
            self.assertEqual((folder / "payload.7z_extracted" / "from7z.exe").read_bytes(), b"seven")

            linked = root / "real.txt"
            linked.write_text("secret", encoding="utf-8")
            pointer = root / "link.dat"
            pointer.symlink_to(linked)
            packed = root / "links.7z"
            with py7zr.SevenZipFile(packed, "w") as archive:
                archive.write(pointer, "link.dat")
            with self.assertRaises(ArchiveError) as caught:
                extract_archive(packed, root / "links-out")
            self.assertIn("symlink member", str(caught.exception))


class IncompleteScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        set_checkpoint_path(root / "scan_checkpoint.json")
        self.addCleanup(lambda: set_checkpoint_path(None))
        clear_checkpoint()
        self.reports = root / "reports"
        self.reports.mkdir()

    def test_hash_failure_is_listed_and_is_not_a_clean_scan(self) -> None:
        folder = Path(self.tmp.name) / "payloads"
        folder.mkdir()
        (folder / "a.exe").write_bytes(b"alpha")

        def deny(*args, **kwargs):
            raise OSError("permission denied")

        with (
            patch("aegis.scan.sha256_file", deny),
            patch("aegis.report.desktop_dir", lambda: self.reports),
        ):
            result = run_scan(folder, _config(), lambda _line: None)
        self.assertIsNone(result.clean_message)
        self.assertTrue(result.errors)
        self.assertNotIn("0 threats", result.dialog_text())
        self.assertIn("could not hash", result.dialog_text())
        self.assertTrue(result.report_paths)
        report = result.report_paths[0].read_text(encoding="utf-8")
        self.assertIn("could not hash", report)
        self.assertIn("Scan incomplete", report)
        self.assertNotIn("0 threats", report)

    def test_skipped_archive_is_listed(self) -> None:
        folder = Path(self.tmp.name) / "bundle"
        folder.mkdir()
        (folder / "broken.zip").write_bytes(b"this is not a zip")
        with patch("aegis.report.desktop_dir", lambda: self.reports):
            result = run_scan(folder, _config(), lambda _line: None)
        self.assertIsNone(result.clean_message)
        self.assertTrue(any("Skipped archive broken.zip" in item for item in result.errors))
        self.assertNotIn("0 threats", result.dialog_text())
        report = result.report_paths[0].read_text(encoding="utf-8")
        self.assertIn("Skipped archive broken.zip", report)

    def test_virustotal_error_is_not_called_clean(self) -> None:
        folder = Path(self.tmp.name) / "payloads"
        folder.mkdir()
        (folder / "a.exe").write_bytes(b"alpha")
        logs: list[str] = []

        def fake_lookup(sha, config, limiter, log, file_path=None, file_index=0):
            return FileIntel(sha256=sha, vt_error="VirusTotal authentication failed (HTTP 401)")

        with (
            patch("aegis.scan.lookup_hash", fake_lookup),
            patch("aegis.report.desktop_dir", lambda: self.reports),
        ):
            result = run_scan(folder, _config(), logs.append)
        self.assertTrue(any("Unknown because of authentication failure" in line for line in logs))
        self.assertFalse(any("Clean/undetected" in line for line in logs))
        self.assertIn("Unknown because of authentication failure", result.dialog_text())
        html = render_html(result.target, result.scanned_at, result.evaluated, result.threats, result.errors)
        self.assertIn("Unknown because of authentication failure", html)
        self.assertNotIn("0 threats", html)

    def test_rate_limit_and_network_errors_name_the_reason(self) -> None:
        self.assertEqual(
            unknown_because("VirusTotal HTTP 429: quota"),
            "Unknown because of rate limit",
        )
        self.assertEqual(
            unknown_because("Hybrid Analysis request failed: connection timed out"),
            "Unknown because of network error",
        )
        self.assertEqual(
            unknown_because(
                "VirusTotal authentication failed (HTTP 401); Hybrid Analysis request failed: network down"
            ),
            "Unknown because of authentication failure; Unknown because of network error",
        )

    def test_failed_google_explanation_is_written_into_the_report(self) -> None:
        payload = PayloadFile(
            full_path=Path("a.exe"),
            display_name="a.exe",
            internal_path="a.exe",
            extension=".exe",
        )
        intel = FileIntel(sha256="abc", malicious=4, ai_error="HTTP 503")
        page = render_html(
            Path("sample"),
            datetime.now(),
            1,
            [ThreatRecord(payload, intel)],
        )
        self.assertIn("Google simplified explanation failed.", page)
        self.assertIn("Gamers' Summary", page)
        self.assertNotIn("HTTP 503", page)

    def test_ignore_extracts_an_archive_past_the_cap(self) -> None:
        archive = Path(self.tmp.name) / "stored.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as handle:
            handle.writestr("a.exe", b"alpha-payload")
        seen: list[str] = []

        def fake_lookup(sha, config, limiter, log, file_path=None, file_index=0):
            seen.append(file_path.name)
            return FileIntel(sha256=sha, vt_found=True)

        def tiny_budget(*_args, **_kwargs):
            return ExtractBudget(max_bytes=4)

        with (
            patch("aegis.scan.ExtractBudget", tiny_budget),
            patch("aegis.scan.lookup_hash", fake_lookup),
            patch("aegis.report.desktop_dir", lambda: self.reports),
        ):
            with self.assertRaises(ScanPaused):
                run_scan(archive, _config(), lambda _line: None, on_extract_limit=lambda _message: False)
            result = run_scan(archive, _config(), lambda _line: None, on_extract_limit=lambda _message: True)
        self.assertEqual(seen, ["a.exe"])
        self.assertEqual(result.evaluated, 1)
        self.assertTrue(result.clean_message)


if __name__ == "__main__":
    unittest.main()
