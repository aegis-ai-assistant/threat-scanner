"""Round-robin lookups stop on a conclusive verdict and keep API errors incomplete."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.checkpoint import clear_checkpoint, set_checkpoint_path
from aegis.config import AppConfig
from aegis.intel import FileIntel
from aegis.intel.outcome import (
    ENGINE_HYBRID,
    ENGINE_VIRUSTOTAL,
    STATUS_API_ERROR,
    STATUS_UNKNOWN_HASH,
    VERDICT_CLEAN,
    VERDICT_MALICIOUS,
    EngineResult,
    classify_virustotal,
)
from aegis.intel.router import lookup_hash
from aegis.rate_limit import RateLimiter
from aegis.scan import run_scan


def _config(**overrides) -> AppConfig:
    values = dict(
        virustotal_api_key="vt-test",
        hybrid_analysis_api_key="hybrid-test",
        metadefender_api_key="",
        google_api_key="",
        secondary_engine="hybrid_analysis",
        free_tier=False,
        request_delay_seconds=0,
        vt_auto_upload=False,
        vt_sandbox=True,
        vt_analysis_timeout_seconds=1,
        google_model="gemini-3.7-flash",
        report_format="html",
        open_report=False,
        config_path=Path("config.json"),
    )
    values.update(overrides)
    return AppConfig(**values)


def _vt(status: str, **fields) -> EngineResult:
    intel = FileIntel(sha256=fields.pop("sha256", "a" * 64), **fields)
    return EngineResult(ENGINE_VIRUSTOTAL, status, intel)


def _hybrid(status: str, intel: FileIntel, **fields) -> EngineResult:
    for name, value in fields.items():
        setattr(intel, name, value)
    return EngineResult(ENGINE_HYBRID, status, intel, intel.hybrid_error or intel.hybrid_verdict or "")


class RouterTests(unittest.TestCase):
    def _run(self, vt_status, hybrid_status, file_index=0, **config):
        calls: list[str] = []

        def fake_vt(sha256, api_key, limiter, log):
            calls.append("virustotal")
            if vt_status == VERDICT_MALICIOUS:
                return _vt(vt_status, sha256=sha256, vt_found=True, malicious=4)
            if vt_status == VERDICT_CLEAN:
                return _vt(vt_status, sha256=sha256, vt_found=True, undetected=12)
            if vt_status == STATUS_API_ERROR:
                return _vt(vt_status, sha256=sha256, vt_error="VirusTotal HTTP 500")
            return _vt(STATUS_UNKNOWN_HASH, sha256=sha256, vt_found=False)

        def fake_hybrid(intel, api_key, limiter, log):
            calls.append("hybrid")
            if hybrid_status == VERDICT_MALICIOUS:
                return _hybrid(hybrid_status, intel, hybrid_verdict="malicious")
            if hybrid_status == VERDICT_CLEAN:
                return _hybrid(hybrid_status, intel, hybrid_verdict="no specific threat")
            if hybrid_status == STATUS_API_ERROR:
                return _hybrid(hybrid_status, intel, hybrid_error="Hybrid Analysis HTTP 401")
            return _hybrid(STATUS_UNKNOWN_HASH, intel)

        def fake_enrich(intel, *args, **kwargs):
            calls.append("upload")
            intel.vt_uploaded = True
            return intel

        with (
            patch("aegis.intel.router.query_virustotal", fake_vt),
            patch("aegis.intel.router.query_hybrid_analysis", fake_hybrid),
            patch("aegis.intel.router.enrich_virustotal", fake_enrich),
        ):
            intel = lookup_hash(
                "a" * 64,
                _config(**config),
                RateLimiter(0, enabled=False),
                lambda _line: None,
                file_path=Path("sample.exe"),
                file_index=file_index,
            )
        return calls, intel

    def test_even_files_start_on_virustotal_and_stop_when_clean(self) -> None:
        calls, intel = self._run(VERDICT_CLEAN, VERDICT_MALICIOUS, file_index=0)
        self.assertEqual(calls, ["virustotal"])
        self.assertFalse(intel.is_threat)
        self.assertIsNone(intel.service_error)

    def test_odd_files_start_on_hybrid_and_stop_when_malicious(self) -> None:
        calls, intel = self._run(VERDICT_CLEAN, VERDICT_MALICIOUS, file_index=1)
        self.assertEqual(calls, ["hybrid"])
        self.assertTrue(intel.is_threat)

    def test_unknown_primary_asks_the_other_engine(self) -> None:
        calls, intel = self._run(STATUS_UNKNOWN_HASH, VERDICT_CLEAN, file_index=0)
        self.assertEqual(calls, ["virustotal", "hybrid"])
        self.assertFalse(intel.is_threat)
        self.assertFalse(intel.vt_uploaded)

    def test_malicious_secondary_overrides_an_unknown_primary(self) -> None:
        calls, intel = self._run(STATUS_UNKNOWN_HASH, VERDICT_MALICIOUS, file_index=0)
        self.assertEqual(calls, ["virustotal", "hybrid"])
        self.assertTrue(intel.is_threat)
        self.assertFalse(intel.vt_uploaded)

    def test_upload_only_after_both_engines_miss_the_hash(self) -> None:
        calls, intel = self._run(
            STATUS_UNKNOWN_HASH,
            STATUS_UNKNOWN_HASH,
            vt_auto_upload=True,
        )
        self.assertEqual(calls, ["virustotal", "hybrid", "upload"])
        self.assertTrue(intel.vt_uploaded)

    def test_unseen_hash_is_sent_for_a_sandbox_test(self) -> None:
        calls, intel = self._run(STATUS_UNKNOWN_HASH, STATUS_UNKNOWN_HASH, vt_auto_upload=False)
        self.assertEqual(calls, ["virustotal", "hybrid", "upload"])
        self.assertTrue(intel.hash_unseen)
        self.assertTrue(intel.vt_uploaded)
        self.assertFalse(intel.is_threat)

    def test_upload_stays_off_when_sandbox_follow_up_is_off(self) -> None:
        calls, intel = self._run(
            STATUS_UNKNOWN_HASH,
            STATUS_UNKNOWN_HASH,
            vt_auto_upload=False,
            vt_sandbox=False,
        )
        self.assertEqual(calls, ["virustotal", "hybrid"])
        self.assertFalse(intel.vt_uploaded)
        self.assertFalse(intel.hash_unseen)

    def test_unseen_sandbox_virus_is_a_threat(self) -> None:
        calls: list[str] = []

        def fake_vt(sha256, api_key, limiter, log):
            calls.append("virustotal")
            return _vt(STATUS_UNKNOWN_HASH, sha256=sha256, vt_found=False)

        def fake_hybrid(intel, api_key, limiter, log):
            calls.append("hybrid")
            return _hybrid(STATUS_UNKNOWN_HASH, intel)

        def fake_enrich(intel, *args, **kwargs):
            calls.append("upload")
            intel.vt_uploaded = True
            intel.vt_found = True
            intel.hash_unseen = True
            intel.sandbox_verdict = "malicious"
            intel.sandbox_family = "MALWARE"
            return intel

        with (
            patch("aegis.intel.router.query_virustotal", fake_vt),
            patch("aegis.intel.router.query_hybrid_analysis", fake_hybrid),
            patch("aegis.intel.router.enrich_virustotal", fake_enrich),
        ):
            intel = lookup_hash(
                "c" * 64,
                _config(vt_auto_upload=False, vt_sandbox=True),
                RateLimiter(0, enabled=False),
                lambda _line: None,
                file_path=Path("sample.exe"),
            )
        self.assertEqual(calls, ["virustotal", "hybrid", "upload"])
        self.assertTrue(intel.hash_unseen)
        self.assertTrue(intel.is_threat)
        self.assertEqual(intel.threat_level, "MEDIUM")

    def test_api_error_falls_back_and_blocks_upload_and_clean(self) -> None:
        calls, intel = self._run(
            STATUS_API_ERROR,
            STATUS_UNKNOWN_HASH,
            vt_auto_upload=True,
        )
        self.assertEqual(calls, ["virustotal", "hybrid"])
        self.assertIn("HTTP 500", intel.service_error or "")
        self.assertFalse(intel.vt_uploaded)
        self.assertFalse(intel.is_threat)

    def test_secondary_clean_does_not_erase_a_primary_api_error(self) -> None:
        calls, intel = self._run(STATUS_API_ERROR, VERDICT_CLEAN, vt_auto_upload=True)
        self.assertEqual(calls, ["virustotal", "hybrid"])
        self.assertIsNotNone(intel.service_error)
        self.assertFalse(intel.is_threat)
        self.assertFalse(intel.vt_uploaded)

    def test_zero_detections_skip_the_other_engine_and_stay_clean(self) -> None:
        calls: list[str] = []

        def fake_vt(sha256, api_key, limiter, log):
            calls.append("virustotal")
            intel = FileIntel(
                sha256=sha256,
                vt_found=True,
                malicious=0,
                suspicious=0,
                undetected=71,
                sandbox_verdict="malicious",
            )
            return EngineResult(ENGINE_VIRUSTOTAL, classify_virustotal(intel), intel)

        def fake_hybrid(*args, **kwargs):
            calls.append("hybrid")
            raise AssertionError("secondary engine should not run")

        def fake_enrich(*args, **kwargs):
            raise AssertionError("upload")

        with (
            patch("aegis.intel.router.query_virustotal", fake_vt),
            patch("aegis.intel.router.query_hybrid_analysis", fake_hybrid),
            patch("aegis.intel.router.enrich_virustotal", fake_enrich),
        ):
            intel = lookup_hash(
                "b" * 64,
                _config(vt_auto_upload=True),
                RateLimiter(0, enabled=False),
                lambda _line: None,
                file_index=0,
            )
        self.assertEqual(calls, ["virustotal"])
        self.assertFalse(intel.is_threat)
        self.assertEqual(classify_virustotal(intel), VERDICT_CLEAN)


class ScanRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        set_checkpoint_path(root / "scan_checkpoint.json")
        self.addCleanup(lambda: set_checkpoint_path(None))
        clear_checkpoint()
        self.folder = root / "payloads"
        self.folder.mkdir()
        (self.folder / "a.exe").write_bytes(b"alpha")
        (self.folder / "b.exe").write_bytes(b"bravo")
        self.reports = root / "reports"
        self.reports.mkdir()

    def test_scan_alternates_the_file_index(self) -> None:
        seen: list[int] = []

        def fake_lookup(sha, config, limiter, log, file_path=None, file_index=0):
            seen.append(file_index)
            return FileIntel(sha256=sha, vt_found=True, undetected=3)

        with patch("aegis.scan.lookup_hash", fake_lookup):
            result = run_scan(self.folder, _config(), lambda _line: None)
        self.assertEqual(seen, [0, 1])
        self.assertIsNotNone(result.clean_message)

    def test_hybrid_api_error_is_an_incomplete_scan(self) -> None:
        def fake_lookup(sha, config, limiter, log, file_path=None, file_index=0):
            return FileIntel(sha256=sha, hybrid_error="Hybrid Analysis HTTP 503")

        with (
            patch("aegis.scan.lookup_hash", fake_lookup),
            patch("aegis.report.desktop_dir", lambda: self.reports),
        ):
            result = run_scan(self.folder / "a.exe", _config(), lambda _line: None)
        self.assertIsNone(result.clean_message)
        self.assertNotIn("0 threats", result.dialog_text())
        self.assertIn("Unknown because of a service error", result.dialog_text())
        report = result.report_paths[0].read_text(encoding="utf-8")
        self.assertIn("Unknown because of a service error", report)
        self.assertIn("Scan incomplete", report)


if __name__ == "__main__":
    unittest.main()
