"""Clean-hash skip, interrupted scans, and AI-summary retry."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.checkpoint import clear_checkpoint, load_checkpoint, set_checkpoint_path
from aegis.config import AppConfig
from aegis.intel import FileIntel
from aegis.intel.lookup import known_clean_hash, lookup_hash
from aegis.intel.outcome import (
    ENGINE_HYBRID,
    ENGINE_VIRUSTOTAL,
    STATUS_UNKNOWN_HASH,
    VERDICT_CLEAN,
    EngineResult,
    classify_virustotal,
)
from aegis.intel.transport import LookupInterrupted
from aegis.rate_limit import RateLimiter
from aegis.scan import ScanPaused, complete_saved_ai, run_scan


def _config(**overrides) -> AppConfig:
    values = dict(
        virustotal_api_key="vt-test",
        hybrid_analysis_api_key="hybrid-test",
        metadefender_api_key="",
        google_api_key="",
        secondary_engine="hybrid_analysis",
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


class CleanHashTests(unittest.TestCase):
    def test_known_clean_hash_skips_every_later_service(self) -> None:
        calls: list[str] = []

        def fake_vt(sha256, api_key, limiter, log):
            calls.append("virustotal")
            intel = FileIntel(sha256=sha256, vt_found=True, malicious=0, suspicious=0, undetected=40)
            return EngineResult(ENGINE_VIRUSTOTAL, classify_virustotal(intel), intel)

        def fake_enrich(*args, **kwargs):
            calls.append("enrich")
            return args[0]

        def fake_hybrid(*args, **kwargs):
            calls.append("hybrid")
            intel = args[0]
            return EngineResult(ENGINE_HYBRID, VERDICT_CLEAN, intel)

        def fake_meta(*args, **kwargs):
            calls.append("metadefender")

        with (
            patch("aegis.intel.router.query_virustotal", fake_vt),
            patch("aegis.intel.router.enrich_virustotal", fake_enrich),
            patch("aegis.intel.router.query_hybrid_analysis", fake_hybrid),
            patch("aegis.intel.router.query_metadefender", fake_meta),
        ):
            intel = lookup_hash("a" * 64, _config(metadefender_api_key="md-test", secondary_engine="both"), RateLimiter(0, enabled=False), lambda _line: None, file_path=Path("sample.exe"))

        self.assertTrue(known_clean_hash(intel))
        self.assertEqual(calls, ["virustotal"])

    def test_unknown_hash_still_continues(self) -> None:
        calls: list[str] = []

        def fake_vt(sha256, api_key, limiter, log):
            calls.append("virustotal")
            intel = FileIntel(sha256=sha256, vt_found=False)
            return EngineResult(ENGINE_VIRUSTOTAL, STATUS_UNKNOWN_HASH, intel)

        def fake_enrich(intel, *args, **kwargs):
            calls.append("enrich")
            intel.vt_found = True
            intel.malicious = 3
            return intel

        def fake_hybrid(intel, *args, **kwargs):
            calls.append("hybrid")
            return EngineResult(ENGINE_HYBRID, STATUS_UNKNOWN_HASH, intel)

        with (
            patch("aegis.intel.router.query_virustotal", fake_vt),
            patch("aegis.intel.router.enrich_virustotal", fake_enrich),
            patch("aegis.intel.router.query_hybrid_analysis", fake_hybrid),
        ):
            lookup_hash(
                "b" * 64,
                _config(),
                RateLimiter(0, enabled=False),
                lambda _line: None,
                file_path=Path("sample.exe"),
            )

        self.assertEqual(calls, ["virustotal", "hybrid", "enrich"])


class ResumeTests(unittest.TestCase):
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

    def test_network_failure_resumes_at_the_unfinished_file(self) -> None:
        calls: list[str] = []

        def fake_lookup(sha, config, limiter, log, file_path=None, file_index=0):
            calls.append(file_path.name)
            if len(calls) == 2:
                raise LookupInterrupted("network down")
            return FileIntel(sha256=sha, vt_found=True, malicious=0, suspicious=0)

        with patch("aegis.scan.lookup_hash", fake_lookup):
            with self.assertRaises(ScanPaused):
                run_scan(self.folder, _config(), lambda _line: None)
            saved = load_checkpoint()
            self.assertIsNotNone(saved)
            assert saved is not None
            self.assertEqual(saved.phase, "scanning")
            self.assertEqual(saved.completed_count, 1)
            run_scan(self.folder, _config(), lambda _line: None, resume=True)

        self.assertEqual(calls, ["a.exe", "b.exe", "b.exe"])
        self.assertIsNone(load_checkpoint())

    def test_failed_ai_summary_can_be_retried_without_new_lookups(self) -> None:
        lookups: list[str] = []
        reports: list[object] = []

        def fake_lookup(sha, config, limiter, log, file_path=None, file_index=0):
            lookups.append(sha)
            return FileIntel(sha256=sha, vt_found=True, malicious=8, suspicious=1)

        def fake_fail(threats, api_key, model, limiter, log, on_record=None):
            for record in threats:
                record.intel.ai_error = "offline"
                if on_record:
                    on_record(record)

        def fake_ok(threats, api_key, model, limiter, log, on_record=None):
            for record in threats:
                record.intel.ai_synthesis = "Flagged by several engines."
                record.intel.ai_plain_what = "This file looks dangerous."
                record.intel.ai_plain_why = "Scanners recognized it."
                record.intel.ai_plain_bottom = "Do not open it."
                record.intel.ai_error = None
                if on_record:
                    on_record(record)

        def fake_write(*args, **kwargs):
            reports.append(args)
            return [Path(self.tmp.name) / "report.html"]

        config = _config(google_api_key="google-test")
        single = self.folder / "a.exe"
        with (
            patch("aegis.scan.lookup_hash", fake_lookup),
            patch("aegis.intel.gemini.synthesize_threats", fake_fail),
            patch("aegis.scan.write_reports", fake_write),
        ):
            first = run_scan(single, config, lambda _line: None)
        self.assertTrue(first.ai_pending)
        self.assertEqual(first.report_paths, [])
        saved = load_checkpoint()
        self.assertIsNotNone(saved)
        assert saved is not None
        self.assertEqual(saved.phase, "ai_pending")
        self.assertEqual(len(lookups), 1)

        with (
            patch("aegis.scan.lookup_hash", fake_lookup),
            patch("aegis.intel.gemini.synthesize_threats", fake_ok),
            patch("aegis.scan.write_reports", fake_write),
        ):
            second = complete_saved_ai(config, lambda _line: None)

        self.assertFalse(second.ai_pending)
        self.assertEqual(len(reports), 1)
        self.assertEqual(len(lookups), 1)
        self.assertTrue(second.threats[0].intel.ai_summary_ready)
        self.assertIsNone(load_checkpoint())


if __name__ == "__main__":
    unittest.main()
