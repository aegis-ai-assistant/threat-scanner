"""Load API keys and scanner options from config.json beside the app."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from aegis.paths import application_dir, bundled_resource

VALID_SECONDARY = {"hybrid_analysis", "metadefender", "both", "none"}
VALID_REPORT = {"html", "rtf", "both"}


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class AppConfig:
    virustotal_api_key: str
    hybrid_analysis_api_key: str
    metadefender_api_key: str
    google_api_key: str
    secondary_engine: str
    free_tier: bool
    request_delay_seconds: float
    vt_auto_upload: bool
    vt_sandbox: bool
    vt_analysis_timeout_seconds: float
    google_model: str
    report_format: str
    open_report: bool
    config_path: Path

    @property
    def has_virustotal(self) -> bool:
        return _key_present(self.virustotal_api_key)

    @property
    def has_hybrid(self) -> bool:
        return _key_present(self.hybrid_analysis_api_key)

    @property
    def has_metadefender(self) -> bool:
        return _key_present(self.metadefender_api_key)

    @property
    def has_google(self) -> bool:
        return _key_present(self.google_api_key)

    def query_hybrid(self) -> bool:
        if not self.has_hybrid:
            return False
        return self.secondary_engine in {"hybrid_analysis", "both"}

    def query_metadefender(self) -> bool:
        if not self.has_metadefender:
            return False
        return self.secondary_engine in {"metadefender", "both"}


def _clean_key(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _key_present(value: str) -> bool:
    if not value:
        return False
    upper = value.upper()
    return not upper.startswith("YOUR_") and "YOUR_" not in upper and value not in {"changeme", "placeholder"}


def _normalize_google_model(value: str) -> str:
    from aegis.constants import DEPRECATED_GEMINI_MODELS, GEMINI_PRIMARY_MODEL

    model = value or GEMINI_PRIMARY_MODEL
    if model in DEPRECATED_GEMINI_MODELS:
        return GEMINI_PRIMARY_MODEL
    return model


def load_config(explicit: Path | None = None) -> AppConfig:
    path = explicit or (application_dir() / "config.json")
    if not path.is_file():
        example = application_dir() / "config.example.json"
        bundled = bundled_resource("config.example.json")
        if bundled is not None and not example.is_file():
            try:
                example.write_bytes(bundled.read_bytes())
            except OSError:
                example = bundled
        raise ConfigError(
            f"Missing {path}. Copy config.example.json to config.json and add your API keys."
            + (f" Example is at {example}." if example.is_file() else "")
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a JSON object.")

    secondary = str(raw.get("secondary_engine", "hybrid_analysis")).strip().lower()
    if secondary not in VALID_SECONDARY:
        raise ConfigError(
            f"secondary_engine must be one of {sorted(VALID_SECONDARY)}, got {secondary!r}."
        )
    report_format = str(raw.get("report_format", "both")).strip().lower()
    if report_format not in VALID_REPORT:
        raise ConfigError(f"report_format must be one of {sorted(VALID_REPORT)}, got {report_format!r}.")

    delay = float(raw.get("request_delay_seconds", 15))
    if delay < 0:
        raise ConfigError("request_delay_seconds cannot be negative.")

    cfg = AppConfig(
        virustotal_api_key=_clean_key(raw.get("virustotal_api_key")),
        hybrid_analysis_api_key=_clean_key(raw.get("hybrid_analysis_api_key")),
        metadefender_api_key=_clean_key(raw.get("metadefender_api_key")),
        google_api_key=_clean_key(raw.get("google_api_key")),
        secondary_engine=secondary,
        free_tier=bool(raw.get("free_tier", True)),
        request_delay_seconds=delay,
        vt_auto_upload=bool(raw.get("vt_auto_upload", False)),
        vt_sandbox=bool(raw.get("vt_sandbox", True)),
        vt_analysis_timeout_seconds=max(0.0, float(raw.get("vt_analysis_timeout_seconds", 90))),
        google_model=_normalize_google_model(_clean_key(raw.get("google_model"))),
        report_format=report_format,
        open_report=bool(raw.get("open_report", True)),
        config_path=path,
    )
    if not cfg.has_virustotal:
        raise ConfigError(
            "A VirusTotal API key is required in config.json (virustotal_api_key). "
            "Get one at https://www.virustotal.com/gui/my-apikey"
        )
    return cfg
