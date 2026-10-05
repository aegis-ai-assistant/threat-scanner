"""Static scanner configuration: payload extensions, vendors, branding."""

from __future__ import annotations

APP_NAME = "Aegis Threat Scanner"
APP_VERSION = "1.0.0"
REPORT_TITLE = "AEGIS THREAT ANALYSIS REPORT"
CONTEXT_MENU_LABEL = "Scan Payload with ThreatScanner"
CONTEXT_MENU_KEY = "ThreatScanner"
WORKSPACE_DIRNAME = "threat_scan_workspace"
USER_AGENT = f"AegisThreatScanner/{APP_VERSION}"
HYBRID_USER_AGENT = "Falcon Sandbox"
GEMINI_PRIMARY_MODEL = "gemini-3.7-flash"
GEMINI_FALLBACK_MODEL = "gemini-3.6-flash"
DEPRECATED_GEMINI_MODELS = frozenset(
    {
        "gemini-1.5-flash",
        "gemini-1.5-pro",
        "gemini-2.0-flash",
        "gemini-2.0-flash-001",
        "gemini-2.5-flash",
        "gemini-2.5-pro",
    }
)

# Potential execution / payload vectors to hash and query.
PAYLOAD_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jse",
        ".wsf",
        ".hta",
        ".scr",
        ".pif",
        ".msi",
        ".com",
        ".reg",
        ".iso",
        ".img",
        ".lnk",
        ".chm",
        ".cpl",
        ".docm",
        ".xlsm",
    }
)

ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({".zip", ".rar", ".7z"})
TAR_GZ_SUFFIXES: tuple[str, ...] = (".tar.gz", ".tgz")

MAX_ARCHIVE_DEPTH = 4

# Preferred AV vendors to surface first in the report breakdown.
PRIORITY_VENDORS: tuple[str, ...] = (
    "CrowdStrike",
    "Kaspersky",
    "Microsoft",
    "BitDefender",
    "ESET-NOD32",
    "Malwarebytes",
    "Sophos",
    "TrendMicro",
    "Symantec",
    "F-Secure",
    "Avast",
    "AVG",
    "GData",
    "Paloalto",
    "Fortinet",
    "McAfee",
    "Ikarus",
    "ZoneAlarm",
)

VT_GUI_FILE = "https://www.virustotal.com/gui/file/"
VT_API_FILE = "https://www.virustotal.com/api/v3/files/"
VT_API_ANALYSES = "https://www.virustotal.com/api/v3/analyses/"
VT_MAX_UPLOAD_BYTES = 32 * 1024 * 1024
HYBRID_SEARCH_HASH = "https://www.hybrid-analysis.com/api/v2/search/hash"
HYBRID_OVERVIEW = "https://www.hybrid-analysis.com/api/v2/overview/"
GEMINI_GENERATE = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
HYBRID_GUI_SAMPLE = "https://www.hybrid-analysis.com/sample/"
METADEFENDER_HASH = "https://api.metadefender.com/v4/hash/"
METADEFENDER_GUI = "https://metadefender.opswat.com/results/hash/"
