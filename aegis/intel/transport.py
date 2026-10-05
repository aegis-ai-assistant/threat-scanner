"""Failures that mean a file lookup did not finish and must be retried later."""

from __future__ import annotations

import requests


class LookupInterrupted(Exception):
    """Network or service failure. The current file is not saved as finished."""


def network_failure(service: str, exc: requests.RequestException) -> LookupInterrupted:
    return LookupInterrupted(f"{service} request failed: {exc}")


def incomplete_response(service: str, response: requests.Response) -> LookupInterrupted:
    snippet = (response.text or "")[:240].replace("\n", " ").strip()
    message = f"{service} HTTP {response.status_code}"
    if snippet:
        message = f"{message}: {snippet}"
    return LookupInterrupted(message)
