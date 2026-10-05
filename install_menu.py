#!/usr/bin/env python3
"""Standalone helper to add or remove the Explorer context menu."""

from __future__ import annotations

import argparse
import sys

from aegis.context_menu import ContextMenuError, install_context_menu, uninstall_context_menu


def main() -> int:
    parser = argparse.ArgumentParser(description="Install or remove the ThreatScanner Explorer menu.")
    parser.add_argument("--uninstall", action="store_true", help="Remove the context menu keys")
    args = parser.parse_args()
    try:
        if args.uninstall:
            uninstall_context_menu()
            print("Removed ThreatScanner context menu keys from HKCU.")
        else:
            command = install_context_menu()
            print("Registered context menu: Scan Payload with ThreatScanner")
            print(f"Command: {command}")
    except ContextMenuError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
