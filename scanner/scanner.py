#!/usr/bin/env python3
"""CLI entry point invoked by PHP. Thin wrapper around the plugin-based passive engine."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from engine.runner import run_passive_scan

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--allow-private", action="store_true", help="Lab use only")
    parser.add_argument("--log-file", default=None, help="JSONL request log path")
    parser.add_argument("--cancel-file", default=None, help="Presence of this file aborts the scan")
    args = parser.parse_args()
    try:
        result = run_passive_scan(
            args.url,
            allow_private=args.allow_private,
            cancel_file=args.cancel_file,
            log_file=args.log_file,
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result.get("ok") else 1
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False))
        return 1

if __name__ == "__main__":
    sys.exit(main())
