#!/usr/bin/env python3
"""CLI entry point invoked by PHP. Thin wrapper around the plugin-based passive engine."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from engine.runner import run_scan

# Finding text is authored in Portuguese. PHP reads this process's stdout as UTF-8 (via
# json_decode), but on Windows, stdout defaults to the console's ANSI code page once it is
# redirected to a pipe, silently mangling accented characters into invalid UTF-8. Force UTF-8
# regardless of platform or how the process is invoked.
for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8")

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--mode", default="passive", choices=["passive", "safe_active"], help="passive: header/config observation only. safe_active: also probes discovered parameters (SQLi, XSS, etc.)")
    parser.add_argument("--allow-private", action="store_true", help="Lab use only")
    parser.add_argument("--log-file", default=None, help="JSONL request log path")
    parser.add_argument("--cancel-file", default=None, help="Presence of this file aborts the scan")
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Header sent on every request (repeatable); e.g. authenticated scanning")
    parser.add_argument("--cookie", default=None, help="Shortcut for --header 'Cookie: ...' (authenticated scanning)")
    parser.add_argument("--max-pages", type=int, default=None,
                        help="Override how many distinct same-origin pages the crawl visits")
    parser.add_argument("--max-depth", type=int, default=None,
                        help="Override how far (links followed) the crawl travels from the seed URL")
    args = parser.parse_args()

    # Build the auth-header map from --cookie and any --header NAME: VALUE pairs. Only ever sent
    # to the pinned, authorized host and redacted in logs.
    auth_headers: dict[str, str] = {}
    if args.cookie:
        auth_headers["Cookie"] = args.cookie
    for raw in args.header:
        if ":" in raw:
            name, value = raw.split(":", 1)
            if name.strip():
                auth_headers[name.strip()] = value.strip()

    try:
        result = run_scan(
            args.url,
            mode=args.mode,
            allow_private=args.allow_private,
            cancel_file=args.cancel_file,
            log_file=args.log_file,
            auth_headers=auth_headers,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result.get("ok") else 1
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False))
        return 1

if __name__ == "__main__":
    sys.exit(main())
