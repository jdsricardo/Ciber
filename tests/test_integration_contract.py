"""Producer-side conformance tests for docs/INTEGRATION_CONTRACT.md.

These run the engine exactly as the web application does — as a child process of
`scanner/scanner.py`, reading only its standard output — against the laboratory target of the
system tests, and check every rule of the contract that the producer is responsible for: framing,
exit codes, field types, enumerations, column limits and the meaning of `duration_ms`.

The captured sample payload in tests/fixtures/ is validated with the same checker, and the PHP
suite reads that same file, so a change on one side of the boundary that the other side does
not expect breaks a test instead of a production analysis.

    python tests/test_integration_contract.py --regenerate-fixture   # after a contract change
"""
from __future__ import annotations

import json
import pathlib
import socket
import subprocess
import sys
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tests" / "e2e"))

import lab_target  # noqa: E402  (laboratory target shared with the system tests)
from support.local_server import serve  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "scan_result.sample.json"

SEVERITIES = {"critical", "high", "medium", "low"}
STATUSES = {"confirmed", "high_confidence", "probable", "possible", "informational", "manual_review_required"}
# Column widths from database.sql (contract §3.2).
LIMITS = {
    "fingerprint": 120, "title": 180, "category": 80, "cwe": 120, "owasp": 120, "wstg": 120,
    "status": 30, "affected_url": 2048, "method": 10, "parameter": 180, "parameter_location": 40,
    "evidence_summary": 500, "remediation_example_language": 60, "remediation_example_note": 500,
}
REQUIRED_STRINGS = (
    "fingerprint", "title", "category", "cwe", "owasp", "wstg", "severity", "status", "affected_url",
    "method", "description", "evidence_summary", "developer_impact", "remediation",
)
EVIDENCE_KEYS = {"reason", "baseline", "probe_request", "probe_response", "differences", "verification_count"}
EVIDENCE_MAX_BYTES = 65_535


def contract_violations(document: dict) -> list[str]:
    """Every way `document` breaks the response rules of the contract (empty when it conforms)."""
    problems: list[str] = []
    if document.get("ok") is not True:
        if document.get("ok") is False and isinstance(document.get("error"), str) and document["error"].strip():
            return []
        return ["a document must be ok:true, or ok:false with a non-empty error"]

    for field, kind in (("status_code", int), ("duration_ms", int), ("checks_run", int),
                        ("plugins_run", int), ("requests_made", int), ("pages_scanned", int),
                        ("crawled_urls", list), ("findings", list), ("scanned_at", str)):
        if not isinstance(document.get(field), kind):
            problems.append(f"{field} must be {kind.__name__}")
    if isinstance(document.get("duration_ms"), int) and document["duration_ms"] < 0:
        problems.append("duration_ms must not be negative")

    for index, finding in enumerate(document.get("findings") or []):
        where = f"findings[{index}] ({finding.get('fingerprint')})"
        for field in REQUIRED_STRINGS:
            if not isinstance(finding.get(field), str) or not finding[field].strip():
                problems.append(f"{where}.{field} must be a non-empty string")
        if finding.get("severity") not in SEVERITIES:
            problems.append(f"{where}.severity {finding.get('severity')!r} is not in {sorted(SEVERITIES)}")
        if finding.get("status") not in STATUSES:
            problems.append(f"{where}.status {finding.get('status')!r} is not a known status")
        confidence = finding.get("confidence")
        if not isinstance(confidence, int) or not 0 <= confidence <= 100:
            problems.append(f"{where}.confidence must be an int in 0..100")
        if not isinstance(finding.get("manual_review_required"), bool):
            problems.append(f"{where}.manual_review_required must be bool")
        if finding.get("parameter_location") not in (None, "query", "form", "cookie"):
            problems.append(f"{where}.parameter_location must be query, form, cookie or null")
        for field, limit in LIMITS.items():
            value = finding.get(field)
            if isinstance(value, str) and len(value) > limit:
                problems.append(f"{where}.{field} has {len(value)} characters; the column holds {limit}")
        evidence = finding.get("evidence")
        if not isinstance(evidence, dict) or not EVIDENCE_KEYS <= set(evidence):
            problems.append(f"{where}.evidence must be an object with {sorted(EVIDENCE_KEYS)}")
        elif len(json.dumps(evidence).encode("utf-8")) > EVIDENCE_MAX_BYTES:
            problems.append(f"{where}.evidence exceeds {EVIDENCE_MAX_BYTES} bytes when serialized")
    return problems


def run_cli(*args: str, timeout: float = 300) -> tuple[int, str, str]:
    """Invoke the engine the way the consumer does and return (exit code, stdout, stderr)."""
    process = subprocess.run(
        [sys.executable, str(ROOT / "scanner" / "scanner.py"), *args],
        capture_output=True, timeout=timeout,
    )
    return process.returncode, process.stdout.decode("utf-8"), process.stderr.decode("utf-8", "replace")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class LabVariant:
    """Runs the laboratory target in-process with a given variant and per-response delay."""

    def __init__(self, variant: str, delay: float = 0.0) -> None:
        self.settings = {"variant": variant, "delay": delay, "log": None}

    def __enter__(self) -> str:
        self.previous = dict(lab_target.CONFIG)
        lab_target.CONFIG.update(self.settings)
        self.context = serve(lab_target.LabHandler)
        return self.context.__enter__() + "/"

    def __exit__(self, *exc) -> None:
        self.context.__exit__(*exc)
        lab_target.CONFIG.clear()
        lab_target.CONFIG.update(self.previous)


class ProducerConformanceTests(unittest.TestCase):
    def assertConforms(self, document: dict) -> None:
        problems = contract_violations(document)
        self.assertEqual([], problems, "contract violations:\n  " + "\n  ".join(problems))

    def test_success_is_one_json_document_with_exit_code_zero(self):
        with LabVariant("vulnerable") as url:
            code, out, _ = run_cli(url, "--mode=passive", "--allow-private")
        self.assertEqual(0, code)
        document = json.loads(out)  # the whole stdout is the document (§1 framing)
        self.assertTrue(document["ok"])
        self.assertEqual(34, document["checks_run"])
        self.assertConforms(document)

    def test_active_document_conforms(self):
        with LabVariant("vulnerable") as url:
            code, out, _ = run_cli(url, "--mode=safe_active", "--allow-private")
        self.assertEqual(0, code)
        document = json.loads(out)
        self.assertEqual(64, document["checks_run"])
        self.assertConforms(document)

    def test_failure_is_ok_false_with_reason_and_exit_code_one(self):
        code, out, _ = run_cli(f"http://127.0.0.1:{free_port()}/", "--mode=passive", "--allow-private")
        self.assertEqual(1, code)
        document = json.loads(out)
        self.assertIs(False, document["ok"])
        self.assertTrue(document["error"].strip())

    def test_private_target_without_permission_is_refused(self):
        code, out, _ = run_cli("http://127.0.0.1:1/", "--mode=passive")
        self.assertEqual(1, code)
        self.assertIs(False, json.loads(out)["ok"])

    def test_duration_is_the_wall_clock_of_the_whole_scan(self):
        # 5 pages x 2 baseline requests, each answered after 0.2 s: the scan cannot take less
        # than ~2 s, so a duration below that is not the duration of the scan (§3.1).
        with LabVariant("vulnerable", delay=0.2) as url:
            started = time.monotonic()
            code, out, _ = run_cli(url, "--mode=passive", "--allow-private")
            elapsed_ms = (time.monotonic() - started) * 1000
        document = json.loads(out)
        self.assertEqual(0, code)
        self.assertGreaterEqual(document["duration_ms"], 2000)
        self.assertLessEqual(document["duration_ms"], elapsed_ms)

    def test_values_longer_than_a_column_respect_its_limit(self):
        # The edge variant has a form field whose name is 300 characters long (§3.2: 180).
        with LabVariant("edge") as url:
            code, out, _ = run_cli(url, "--mode=safe_active", "--allow-private")
        document = json.loads(out)
        self.assertEqual(0, code)
        self.assertTrue(any(f.get("parameter_location") == "form" for f in document["findings"]),
                        "the long form field should have been probed and reported")
        self.assertConforms(document)

    def test_shared_sample_payload_conforms(self):
        document = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertConforms(document)
        self.assertTrue(document["findings"], "the sample must carry findings for the PHP side to read")


def regenerate_fixture() -> None:
    with LabVariant("vulnerable") as url:
        code, out, err = run_cli(url, "--mode=safe_active", "--allow-private")
    if code != 0:
        raise SystemExit(f"engine failed: {out or err}")
    document = json.loads(out)
    # Make the sample independent of the random port of this run.
    text = json.dumps(document, ensure_ascii=False, indent=2).replace(url.rstrip("/"), "http://lab.example.test")
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(text + "\n", encoding="utf-8")
    print(f"wrote {FIXTURE.relative_to(ROOT)} ({len(document['findings'])} findings)")


if __name__ == "__main__":
    if "--regenerate-fixture" in sys.argv:
        regenerate_fixture()
    else:
        unittest.main()
