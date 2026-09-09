"""Tests for the empirical evaluation harness (evaluation/evaluate.py).

Metric arithmetic is verified deterministically by stubbing run_scan, so no network
or laboratory target is required. Also covers the authorization guard and the
network-failure-counts-as-miss behavior.
"""
import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scanner"))

# Load evaluation/evaluate.py as a module (it lives outside the package tree).
_spec = importlib.util.spec_from_file_location("evaluate", ROOT / "evaluation" / "evaluate.py")
evaluate_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evaluate_mod)


def _stub_scan(mapping):
    """Return a run_scan replacement that yields findings for the given url->fingerprints map."""
    def _run(url, mode="safe_active", allow_private=False):
        if url not in mapping:
            return {"ok": False, "error": "alvo desconhecido"}
        return {
            "ok": True,
            "findings": [{"fingerprint": fp} for fp in mapping[url]],
            "requests_made": 3,
            "duration_ms": 42,
        }
    return _run


class MetricTests(unittest.TestCase):
    def test_family_of(self):
        self.assertEqual(evaluate_mod.family_of("sqli.boolean_differential"), "sqli")
        self.assertEqual(evaluate_mod.family_of("headers"), "headers")

    def test_prf(self):
        self.assertEqual(evaluate_mod._prf(0, 0, 0), (0.0, 0.0, 0.0))
        p, r, f1 = evaluate_mod._prf(1, 1, 1)  # tp=1, fp=1, fn=1
        self.assertAlmostEqual(p, 0.5)
        self.assertAlmostEqual(r, 0.5)
        self.assertAlmostEqual(f1, 0.5)
        p, r, f1 = evaluate_mod._prf(2, 0, 0)
        self.assertEqual((p, r, f1), (1.0, 1.0, 1.0))

    def test_evaluate_counts_tp_fp_fn(self):
        data = {
            "authorized": True,
            "scope_families": ["sqli", "xss", "cors"],
            "targets": [
                # detects sqli (TP) but misses expected xss (FN)
                {"name": "t1", "url": "http://lab/sqli", "expected_families": ["sqli", "xss"]},
                # hardened control: detects a cors issue that is NOT expected -> FP
                {"name": "t2", "url": "http://lab/safe", "expected_families": []},
            ],
        }
        mapping = {
            "http://lab/sqli": ["sqli.error_based", "headers.csp_missing"],  # headers is out of scope, ignored
            "http://lab/safe": ["cors.origin_reflected"],
        }
        original = evaluate_mod.run_scan
        evaluate_mod.run_scan = _stub_scan(mapping)
        try:
            result = evaluate_mod.evaluate(data, allow_private=True)
        finally:
            evaluate_mod.run_scan = original

        counts = result["counts"]
        self.assertEqual(counts["sqli"], {"tp": 1, "fp": 0, "fn": 0})
        self.assertEqual(counts["xss"], {"tp": 0, "fp": 0, "fn": 1})
        self.assertEqual(counts["cors"], {"tp": 0, "fp": 1, "fn": 0})
        # out-of-scope 'headers' detection must not appear at all
        self.assertNotIn("headers", counts)

    def test_failed_scan_counts_expected_as_missed(self):
        data = {
            "authorized": True,
            "scope_families": ["sqli"],
            "targets": [{"name": "dead", "url": "http://unreachable", "expected_families": ["sqli"]}],
        }
        original = evaluate_mod.run_scan
        evaluate_mod.run_scan = _stub_scan({})  # url not in map -> ok:false
        try:
            result = evaluate_mod.evaluate(data, allow_private=True)
        finally:
            evaluate_mod.run_scan = original
        self.assertEqual(result["counts"]["sqli"], {"tp": 0, "fp": 0, "fn": 1})
        self.assertIn("error", result["per_target"][0])

    def test_authorization_guard_rejects_unauthorized(self):
        import json
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            json.dump({"authorized": False, "targets": [{"url": "x"}]}, handle)
            path = pathlib.Path(handle.name)
        with self.assertRaises(SystemExit):
            evaluate_mod.load_ground_truth(path)
        path.unlink()

    def test_render_markdown_produces_table(self):
        data = {"authorized": True, "environment": "lab", "scope_families": ["sqli"],
                "targets": [{"name": "t", "url": "http://lab/sqli", "expected_families": ["sqli"]}]}
        original = evaluate_mod.run_scan
        evaluate_mod.run_scan = _stub_scan({"http://lab/sqli": ["sqli.error_based"]})
        try:
            evaluation = evaluate_mod.evaluate(data, allow_private=True)
        finally:
            evaluate_mod.run_scan = original
        report = evaluate_mod.render_markdown(data, evaluation)
        self.assertIn("Métricas por família", report)
        self.assertIn("| sqli |", report)
        self.assertIn("**Total**", report)


if __name__ == "__main__":
    unittest.main()
