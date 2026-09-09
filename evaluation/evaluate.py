#!/usr/bin/env python3
"""Empirical evaluation harness for SentinelScope.

Runs the scanner against a set of deliberately vulnerable targets described in a
ground-truth file and computes per-class and overall detection metrics
(true positives, false positives, false negatives, precision, recall, F1),
producing a Markdown report suitable for the TCC's results section.

This is the reproducible skeleton of the empirical evaluation proposed in the
article (Doupé, Cova and Vigna, 2010; Bau et al., 2010; Fonseca, Vieira and
Madeira, 2007): point it at DVWA / OWASP Juice Shop / WebGoat in an isolated,
authorized laboratory and record the numbers it prints. It intentionally makes
NO network request of its own beyond the scanner, and refuses to run unless the
ground-truth file explicitly acknowledges authorization.

Usage:
    python evaluation/evaluate.py evaluation/ground_truth.example.json \
        --out evaluation/report.md [--allow-private]

Ground-truth schema (see ground_truth.example.json):
    {
      "authorized": true,                      # required, must be true
      "environment": "free text, e.g. DVWA 1.10 on localhost lab",
      "scope_families": ["sqli", "xss", ...],  # vuln families this run judges
      "targets": [
        {
          "name": "DVWA SQLi (low)",
          "url": "http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit",
          "mode": "safe_active",
          "expected_families": ["sqli"]         # families truly present here
        }
      ]
    }

A "family" is the prefix of a finding fingerprint before the first dot
(e.g. "sqli.boolean_differential" -> "sqli"). Only families listed in
`scope_families` are judged: a detection outside that set (e.g. a passive
"headers" finding) is neither a true nor a false positive, it is simply out of
scope for the class-detection experiment.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scanner"))

from engine.runner import run_scan  # noqa: E402


def family_of(fingerprint: str) -> str:
    return fingerprint.split(".", 1)[0]


def load_ground_truth(path: pathlib.Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("authorized") is not True:
        raise SystemExit(
            "Recusado: o arquivo de ground-truth precisa declarar \"authorized\": true, "
            "confirmando que os alvos são um laboratório próprio ou autorizado."
        )
    if not data.get("targets"):
        raise SystemExit("Ground-truth sem alvos ('targets').")
    return data


def evaluate(data: dict, allow_private: bool) -> dict:
    scope = set(data.get("scope_families", []))
    # counts[family] = {"tp": int, "fp": int, "fn": int}
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    per_target = []

    for target in data["targets"]:
        url = target["url"]
        mode = target.get("mode", "safe_active")
        expected = set(target.get("expected_families", []))
        result = run_scan(url, mode=mode, allow_private=allow_private)

        if not result.get("ok"):
            per_target.append({"name": target.get("name", url), "url": url,
                               "error": result.get("error", "erro desconhecido")})
            # A scan that could not run counts every expected family as a miss.
            for fam in expected:
                counts[fam]["fn"] += 1
            continue

        detected = {family_of(f["fingerprint"]) for f in result["findings"]}
        detected_in_scope = detected & scope if scope else detected

        tp = expected & detected_in_scope
        fn = expected - detected_in_scope
        fp = (detected_in_scope - expected) if scope else set()

        for fam in tp:
            counts[fam]["tp"] += 1
        for fam in fn:
            counts[fam]["fn"] += 1
        for fam in fp:
            counts[fam]["fp"] += 1

        per_target.append({
            "name": target.get("name", url), "url": url, "mode": mode,
            "expected": sorted(expected), "detected_in_scope": sorted(detected_in_scope),
            "tp": sorted(tp), "fp": sorted(fp), "fn": sorted(fn),
            "requests_made": result.get("requests_made"),
            "duration_ms": result.get("duration_ms"),
        })

    return {"scope": sorted(scope), "counts": counts, "per_target": per_target}


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def render_markdown(data: dict, evaluation: dict) -> str:
    lines: list[str] = []
    lines.append("# Resultado da avaliação empírica — SentinelScope\n")
    lines.append(f"**Ambiente:** {data.get('environment', '(não informado)')}\n")
    lines.append(f"**Famílias avaliadas (escopo):** {', '.join(evaluation['scope']) or '(todas)'}\n")

    lines.append("\n## Métricas por família\n")
    lines.append("| Família | VP | FP | FN | Precisão | Recall | F1 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    total = {"tp": 0, "fp": 0, "fn": 0}
    for fam in sorted(evaluation["counts"]):
        c = evaluation["counts"][fam]
        total["tp"] += c["tp"]; total["fp"] += c["fp"]; total["fn"] += c["fn"]
        p, r, f1 = _prf(c["tp"], c["fp"], c["fn"])
        lines.append(f"| {fam} | {c['tp']} | {c['fp']} | {c['fn']} | {p:.2f} | {r:.2f} | {f1:.2f} |")
    p, r, f1 = _prf(total["tp"], total["fp"], total["fn"])
    lines.append(f"| **Total** | **{total['tp']}** | **{total['fp']}** | **{total['fn']}** "
                 f"| **{p:.2f}** | **{r:.2f}** | **{f1:.2f}** |")

    lines.append("\n## Detalhe por alvo\n")
    for t in evaluation["per_target"]:
        lines.append(f"### {t['name']}")
        lines.append(f"- URL: `{t['url']}`")
        if "error" in t:
            lines.append(f"- **Erro na varredura:** {t['error']}")
            continue
        lines.append(f"- Modo: {t['mode']} · requisições: {t.get('requests_made')} · duração: {t.get('duration_ms')} ms")
        lines.append(f"- Esperado: {t['expected'] or '—'}")
        lines.append(f"- Detectado (no escopo): {t['detected_in_scope'] or '—'}")
        lines.append(f"- VP: {t['tp'] or '—'} · FP: {t['fp'] or '—'} · FN: {t['fn'] or '—'}")
        lines.append("")
    lines.append("\n> Gerado por `evaluation/evaluate.py`. Preencha a coluna comparativa com a "
                 "baseline de mercado (ex.: OWASP ZAP baseline) executada sobre os mesmos alvos.\n")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Avaliação empírica do SentinelScope contra alvos vulneráveis autorizados.")
    parser.add_argument("ground_truth", help="Caminho do arquivo JSON de ground-truth.")
    parser.add_argument("--out", default=None, help="Arquivo Markdown de saída (padrão: stdout).")
    parser.add_argument("--allow-private", action="store_true",
                        help="Permite alvos em rede privada/loopback (somente laboratório autorizado).")
    args = parser.parse_args()

    data = load_ground_truth(pathlib.Path(args.ground_truth))
    evaluation = evaluate(data, allow_private=args.allow_private)
    report = render_markdown(data, evaluation)

    if args.out:
        pathlib.Path(args.out).write_text(report, encoding="utf-8")
        print(f"Relatório escrito em {args.out}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
