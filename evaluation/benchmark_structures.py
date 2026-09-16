#!/usr/bin/env python3
"""Measures the data-structure decisions of the scanner engine's critical loops.

Three decisions taken in `engine/runner.py` are measured against the alternative that was
considered for each one, on the same input sizes the engine really works with (max_pages) and
one and two orders of magnitude beyond, so the asymptotic behaviour is visible and not guessed:

1. crawl frontier  -- list.pop(0) (O(n) shift) vs collections.deque.popleft() (O(1))
2. visited pages   -- membership in a list (O(n)) vs in a set (O(1) average)
3. de-duplication  -- pairwise scan (O(n^2)) vs a set of keys (O(n))

Run: python evaluation/benchmark_structures.py [--json]
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import deque

REPEATS = 5
SIZES = (30, 1_000, 10_000)


def _median_ms(operation, repeats: int = REPEATS) -> float:
    """Median wall-clock time of `operation`, in milliseconds.

    The median (not the mean) is reported so a single scheduling hiccup on the measuring
    machine cannot move the result.
    """
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        operation()
        samples.append((time.perf_counter() - start) * 1000)
    return round(statistics.median(samples), 4)


def frontier_list(size: int) -> None:
    queue = [(f"https://alvo.local/pagina/{i}", 0) for i in range(size)]
    while queue:
        queue.pop(0)


def frontier_deque(size: int) -> None:
    queue = deque((f"https://alvo.local/pagina/{i}", 0) for i in range(size))
    while queue:
        queue.popleft()


def visited_list(size: int) -> None:
    signatures = [f"https://alvo.local/pagina/{i}?" for i in range(size)]
    visited: list[str] = []
    for signature in signatures:
        if signature not in visited:
            visited.append(signature)


def visited_set(size: int) -> None:
    signatures = [f"https://alvo.local/pagina/{i}?" for i in range(size)]
    visited: set[str] = set()
    for signature in signatures:
        if signature not in visited:
            visited.add(signature)


def _finding_keys(size: int) -> list[tuple[str, str, str]]:
    """Half the keys are repeats, which is what a multi-page crawl really produces."""
    return [(f"headers.check_{i % (size // 2 or 1)}", f"https://alvo.local/p/{i % 10}", "q")
            for i in range(size)]


def dedup_pairwise(size: int) -> None:
    unique: list[tuple[str, str, str]] = []
    for key in _finding_keys(size):
        if key not in unique:
            unique.append(key)


def dedup_set(size: int) -> None:
    seen: set[tuple[str, str, str]] = set()
    unique: list[tuple[str, str, str]] = []
    for key in _finding_keys(size):
        if key in seen:
            continue
        seen.add(key)
        unique.append(key)


DECISIONS = (
    ("Fila da varredura (frontier)", "lista + pop(0)", frontier_list, "deque + popleft()", frontier_deque),
    ("Páginas já enfileiradas", "lista + in", visited_list, "set + in", visited_set),
    ("Deduplicação de achados", "varredura par a par", dedup_pairwise, "set de chaves", dedup_set),
)


def measure() -> list[dict]:
    results = []
    for title, name_a, operation_a, name_b, operation_b in DECISIONS:
        for size in SIZES:
            time_a = _median_ms(lambda: operation_a(size))
            time_b = _median_ms(lambda: operation_b(size))
            results.append({
                "decision": title,
                "n": size,
                "alternative": name_a,
                "alternative_ms": time_a,
                "chosen": name_b,
                "chosen_ms": time_b,
                "speedup": round(time_a / time_b, 1) if time_b else None,
            })
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()

    results = measure()
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0

    print(f"{'Decisão':32s} {'n':>7s} {'alternativa':24s} {'ms':>9s} {'escolhida':20s} {'ms':>9s} {'ganho':>7s}")
    for row in results:
        speedup = f"{row['speedup']}x" if row["speedup"] else "-"
        print(f"{row['decision']:32s} {row['n']:>7d} {row['alternative']:24s} "
              f"{row['alternative_ms']:>9.4f} {row['chosen']:20s} {row['chosen_ms']:>9.4f} {speedup:>7s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
