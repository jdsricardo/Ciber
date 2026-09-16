<?php

declare(strict_types=1);

/**
 * Measures the data-structure decision behind AnalysisComparison (new / persistent / fixed).
 *
 * The comparison has to answer "is this fingerprint present in the other analysis?" once per
 * finding. Two implementations are measured on the same inputs: the pairwise scan that the
 * question suggests, and the fingerprint-keyed hash map the domain service actually uses.
 * Sizes cover the acceptance criterion (CA-05 / NFR-01 works with 1,000 findings) plus one
 * order of magnitude above and below it.
 *
 * Run: php evaluation/benchmark_comparison.php [--json]
 */

require __DIR__ . '/../app/autoload.php';

use App\Domain\Service\AnalysisComparison;

const REPEATS = 5;
const SIZES = [100, 1000, 10000];

/** @return array<int,array<string,mixed>> */
function buildFindings(int $size, int $offset): array
{
    $findings = [];
    for ($i = 0; $i < $size; $i++) {
        $findings[] = ['fingerprint' => 'headers.check_' . ($i + $offset), 'severity' => 'low'];
    }
    return $findings;
}

/** Median wall-clock time of $work, in milliseconds, so one scheduling hiccup cannot move it. */
function medianMs(callable $work): float
{
    $samples = [];
    for ($i = 0; $i < REPEATS; $i++) {
        $start = microtime(true);
        $work();
        $samples[] = (microtime(true) - $start) * 1000;
    }
    sort($samples);
    return round($samples[intdiv(count($samples), 2)], 4);
}

/** The alternative: for each new finding, scan the old list looking for the same fingerprint. */
function diffPairwise(array $oldFindings, array $newFindings): array
{
    $new = [];
    $persistent = [];
    foreach ($newFindings as $candidate) {
        $found = false;
        foreach ($oldFindings as $previous) {
            if ($previous['fingerprint'] === $candidate['fingerprint']) {
                $found = true;
                break;
            }
        }
        $found ? $persistent[] = $candidate : $new[] = $candidate;
    }
    $fixed = [];
    foreach ($oldFindings as $previous) {
        $found = false;
        foreach ($newFindings as $candidate) {
            if ($previous['fingerprint'] === $candidate['fingerprint']) {
                $found = true;
                break;
            }
        }
        if (!$found) {
            $fixed[] = $previous;
        }
    }
    return ['new' => $new, 'persistent' => $persistent, 'fixed' => $fixed];
}

$results = [];
foreach (SIZES as $size) {
    // Half the findings persist between the two analyses, which is the realistic case: a
    // re-scan after a partial fix, not two unrelated result sets.
    $old = buildFindings($size, 0);
    $new = buildFindings($size, intdiv($size, 2));

    $pairwise = medianMs(static fn() => diffPairwise($old, $new));
    $keyed = medianMs(static fn() => AnalysisComparison::diff($old, $new));

    $results[] = [
        'decision' => 'Comparação entre análises',
        'n' => $size,
        'alternative' => 'varredura par a par',
        'alternative_ms' => $pairwise,
        'chosen' => 'mapa por fingerprint',
        'chosen_ms' => $keyed,
        'speedup' => $keyed > 0 ? round($pairwise / $keyed, 1) : null,
    ];
}

if (in_array('--json', $argv, true)) {
    echo json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), PHP_EOL;
    exit(0);
}

printf("%-28s %7s %-22s %9s %-22s %9s %7s\n", 'Decisão', 'n', 'alternativa', 'ms', 'escolhida', 'ms', 'ganho');
foreach ($results as $row) {
    printf(
        "%-28s %7d %-22s %9.4f %-22s %9.4f %6sx\n",
        $row['decision'], $row['n'], $row['alternative'], $row['alternative_ms'],
        $row['chosen'], $row['chosen_ms'], (string) $row['speedup']
    );
}
