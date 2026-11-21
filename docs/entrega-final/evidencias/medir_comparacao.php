<?php
declare(strict_types=1);

/**
 * Reproduz a medição do D4: identidade completa, dois métodos, três volumes.
 * Executar na raiz: php docs/entrega-final/evidencias/medir_comparacao.php
 * P95: posto ceil(0,95*n), sem interpolação. Dados determinísticos, sem sorteio.
 */
require dirname(__DIR__, 3) . '/app/autoload.php';

use App\Domain\Service\AnalysisComparison;

function inputRows(int $size, int $offset): array
{
    $rows = [];
    for ($i = 0; $i < $size; $i++) {
        $id = $i + $offset;
        $rows[] = [
            'identity' => 'xss.reflected_html_text|https://laboratorio.invalid/p/' . $id . '|query|q',
            'fingerprint' => 'xss.reflected_html_text',
            'severity' => 'high',
        ];
    }
    return $rows;
}

function comparePairwise(array $old, array $new): array
{
    $added = [];
    $persistent = [];
    foreach ($new as $candidate) {
        $found = false;
        foreach ($old as $previous) {
            if ($previous['identity'] === $candidate['identity']) {
                $found = true;
                break;
            }
        }
        if ($found) {
            $persistent[$candidate['identity']] = $candidate;
        } else {
            $added[$candidate['identity']] = $candidate;
        }
    }
    $fixed = [];
    foreach ($old as $previous) {
        $found = false;
        foreach ($new as $candidate) {
            if ($previous['identity'] === $candidate['identity']) {
                $found = true;
                break;
            }
        }
        if (!$found) {
            $fixed[$previous['identity']] = $previous;
        }
    }
    return ['new' => $added, 'persistent' => $persistent, 'fixed' => $fixed];
}

function measureSamples(callable $work, int $repeats): array
{
    $samples = [];
    for ($i = 0; $i < $repeats; $i++) {
        $start = hrtime(true);
        $work();
        $samples[] = (hrtime(true) - $start) / 1_000_000;
    }
    sort($samples);
    $middle = intdiv($repeats, 2);
    $median = $repeats % 2 ? $samples[$middle] : ($samples[$middle - 1] + $samples[$middle]) / 2;
    return [
        'median_ms' => round($median, 4),
        'p95_ms' => round($samples[(int) ceil(0.95 * $repeats) - 1], 4),
        'samples_ms' => array_map(static fn(float $value): float => round($value, 6), $samples),
    ];
}

$repeats = 20;
foreach ($argv as $argument) {
    if (str_starts_with($argument, '--repeticoes=')) {
        $repeats = max(5, (int) substr($argument, strlen('--repeticoes=')));
    }
}
$output = [
    'date_utc' => gmdate('c'),
    'php' => PHP_VERSION,
    'platform' => php_uname(),
    'cpu' => getenv('PROCESSOR_IDENTIFIER') ?: 'Consultar inventário da máquina',
    'repeats' => $repeats,
    'unit' => 'milliseconds',
    'p95_method' => 'nearest-rank: sorted_samples[ceil(0.95*n)-1]',
    'dataset' => 'Deterministic, complete identities, 50% overlap; no network or database.',
    'warmup' => 'One call per method and size before sampling.',
    'results' => [],
];
foreach ([100, 1000, 10000] as $size) {
    $old = inputRows($size, 0);
    $new = inputRows($size, intdiv($size, 2));
    $expected = comparePairwise($old, $new);
    $actual = AnalysisComparison::diff($old, $new);
    if ($expected !== $actual) {
        throw new RuntimeException('Métodos produziram resultados diferentes.');
    }
    $pairwise = measureSamples(static fn(): array => comparePairwise($old, $new), $repeats);
    $keyed = measureSamples(static fn(): array => AnalysisComparison::diff($old, $new), $repeats);
    $output['results'][] = [
        'n_per_analysis' => $size,
        'pairwise' => $pairwise,
        'identity_map' => $keyed,
        'same_result' => true,
    ];
    fwrite(STDERR, 'Concluído: n=' . $size . PHP_EOL);
}
echo json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), PHP_EOL;

