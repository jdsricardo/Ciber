<?php

declare(strict_types=1);

namespace App\Domain\Service;

/**
 * Compares the findings of two analyses of the same application and classifies each finding as
 * new, persistent, or fixed. Identity is the row's `identity` key — check, endpoint and input, as
 * produced by {@see \App\Domain\Model\Finding::identity()} — falling back to the fingerprint for
 * rows that carry no identity.
 *
 * Both sides are first turned into maps keyed by identity, so each classification is a hash
 * lookup instead of a scan of the other list. The measurement behind that choice is in
 * `evaluation/benchmark_comparison.php` and `docs/ALGORITHM_MEASUREMENTS.md`.
 *
 * It owns no I/O and no rendering, so it is unit-testable in isolation.
 */
final class AnalysisComparison
{
    /**
     * @param array<int,array<string,mixed>> $oldFindings findings of the earlier analysis
     * @param array<int,array<string,mixed>> $newFindings findings of the later analysis
     * @return array{new:array<string,array<string,mixed>>,persistent:array<string,array<string,mixed>>,fixed:array<string,array<string,mixed>>}
     */
    public static function diff(array $oldFindings, array $newFindings): array
    {
        $old = self::keyByIdentity($oldFindings);
        $new = self::keyByIdentity($newFindings);

        return [
            'new' => array_diff_key($new, $old),             // present now, absent before
            'persistent' => array_intersect_key($new, $old), // present in both
            'fixed' => array_diff_key($old, $new),           // present before, absent now
        ];
    }

    /**
     * @param array<int,array<string,mixed>> $findings
     * @return array<string,array<string,mixed>>
     */
    private static function keyByIdentity(array $findings): array
    {
        $keyed = [];
        foreach ($findings as $finding) {
            $identity = (string) ($finding['identity'] ?? $finding['fingerprint'] ?? '');
            if ($identity !== '') {
                $keyed[$identity] = $finding;
            }
        }
        return $keyed;
    }
}
