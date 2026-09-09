<?php

declare(strict_types=1);

namespace App\Support;

/**
 * Compares the findings of two analyses of the same application and classifies each
 * finding as new, persistent, or fixed, using the stable per-finding fingerprint as
 * identity. Extracted from the request handler so the classification is unit-testable
 * in isolation (it owns no I/O and no rendering).
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
        $old = self::keyByFingerprint($oldFindings);
        $new = self::keyByFingerprint($newFindings);

        return [
            'new' => array_diff_key($new, $old),          // present now, absent before
            'persistent' => array_intersect_key($new, $old), // present in both
            'fixed' => array_diff_key($old, $new),         // present before, absent now
        ];
    }

    /** @param array<int,array<string,mixed>> $findings @return array<string,array<string,mixed>> */
    private static function keyByFingerprint(array $findings): array
    {
        $keyed = [];
        foreach ($findings as $finding) {
            $fingerprint = (string) ($finding['fingerprint'] ?? '');
            if ($fingerprint !== '') {
                $keyed[$fingerprint] = $finding;
            }
        }
        return $keyed;
    }
}
