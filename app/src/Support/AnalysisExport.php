<?php

declare(strict_types=1);

namespace App\Support;

/**
 * Builds the machine-readable (JSON) representation of a completed analysis and its findings,
 * for CI pipelines or ticketing. Extracted from the request handler so the shape is
 * unit-testable in isolation (it owns no I/O).
 */
final class AnalysisExport
{
    /**
     * @param array<string,mixed> $analysis one analysis row
     * @param array<int,array<string,mixed>> $findings its finding rows
     * @return array<string,mixed> JSON-serializable document
     */
    public static function toArray(array $analysis, array $findings): array
    {
        return [
            'tool' => 'SentinelScope',
            'analysis' => [
                'id' => (int) $analysis['id'],
                'application' => $analysis['application_name'] ?? null,
                'base_url' => $analysis['base_url'] ?? null,
                'mode' => $analysis['mode'] ?? null,
                'status' => $analysis['status'] ?? null,
                'security_score' => isset($analysis['security_score']) && $analysis['security_score'] !== null
                    ? (int) $analysis['security_score'] : null,
                'checks_run' => (int) ($analysis['checks_run'] ?? 0),
                'http_status' => (int) ($analysis['http_status'] ?? 0),
                'duration_ms' => (int) ($analysis['duration_ms'] ?? 0),
                'started_at' => $analysis['started_at'] ?? null,
                'completed_at' => $analysis['completed_at'] ?? null,
            ],
            'summary' => ['findings' => count($findings)],
            'findings' => array_map([self::class, 'mapFinding'], $findings),
        ];
    }

    /** @param array<string,mixed> $f @return array<string,mixed> */
    private static function mapFinding(array $f): array
    {
        return [
            'fingerprint' => $f['fingerprint'] ?? null,
            'title' => $f['title'] ?? null,
            'category' => $f['category'] ?? null,
            'severity' => $f['severity'] ?? null,
            'confidence' => isset($f['confidence']) && $f['confidence'] !== null ? (int) $f['confidence'] : null,
            'status' => $f['status'] ?? null,
            'cwe' => $f['cwe'] ?? null,
            'owasp' => $f['owasp'] ?? null,
            'wstg' => $f['wstg'] ?? null,
            'affected_url' => $f['affected_url'] ?? null,
            'method' => $f['method'] ?? null,
            'parameter' => $f['parameter'] ?? null,
            'parameter_location' => $f['parameter_location'] ?? null,
            'manual_review_required' => (bool) ($f['manual_review_required'] ?? false),
            'observed' => ($f['evidence_summary'] ?? '') ?: ($f['description'] ?? null),
            'developer_impact' => $f['developer_impact'] ?? null,
            'remediation' => $f['remediation'] ?? null,
            'remediation_example' => [
                'language' => $f['remediation_example_language'] ?? null,
                'vulnerable' => $f['remediation_example_vulnerable'] ?? null,
                'fixed' => $f['remediation_example_fixed'] ?? null,
                'note' => $f['remediation_example_note'] ?? null,
            ],
            'evidence' => isset($f['evidence']) ? json_decode((string) $f['evidence'], true) : null,
        ];
    }
}
