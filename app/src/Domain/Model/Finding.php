<?php

declare(strict_types=1);

namespace App\Domain\Model;

use App\Domain\Exception\InvalidInput;

/**
 * One security issue observed during an analysis.
 *
 * Identity is the `fingerprint`: a stable key derived from the check and the affected place,
 * which is what makes two analyses of the same application comparable. Severity says how bad
 * the issue would be; `confidence` says how sure the detector is. They are deliberately kept
 * apart — weak evidence lowers confidence, never severity.
 *
 * The explanatory fields (`developerImpact`, `remediation`, the example pair) are part of the
 * entity rather than of the view, because a finding the developer cannot act on is the problem
 * this project exists to solve.
 */
final class Finding
{
    /**
     * @param array<string,mixed> $evidence structured evidence produced by the scanner engine
     */
    public function __construct(
        public readonly string $fingerprint,
        public readonly string $title,
        public readonly Severity $severity,
        public readonly string $affectedUrl,
        public readonly string $developerImpact,
        public readonly string $remediation,
        public readonly ?int $confidence = null,
        public readonly ?string $status = null,
        public readonly ?string $category = null,
        public readonly ?string $cwe = null,
        public readonly ?string $owasp = null,
        public readonly ?string $wstg = null,
        public readonly ?string $method = null,
        public readonly ?string $parameter = null,
        public readonly ?string $parameterLocation = null,
        public readonly ?string $description = null,
        public readonly ?string $evidenceSummary = null,
        public readonly array $evidence = [],
        public readonly bool $manualReviewRequired = false,
        public readonly ?RemediationExample $example = null,
    ) {
        if (trim($fingerprint) === '') {
            throw new InvalidInput('O achado precisa de um identificador de verificação (fingerprint).');
        }
        if (trim($title) === '') {
            throw new InvalidInput('O achado precisa de um título.');
        }
        if (trim($affectedUrl) === '') {
            throw new InvalidInput('O achado precisa da URL afetada.');
        }
        if ($confidence !== null && ($confidence < 0 || $confidence > 100)) {
            throw new InvalidInput('A confiança do achado deve estar entre 0 e 100.');
        }
    }

    /**
     * Builds a Finding from one decoded scanner finding or one persisted row. Both carry the
     * same field names, which is why the engine's JSON and the `findings` table agree.
     *
     * @param array<string,mixed> $row
     */
    public static function fromRow(array $row): self
    {
        $evidence = $row['evidence'] ?? [];
        if (is_string($evidence)) {
            $evidence = json_decode($evidence, true) ?: [];
        }

        return new self(
            fingerprint: (string) ($row['fingerprint'] ?? ''),
            title: (string) ($row['title'] ?? ''),
            severity: Severity::fromString((string) ($row['severity'] ?? '')),
            affectedUrl: (string) ($row['affected_url'] ?? ''),
            developerImpact: (string) ($row['developer_impact'] ?? ''),
            remediation: (string) ($row['remediation'] ?? ''),
            confidence: isset($row['confidence']) && $row['confidence'] !== null ? (int) $row['confidence'] : null,
            status: self::nullableString($row['status'] ?? null),
            category: self::nullableString($row['category'] ?? null),
            cwe: self::nullableString($row['cwe'] ?? null),
            owasp: self::nullableString($row['owasp'] ?? null),
            wstg: self::nullableString($row['wstg'] ?? null),
            method: self::nullableString($row['method'] ?? null),
            parameter: self::nullableString($row['parameter'] ?? null),
            parameterLocation: self::nullableString($row['parameter_location'] ?? null),
            description: self::nullableString($row['description'] ?? null),
            evidenceSummary: self::nullableString($row['evidence_summary'] ?? null),
            evidence: is_array($evidence) ? $evidence : [],
            manualReviewRequired: (bool) ($row['manual_review_required'] ?? false),
            example: RemediationExample::fromRow($row),
        );
    }

    /** What the scanner observed, preferring the short summary over the long description. */
    public function observed(): string
    {
        return ($this->evidenceSummary ?? '') !== '' ? (string) $this->evidenceSummary : (string) $this->description;
    }

    private static function nullableString(mixed $value): ?string
    {
        return $value === null || $value === '' ? null : (string) $value;
    }
}
