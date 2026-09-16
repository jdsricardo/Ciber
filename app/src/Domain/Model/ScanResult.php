<?php

declare(strict_types=1);

namespace App\Domain\Model;

use App\Domain\Exception\InvalidInput;

/**
 * What one scan produced: either a set of findings and its run metrics, or the reason it
 * failed. Modelling both outcomes as one type keeps the caller from having to inspect a raw
 * associative array to learn whether the scan worked.
 */
final class ScanResult
{
    /** @param list<Finding> $findings */
    private function __construct(
        public readonly bool $ok,
        public readonly array $findings = [],
        public readonly int $checksRun = 0,
        public readonly int $durationMs = 0,
        public readonly int $httpStatus = 0,
        public readonly ?string $error = null,
    ) {
    }

    /** @param list<Finding> $findings */
    public static function success(array $findings, int $checksRun, int $durationMs, int $httpStatus): self
    {
        return new self(true, $findings, $checksRun, $durationMs, $httpStatus);
    }

    public static function failure(string $error): self
    {
        $error = trim($error);
        if ($error === '') {
            throw new InvalidInput('Uma análise que falhou precisa registrar o motivo.');
        }
        return new self(false, error: $error);
    }

    /**
     * Reads the JSON document produced by the scanner engine. Unknown or missing fields fall
     * back to neutral values rather than throwing, because a scanner that answers partially is
     * still more useful than no answer — but an `ok:false` (or an unreadable body) is a failure.
     *
     * @param array<string,mixed> $payload
     */
    public static function fromEnginePayload(array $payload): self
    {
        if (empty($payload['ok'])) {
            return self::failure((string) ($payload['error'] ?? 'Erro desconhecido durante a análise.'));
        }
        $findings = [];
        foreach ((array) ($payload['findings'] ?? []) as $row) {
            if (is_array($row)) {
                $findings[] = Finding::fromRow($row);
            }
        }
        return self::success(
            $findings,
            (int) ($payload['checks_run'] ?? 0),
            (int) ($payload['duration_ms'] ?? 0),
            (int) ($payload['status_code'] ?? 0),
        );
    }

    public function score(): SecurityScore
    {
        return SecurityScore::fromFindings($this->findings);
    }
}
