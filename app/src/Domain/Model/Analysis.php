<?php

declare(strict_types=1);

namespace App\Domain\Model;

use App\Domain\Exception\InvalidInput;
use DateTimeImmutable;

/**
 * One execution of the check catalogue against one application.
 *
 * An analysis is the unit of comparison: the history of an application is its sequence of
 * analyses, and "what changed?" is always a question about two of them. The invariants that
 * make that possible are enforced here — a completed analysis always has a score, and a
 * failed one always has a reason.
 */
final class Analysis
{
    public function __construct(
        public readonly ?int $id,
        public readonly int $applicationId,
        public readonly ScanMode $mode,
        public readonly AnalysisStatus $status,
        public readonly DateTimeImmutable $startedAt,
        public readonly ?SecurityScore $score = null,
        public readonly int $checksRun = 0,
        public readonly int $durationMs = 0,
        public readonly int $httpStatus = 0,
        public readonly ?string $errorMessage = null,
        public readonly ?DateTimeImmutable $completedAt = null,
        public readonly ?string $applicationName = null,
        public readonly ?TargetUrl $baseUrl = null,
    ) {
        if ($id !== null && $id <= 0) {
            throw new InvalidInput('Identificador de análise inválido.');
        }
        if ($applicationId <= 0) {
            throw new InvalidInput('A análise precisa pertencer a uma aplicação registrada.');
        }
        if ($status === AnalysisStatus::Completed && $score === null) {
            throw new InvalidInput('Uma análise concluída precisa de uma pontuação de segurança.');
        }
        if ($status === AnalysisStatus::Failed && ($errorMessage === null || trim($errorMessage) === '')) {
            throw new InvalidInput('Uma análise que falhou precisa registrar o motivo.');
        }
        if ($checksRun < 0 || $durationMs < 0) {
            throw new InvalidInput('Verificações executadas e duração não podem ser negativas.');
        }
    }

    /** Factory for the analysis created at the moment the user starts a run. */
    public static function start(int $applicationId, ScanMode $mode): self
    {
        return new self(
            id: null,
            applicationId: $applicationId,
            mode: $mode,
            status: AnalysisStatus::Running,
            startedAt: new DateTimeImmutable('now'),
        );
    }

    /** @param array<string,mixed> $row */
    public static function fromRow(array $row): self
    {
        $score = isset($row['security_score']) && $row['security_score'] !== null
            ? SecurityScore::fromInt((int) $row['security_score'])
            : null;
        $baseUrl = isset($row['base_url']) && $row['base_url'] !== null
            ? TargetUrl::fromString((string) $row['base_url'])
            : null;

        return new self(
            id: (int) $row['id'],
            applicationId: (int) $row['application_id'],
            mode: ScanMode::fromString((string) ($row['mode'] ?? ScanMode::Passive->value)),
            status: AnalysisStatus::fromString((string) $row['status']),
            startedAt: new DateTimeImmutable((string) ($row['started_at'] ?? 'now')),
            score: $score,
            checksRun: (int) ($row['checks_run'] ?? 0),
            durationMs: (int) ($row['duration_ms'] ?? 0),
            httpStatus: (int) ($row['http_status'] ?? 0),
            errorMessage: isset($row['error_message']) && $row['error_message'] !== ''
                ? (string) $row['error_message'] : null,
            completedAt: isset($row['completed_at']) && $row['completed_at'] !== null
                ? new DateTimeImmutable((string) $row['completed_at']) : null,
            applicationName: isset($row['application_name']) ? (string) $row['application_name'] : null,
            baseUrl: $baseUrl,
        );
    }

    public function requireId(): int
    {
        return $this->id ?? throw new InvalidInput('A análise ainda não foi persistida.');
    }

    /** Two analyses can only be compared when they belong to the same application. */
    public function isComparableWith(self $other): bool
    {
        return $this->applicationId === $other->applicationId;
    }
}
