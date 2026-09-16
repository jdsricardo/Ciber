<?php

declare(strict_types=1);

namespace Tests\Php;

use App\Domain\Contract\AnalysisRepository;
use App\Domain\Model\Analysis;
use App\Domain\Model\AnalysisStatus;
use App\Domain\Model\SecurityScore;
use DateTimeImmutable;

/** In-memory {@see AnalysisRepository}, so analyses can be exercised without a database. */
final class InMemoryAnalysisRepository implements AnalysisRepository
{
    /** @var array<int,Analysis> */
    private array $rows = [];
    private int $nextId = 1;

    public function find(int $id): ?Analysis
    {
        return $this->rows[$id] ?? null;
    }

    public function listByApplication(int $applicationId): array
    {
        $matching = array_filter(
            $this->rows,
            static fn(Analysis $analysis): bool => $analysis->applicationId === $applicationId,
        );
        return array_values(array_reverse($matching, true));
    }

    public function start(Analysis $analysis): Analysis
    {
        $id = $this->nextId++;
        $stored = new Analysis(
            id: $id,
            applicationId: $analysis->applicationId,
            mode: $analysis->mode,
            status: AnalysisStatus::Running,
            startedAt: $analysis->startedAt,
        );
        $this->rows[$id] = $stored;
        return $stored;
    }

    public function markCompleted(
        int $analysisId,
        SecurityScore $score,
        int $checksRun,
        int $durationMs,
        int $httpStatus,
    ): void {
        $current = $this->rows[$analysisId];
        $this->rows[$analysisId] = new Analysis(
            id: $analysisId,
            applicationId: $current->applicationId,
            mode: $current->mode,
            status: AnalysisStatus::Completed,
            startedAt: $current->startedAt,
            score: $score,
            checksRun: $checksRun,
            durationMs: $durationMs,
            httpStatus: $httpStatus,
            completedAt: new DateTimeImmutable('now'),
            applicationName: $current->applicationName,
            baseUrl: $current->baseUrl,
        );
    }

    public function markFailed(int $analysisId, string $errorMessage): void
    {
        $current = $this->rows[$analysisId];
        $this->rows[$analysisId] = new Analysis(
            id: $analysisId,
            applicationId: $current->applicationId,
            mode: $current->mode,
            status: AnalysisStatus::Failed,
            startedAt: $current->startedAt,
            errorMessage: $errorMessage,
            completedAt: new DateTimeImmutable('now'),
            applicationName: $current->applicationName,
            baseUrl: $current->baseUrl,
        );
    }
}
