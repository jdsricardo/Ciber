<?php

declare(strict_types=1);

namespace App\Infrastructure\Persistence;

use App\Domain\Contract\AnalysisRepository;
use App\Domain\Model\Analysis;
use App\Domain\Model\SecurityScore;
use App\Infrastructure\Database;

/** MariaDB adapter for {@see AnalysisRepository}. The only place analysis SQL is written. */
final class PdoAnalysisRepository implements AnalysisRepository
{
    public function find(int $id): ?Analysis
    {
        $row = Database::one(
            'SELECT n.*, a.name application_name, a.base_url
             FROM analyses n JOIN applications a ON a.id = n.application_id
             WHERE n.id=?',
            [$id]
        );
        return $row === false ? null : Analysis::fromRow($row);
    }

    public function listByApplication(int $applicationId): array
    {
        // Served by idx_analysis_application_date (application_id, started_at): the index
        // covers both the filter and the ordering, so no filesort is needed for the history.
        $rows = Database::all(
            'SELECT * FROM analyses WHERE application_id=? ORDER BY started_at DESC',
            [$applicationId]
        );
        return array_map(Analysis::fromRow(...), $rows);
    }

    public function start(Analysis $analysis): Analysis
    {
        Database::run(
            "INSERT INTO analyses(application_id,status,mode) VALUES(?,'running',?)",
            [$analysis->applicationId, $analysis->mode->value]
        );
        return new Analysis(
            id: Database::lastInsertId(),
            applicationId: $analysis->applicationId,
            mode: $analysis->mode,
            status: $analysis->status,
            startedAt: $analysis->startedAt,
        );
    }

    public function markCompleted(
        int $analysisId,
        SecurityScore $score,
        int $checksRun,
        int $durationMs,
        int $httpStatus,
    ): void {
        Database::run(
            "UPDATE analyses SET status='completed',security_score=?,checks_run=?,duration_ms=?,http_status=?,
             completed_at=UTC_TIMESTAMP() WHERE id=?",
            [$score->value, $checksRun, $durationMs, $httpStatus, $analysisId]
        );
    }

    public function markFailed(int $analysisId, string $errorMessage): void
    {
        Database::run(
            "UPDATE analyses SET status='failed',error_message=?,completed_at=UTC_TIMESTAMP() WHERE id=?",
            [mb_substr($errorMessage, 0, 1000), $analysisId]
        );
    }
}
