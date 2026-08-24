<?php

declare(strict_types=1);

namespace App\Repositories;

use App\Database;

final class AnalysisRepository
{
    public function find(int $id): array|false
    {
        return Database::one(
            'SELECT n.*, a.name application_name, a.base_url
             FROM analyses n JOIN applications a ON a.id = n.application_id
             WHERE n.id=?',
            [$id]
        );
    }

    public function listByApplication(int $applicationId): array
    {
        return Database::all('SELECT * FROM analyses WHERE application_id=? ORDER BY started_at DESC', [$applicationId]);
    }

    public function createRunning(int $applicationId, string $mode): int
    {
        Database::run("INSERT INTO analyses(application_id,status,mode) VALUES(?,'running',?)", [$applicationId, $mode]);
        return Database::lastInsertId();
    }

    public function markFailed(int $id, string $errorMessage): void
    {
        Database::run(
            "UPDATE analyses SET status='failed',error_message=?,completed_at=UTC_TIMESTAMP() WHERE id=?",
            [$errorMessage, $id]
        );
    }

    public function markCompleted(int $id, int $securityScore, int $checksRun, int $durationMs, int $httpStatus): void
    {
        Database::run(
            "UPDATE analyses SET status='completed',security_score=?,checks_run=?,duration_ms=?,http_status=?,completed_at=UTC_TIMESTAMP() WHERE id=?",
            [$securityScore, $checksRun, $durationMs, $httpStatus, $id]
        );
    }
}
