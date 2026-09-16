<?php

declare(strict_types=1);

namespace App\Domain\Contract;

use App\Domain\Model\Analysis;
use App\Domain\Model\SecurityScore;

/** Storage of analyses, declared by the domain and implemented outside it. */
interface AnalysisRepository
{
    public function find(int $id): ?Analysis;

    /** @return list<Analysis> history of one application, newest first */
    public function listByApplication(int $applicationId): array;

    /** Persists a `running` analysis and returns it with the identifier assigned by storage. */
    public function start(Analysis $analysis): Analysis;

    public function markCompleted(
        int $analysisId,
        SecurityScore $score,
        int $checksRun,
        int $durationMs,
        int $httpStatus,
    ): void;

    public function markFailed(int $analysisId, string $errorMessage): void;
}
