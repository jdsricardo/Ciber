<?php

declare(strict_types=1);

namespace App\Domain\Contract;

use App\Domain\Model\Finding;

/** Storage of findings, declared by the domain and implemented outside it. */
interface FindingRepository
{
    /** @return list<Finding> ordered by severity (most severe first), then title */
    public function byAnalysis(int $analysisId): array;

    /** @param list<Finding> $findings persisted as one unit with the analysis that produced them */
    public function saveAll(int $analysisId, array $findings): void;
}
