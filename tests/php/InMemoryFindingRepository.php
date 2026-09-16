<?php

declare(strict_types=1);

namespace Tests\Php;

use App\Domain\Contract\FindingRepository;
use App\Domain\Model\Finding;

/** In-memory {@see FindingRepository}, ordering by severity exactly as the SQL adapter does. */
final class InMemoryFindingRepository implements FindingRepository
{
    /** @var array<int,list<Finding>> */
    private array $byAnalysis = [];

    public function byAnalysis(int $analysisId): array
    {
        $findings = $this->byAnalysis[$analysisId] ?? [];
        usort(
            $findings,
            static fn(Finding $a, Finding $b): int => [$a->severity->rank(), $a->title]
                <=> [$b->severity->rank(), $b->title],
        );
        return $findings;
    }

    public function saveAll(int $analysisId, array $findings): void
    {
        $this->byAnalysis[$analysisId] = array_merge($this->byAnalysis[$analysisId] ?? [], $findings);
    }
}
