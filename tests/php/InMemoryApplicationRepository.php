<?php

declare(strict_types=1);

namespace Tests\Php;

use App\Domain\Contract\ApplicationRepository;
use App\Domain\Model\Application;

/**
 * In-memory {@see ApplicationRepository}: the same contract, backed by an array.
 * It exists so the domain and the use cases can be tested without a database.
 */
final class InMemoryApplicationRepository implements ApplicationRepository
{
    /** @var array<int,Application> */
    private array $rows = [];
    private int $nextId = 1;

    public function all(): array
    {
        return array_values(array_reverse($this->rows, true));
    }

    public function find(int $id): ?Application
    {
        return $this->rows[$id] ?? null;
    }

    public function save(Application $application): Application
    {
        $id = $this->nextId++;
        $stored = new Application(
            $id,
            $application->name,
            $application->baseUrl,
            $application->authorizationConfirmedAt,
        );
        $this->rows[$id] = $stored;
        return $stored;
    }
}
