<?php

declare(strict_types=1);

namespace App\Domain\Contract;

use App\Domain\Model\Application;

/**
 * Storage of registered applications, declared by the domain and implemented outside it.
 *
 * The interface lives in the domain on purpose: the use cases depend on this name, not on PDO,
 * so the dependency arrow points inwards. The PDO adapter and the in-memory test double are
 * both just implementations of it.
 */
interface ApplicationRepository
{
    /** @return list<Application> newest first, each carrying its analysis count */
    public function all(): array;

    public function find(int $id): ?Application;

    /** Persists a new application and returns it with the identifier assigned by storage. */
    public function save(Application $application): Application;
}
