<?php

declare(strict_types=1);

namespace App\Infrastructure\Persistence;

use App\Domain\Contract\TransactionManager;
use App\Infrastructure\Database;

/** Maps the domain's "all or nothing" onto a real database transaction. */
final class PdoTransactionManager implements TransactionManager
{
    public function transactional(callable $work): mixed
    {
        return Database::transaction($work);
    }
}
