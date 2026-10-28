<?php

declare(strict_types=1);

namespace Tests\Php;

use App\Domain\Contract\TransactionManager;
use RuntimeException;

/**
 * A {@see TransactionManager} whose work never commits: it runs nothing and fails the way a
 * database does when it rejects a write (lost connection, revoked privilege, value too long).
 * Used to check that a failure while storing a result still closes the analysis.
 */
final class FailingTransactionManager implements TransactionManager
{
    public int $calls = 0;

    public function transactional(callable $work): mixed
    {
        $this->calls++;
        throw new RuntimeException('SQLSTATE[42000]: INSERT command denied to user');
    }
}
