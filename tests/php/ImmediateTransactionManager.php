<?php

declare(strict_types=1);

namespace Tests\Php;

use App\Domain\Contract\TransactionManager;

/**
 * A {@see TransactionManager} that simply runs the closure. Atomicity is a property of the
 * database adapter; what the use-case tests need to check is that the work is wrapped at all.
 */
final class ImmediateTransactionManager implements TransactionManager
{
    public int $calls = 0;

    public function transactional(callable $work): mixed
    {
        $this->calls++;
        return $work();
    }
}
