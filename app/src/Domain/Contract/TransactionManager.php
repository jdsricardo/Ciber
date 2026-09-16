<?php

declare(strict_types=1);

namespace App\Domain\Contract;

/**
 * "Do all of this or none of it", expressed without naming a database.
 *
 * Storing an analysis and its findings must be atomic, and that rule belongs to the use case,
 * not to the PDO adapter. The use case therefore depends on this interface; the adapter maps
 * it onto a real transaction and the test double simply runs the closure.
 */
interface TransactionManager
{
    /**
     * @template T
     * @param callable():T $work
     * @return T
     */
    public function transactional(callable $work): mixed;
}
