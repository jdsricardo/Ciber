<?php

declare(strict_types=1);

namespace App\Domain\Exception;

/** A record the caller referenced does not exist (or is not visible to them). */
final class NotFound extends DomainError
{
    public function httpStatus(): int
    {
        return 404;
    }
}
