<?php

declare(strict_types=1);

namespace App\Domain\Exception;

/** A value rejected by a constructor or a domain rule: the caller sent something invalid. */
final class InvalidInput extends DomainError
{
    public function httpStatus(): int
    {
        return 400;
    }
}
