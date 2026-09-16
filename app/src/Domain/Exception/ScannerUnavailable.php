<?php

declare(strict_types=1);

namespace App\Domain\Exception;

/**
 * The scanner gateway could not be reached or answered something the domain cannot read.
 * Raised by the infrastructure adapter, declared here so the domain owns its own vocabulary.
 */
final class ScannerUnavailable extends DomainError
{
    public function httpStatus(): int
    {
        return 502;
    }
}
