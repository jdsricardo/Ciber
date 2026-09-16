<?php

declare(strict_types=1);

namespace App\Domain\Exception;

use RuntimeException;

/**
 * Base of every error the domain raises on its own terms.
 *
 * Error convention of the project:
 *  - the domain throws only DomainError subclasses, never generic exceptions, and never
 *    returns null or false to signal a rule violation;
 *  - the message is written for the developer using the application (Portuguese, no stack
 *    trace, no SQL, no internal identifiers), because it is shown in the interface;
 *  - `httpStatus()` is the only transport knowledge the domain carries, so the presentation
 *    layer can translate an error into a response without a table of `instanceof` checks;
 *  - infrastructure failures (PDO, network, the Python process) are not domain errors: they
 *    are wrapped by the adapter that produced them into the matching DomainError subclass.
 */
abstract class DomainError extends RuntimeException
{
    abstract public function httpStatus(): int;
}
