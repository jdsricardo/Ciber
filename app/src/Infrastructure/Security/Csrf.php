<?php

declare(strict_types=1);

namespace App\Infrastructure\Security;

use App\Domain\Exception\InvalidInput;

/**
 * Session-bound token required by every state-changing request (NFR-02).
 *
 * A mismatch is reported as an InvalidInput so it travels through the same error convention as
 * any other rejected input, instead of surfacing as a generic runtime failure.
 */
final class Csrf
{
    public static function token(): string
    {
        return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
    }

    public static function check(): void
    {
        if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) {
            throw new InvalidInput('Seu token de sessão expirou. Atualize a página e tente novamente.');
        }
    }
}
