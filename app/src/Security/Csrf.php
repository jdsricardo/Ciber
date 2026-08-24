<?php

declare(strict_types=1);

namespace App\Security;

use RuntimeException;

final class Csrf
{
    public static function token(): string
    {
        return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
    }

    public static function check(): void
    {
        if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) {
            throw new RuntimeException('Seu token de sessão expirou. Atualize a página e tente novamente.');
        }
    }
}
