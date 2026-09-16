<?php

declare(strict_types=1);

namespace App\Domain\Model;

use App\Domain\Exception\InvalidInput;

/**
 * Passive observes responses only. Safe-active additionally sends bounded, non-destructive
 * probes to discovered parameters, and therefore requires an explicit extra authorization.
 */
enum ScanMode: string
{
    case Passive = 'passive';
    case SafeActive = 'safe_active';

    public static function fromString(string $value): self
    {
        return self::tryFrom($value)
            ?? throw new InvalidInput('Modo de análise desconhecido: ' . $value . '.');
    }

    public function label(): string
    {
        return match ($this) {
            self::Passive => 'Passiva',
            self::SafeActive => 'Completa (ativa)',
        };
    }
}
