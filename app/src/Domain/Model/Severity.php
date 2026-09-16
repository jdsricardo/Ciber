<?php

declare(strict_types=1);

namespace App\Domain\Model;

use App\Domain\Exception\InvalidInput;

/**
 * How bad a finding would be if it is real. Deliberately separate from confidence, which
 * answers how sure the detector is — a critical finding with weak evidence stays critical.
 */
enum Severity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';

    public static function fromString(string $value): self
    {
        return self::tryFrom($value)
            ?? throw new InvalidInput('Severidade desconhecida: ' . $value . '.');
    }

    /** Points deducted from the security score by one finding of this severity. */
    public function weight(): int
    {
        return match ($this) {
            self::Critical => 30,
            self::High => 15,
            self::Medium => 7,
            self::Low => 2,
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Critical => 'CRÍTICO',
            self::High => 'ALTO',
            self::Medium => 'MÉDIO',
            self::Low => 'BAIXO',
        };
    }

    /** Report order: the most severe first. */
    public function rank(): int
    {
        return match ($this) {
            self::Critical => 0,
            self::High => 1,
            self::Medium => 2,
            self::Low => 3,
        };
    }
}
