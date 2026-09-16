<?php

declare(strict_types=1);

namespace App\Domain\Model;

use App\Domain\Exception\InvalidInput;

/** Lifecycle of one analysis. An analysis is created running and ends completed or failed. */
enum AnalysisStatus: string
{
    case Running = 'running';
    case Completed = 'completed';
    case Failed = 'failed';

    public static function fromString(string $value): self
    {
        return self::tryFrom($value)
            ?? throw new InvalidInput('Status de análise desconhecido: ' . $value . '.');
    }
}
