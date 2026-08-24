<?php

declare(strict_types=1);

namespace App\Support;

final class Scoring
{
    private const WEIGHTS = ['critical' => 30, 'high' => 15, 'medium' => 7, 'low' => 2];

    public static function calculate(array $findings): int
    {
        $penalty = 0;
        foreach ($findings as $finding) {
            $penalty += self::WEIGHTS[$finding['severity']] ?? 0;
        }
        return max(0, 100 - $penalty);
    }
}
