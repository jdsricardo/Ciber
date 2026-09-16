<?php

declare(strict_types=1);

namespace App\Domain\Model;

use App\Domain\Exception\InvalidInput;

/**
 * The 0–100 security score of one analysis.
 *
 * The rule lives here, in the domain, and nowhere else: the score starts at 100 and each
 * finding deducts its severity weight (30 / 15 / 7 / 2), clamped to 0. It is a deterministic
 * internal heuristic for comparing successive analyses of the same application — not a
 * universal measure of security and not a certification.
 */
final class SecurityScore
{
    public const MAXIMUM = 100;

    private function __construct(public readonly int $value)
    {
    }

    public static function fromInt(int $value): self
    {
        if ($value < 0 || $value > self::MAXIMUM) {
            throw new InvalidInput('A pontuação de segurança deve estar entre 0 e ' . self::MAXIMUM . '.');
        }
        return new self($value);
    }

    /** @param iterable<Finding> $findings */
    public static function fromFindings(iterable $findings): self
    {
        $penalty = 0;
        foreach ($findings as $finding) {
            $penalty += $finding->severity->weight();
        }
        return new self(max(0, self::MAXIMUM - $penalty));
    }

    /** @param iterable<array<string,mixed>> $rows rows carrying a `severity` key */
    public static function fromRows(iterable $rows): self
    {
        $penalty = 0;
        foreach ($rows as $row) {
            $severity = Severity::tryFrom((string) ($row['severity'] ?? ''));
            $penalty += $severity?->weight() ?? 0;
        }
        return new self(max(0, self::MAXIMUM - $penalty));
    }
}
