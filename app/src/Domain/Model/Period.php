<?php

declare(strict_types=1);

namespace App\Domain\Model;

use App\Domain\Exception\InvalidInput;
use DateTimeImmutable;
use DateTimeZone;

/**
 * A range of calendar days, in UTC, used to consult the history of an application by period
 * (Termo de Referência, item 6). Both ends are inclusive and either may be open: a period with
 * no start means "since the first analysis", one with no end means "until now".
 *
 * Validation happens here, so a reversed or malformed period cannot reach a repository.
 */
final class Period
{
    private function __construct(
        public readonly ?DateTimeImmutable $from,
        public readonly ?DateTimeImmutable $to,
    ) {
    }

    /** Builds a period from two `YYYY-MM-DD` strings; an empty string leaves that end open. */
    public static function fromStrings(string $from, string $to): self
    {
        $start = self::parseDay($from);
        $end = self::parseDay($to);
        if ($start !== null && $end !== null && $start > $end) {
            throw new InvalidInput('A data inicial deve ser anterior ou igual à data final.');
        }
        return new self($start, $end);
    }

    public static function unbounded(): self
    {
        return new self(null, null);
    }

    public function isUnbounded(): bool
    {
        return $this->from === null && $this->to === null;
    }

    /** First instant inside the period, or null when the start is open. */
    public function startsAt(): ?DateTimeImmutable
    {
        return $this->from;
    }

    /** First instant *after* the period (the day after `to`), or null when the end is open. */
    public function endsBefore(): ?DateTimeImmutable
    {
        return $this->to?->modify('+1 day');
    }

    public function contains(DateTimeImmutable $instant): bool
    {
        $start = $this->startsAt();
        $end = $this->endsBefore();
        return ($start === null || $instant >= $start) && ($end === null || $instant < $end);
    }

    private static function parseDay(string $value): ?DateTimeImmutable
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }
        $day = DateTimeImmutable::createFromFormat('!Y-m-d', $value, new DateTimeZone('UTC'));
        // The round trip rejects what createFromFormat silently normalises, such as 2026-02-31.
        if ($day === false || $day->format('Y-m-d') !== $value) {
            throw new InvalidInput('Informe as datas no formato AAAA-MM-DD.');
        }
        return $day;
    }
}
