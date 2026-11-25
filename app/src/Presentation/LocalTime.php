<?php

declare(strict_types=1);

namespace App\Presentation;

use DateTimeImmutable;
use DateTimeZone;

/**
 * Shows stored instants in the user's time zone. The database and the export keep UTC (one clock
 * for every timestamp, D-07); only what a person reads is converted. The zone comes from
 * APP_TIMEZONE (default America/Sao_Paulo).
 */
final class LocalTime
{
    private static ?DateTimeZone $zone = null;

    public static function useZone(string $name): void
    {
        try {
            self::$zone = new DateTimeZone($name !== '' ? $name : 'America/Sao_Paulo');
        } catch (\Exception) {
            self::$zone = new DateTimeZone('UTC');
        }
    }

    public static function zone(): DateTimeZone
    {
        return self::$zone ??= new DateTimeZone('America/Sao_Paulo');
    }

    /** Plain text, e.g. for an <option>: `25/11/2026 17:40:21`. */
    public static function text(DateTimeImmutable $instant): string
    {
        return $instant->setTimezone(self::zone())->format('d/m/Y H:i:s');
    }

    /** A <time> element: local text for people, the UTC instant in `datetime` for machines. */
    public static function html(DateTimeImmutable $instant): string
    {
        $utc = $instant->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
        return '<time datetime="' . $utc . '">' . self::text($instant) . '</time>';
    }
}
