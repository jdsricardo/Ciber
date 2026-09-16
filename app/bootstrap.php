<?php

declare(strict_types=1);

/**
 * Web runtime bootstrap: autoloading, configuration, session. Everything that a request needs
 * and a unit test does not. Tests load app/autoload.php directly instead.
 */

require __DIR__ . '/autoload.php';

use App\Infrastructure\Config;
use App\Presentation\Html;

Config::load(ROOT . '/.env');
date_default_timezone_set('UTC');
session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Lax', 'use_strict_mode' => true]);

/** Thin view-layer sugar; all real logic lives in App\* classes under app/src/. */
function e(mixed $value): string
{
    return Html::escape($value);
}

function go(string $url): never
{
    header('Location: ' . $url);
    exit;
}
