<?php

declare(strict_types=1);

/**
 * Web runtime bootstrap: autoloading, configuration, session. Everything that a request needs
 * and a unit test does not. Tests load app/autoload.php directly instead.
 */

require __DIR__ . '/autoload.php';

use App\Infrastructure\Config;
use App\Presentation\Html;

// A fatal error must never print a file path or a stack trace to the browser, whatever the
// php.ini of the host says (XAMPP ships display_errors=On). The detail still goes to the log.
ini_set('display_errors', '0');
ini_set('log_errors', '1');

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
