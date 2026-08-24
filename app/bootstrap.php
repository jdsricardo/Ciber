<?php

declare(strict_types=1);

const ROOT = __DIR__ . '/..';

spl_autoload_register(function (string $class): void {
    if (!str_starts_with($class, 'App\\')) {
        return;
    }
    $relative = substr($class, strlen('App\\'));
    $path = ROOT . '/app/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

use App\Config;

Config::load(ROOT . '/.env');
date_default_timezone_set('UTC');
session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Lax', 'use_strict_mode' => true]);

/** Thin view-layer sugar; all real logic lives in App\* classes under app/src/. */
function e(mixed $value): string
{
    return \App\Support\Html::escape($value);
}

function go(string $url): never
{
    header('Location: ' . $url);
    exit;
}
