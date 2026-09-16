<?php

declare(strict_types=1);

/**
 * Maps the `App\` namespace to `app/src/`. Kept separate from bootstrap.php so that tests and
 * command-line tools can load the domain without starting a web session or requiring a `.env`.
 */

if (!defined('ROOT')) {
    define('ROOT', dirname(__DIR__));
}

spl_autoload_register(static function (string $class): void {
    if (!str_starts_with($class, 'App\\')) {
        return;
    }
    $relative = substr($class, strlen('App\\'));
    $path = ROOT . '/app/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require $path;
    }
});
