<?php

declare(strict_types=1);

namespace App;

final class Config
{
    private static ?array $values = null;

    public static function load(string $envFile): void
    {
        if (!is_file($envFile)) {
            http_response_code(503);
            exit('Configuração necessária: copie .env.example para .env e importe database.sql.');
        }
        foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) continue;
            [$name, $value] = array_map('trim', explode('=', $line, 2));
            if (!preg_match('/^[A-Z][A-Z0-9_]*$/', $name)) continue;
            if (strlen($value) >= 2 && (($value[0] === '"' && $value[-1] === '"') || ($value[0] === "'" && $value[-1] === "'"))) {
                $value = substr($value, 1, -1);
            }
            if (getenv($name) === false) {
                putenv($name . '=' . $value);
                $_ENV[$name] = $value;
            }
        }
        self::$values = [
            'db' => [
                'host' => self::env('DB_HOST', '127.0.0.1'),
                'port' => (int) self::env('DB_PORT', '3306'),
                'name' => self::env('DB_NAME', 'sentinelscope'),
                'user' => self::env('DB_USER'),
                'password' => self::env('DB_PASSWORD'),
                'charset' => 'utf8mb4',
            ],
            'python_binary' => self::env('PYTHON_BINARY', 'python'),
            'allow_private_targets' => self::envBool('ALLOW_PRIVATE_TARGETS'),
        ];
    }

    public static function env(string $name, ?string $default = null): string
    {
        $value = getenv($name);
        return $value === false ? ($default ?? '') : $value;
    }

    public static function envBool(string $name, bool $default = false): bool
    {
        return filter_var(self::env($name, $default ? 'true' : 'false'), FILTER_VALIDATE_BOOLEAN);
    }

    public static function get(?string $key = null): mixed
    {
        return $key === null ? self::$values : (self::$values[$key] ?? null);
    }
}
