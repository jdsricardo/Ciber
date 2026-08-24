<?php

declare(strict_types=1);

namespace App\Repositories;

use App\Database;

final class ApplicationRepository
{
    public function all(): array
    {
        return Database::all(
            'SELECT a.*, COUNT(n.id) analysis_count FROM applications a
             LEFT JOIN analyses n ON n.application_id = a.id
             GROUP BY a.id ORDER BY a.created_at DESC'
        );
    }

    public function find(int $id): array|false
    {
        return Database::one('SELECT * FROM applications WHERE id=?', [$id]);
    }

    public function create(string $name, string $baseUrl): int
    {
        Database::run(
            'INSERT INTO applications(name,base_url,authorization_confirmed_at) VALUES(?,?,UTC_TIMESTAMP())',
            [$name, $baseUrl]
        );
        return Database::lastInsertId();
    }
}
