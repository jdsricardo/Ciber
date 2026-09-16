<?php

declare(strict_types=1);

namespace App\Infrastructure\Persistence;

use App\Domain\Contract\ApplicationRepository;
use App\Domain\Model\Application;
use App\Infrastructure\Database;
use DateTimeImmutable;

/** MariaDB adapter for {@see ApplicationRepository}. The only place application SQL is written. */
final class PdoApplicationRepository implements ApplicationRepository
{
    public function all(): array
    {
        $rows = Database::all(
            'SELECT a.*, COUNT(n.id) analysis_count FROM applications a
             LEFT JOIN analyses n ON n.application_id = a.id
             GROUP BY a.id ORDER BY a.created_at DESC'
        );
        return array_map(Application::fromRow(...), $rows);
    }

    public function find(int $id): ?Application
    {
        $row = Database::one('SELECT * FROM applications WHERE id=?', [$id]);
        return $row === false ? null : Application::fromRow($row);
    }

    public function save(Application $application): Application
    {
        Database::run(
            'INSERT INTO applications(name,base_url,authorization_confirmed_at) VALUES(?,?,UTC_TIMESTAMP())',
            [$application->name, $application->baseUrl->value]
        );
        return new Application(
            Database::lastInsertId(),
            $application->name,
            $application->baseUrl,
            new DateTimeImmutable('now'),
        );
    }
}
