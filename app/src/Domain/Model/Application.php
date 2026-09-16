<?php

declare(strict_types=1);

namespace App\Domain\Model;

use App\Domain\Exception\InvalidInput;
use DateTimeImmutable;

/**
 * An application registered for analysis. Registering one is an explicit statement of
 * authorization, so an Application cannot be constructed without the moment that authorization
 * was confirmed.
 */
final class Application
{
    public const MAX_NAME_LENGTH = 120;

    /** @param int|null $id null until the repository has persisted it */
    public function __construct(
        public readonly ?int $id,
        public readonly string $name,
        public readonly TargetUrl $baseUrl,
        public readonly DateTimeImmutable $authorizationConfirmedAt,
        public readonly int $analysisCount = 0,
    ) {
        if (trim($name) === '') {
            throw new InvalidInput('Informe o nome da aplicação.');
        }
        if (mb_strlen($name) > self::MAX_NAME_LENGTH) {
            throw new InvalidInput('O nome da aplicação deve ter no máximo ' . self::MAX_NAME_LENGTH . ' caracteres.');
        }
        if ($id !== null && $id <= 0) {
            throw new InvalidInput('Identificador de aplicação inválido.');
        }
        if ($analysisCount < 0) {
            throw new InvalidInput('A contagem de análises não pode ser negativa.');
        }
    }

    /** Factory for a not-yet-persisted application, confirming authorization at this instant. */
    public static function register(string $name, string $baseUrl): self
    {
        return new self(null, trim($name), TargetUrl::fromString($baseUrl), new DateTimeImmutable('now'));
    }

    /** @param array<string,mixed> $row a persisted row */
    public static function fromRow(array $row): self
    {
        return new self(
            (int) $row['id'],
            (string) $row['name'],
            TargetUrl::fromString((string) $row['base_url']),
            new DateTimeImmutable((string) ($row['authorization_confirmed_at'] ?? 'now')),
            (int) ($row['analysis_count'] ?? 0),
        );
    }

    /** The persisted identifier, for callers that only make sense after the entity was stored. */
    public function requireId(): int
    {
        return $this->id ?? throw new InvalidInput('A aplicação ainda não foi persistida.');
    }
}
