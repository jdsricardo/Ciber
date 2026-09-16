<?php

declare(strict_types=1);

namespace App\Domain\Model;

use App\Domain\Exception\InvalidInput;

/**
 * The address of an application authorized for analysis. Validating here — and only here —
 * means no other layer has to re-check what a target URL may be: an object of this type
 * cannot exist in an invalid state.
 */
final class TargetUrl
{
    private const MAX_LENGTH = 2048;

    private function __construct(public readonly string $value)
    {
    }

    public static function fromString(string $value): self
    {
        $value = trim($value);
        if ($value === '') {
            throw new InvalidInput('Informe a URL da aplicação.');
        }
        if (strlen($value) > self::MAX_LENGTH) {
            throw new InvalidInput('A URL informada excede ' . self::MAX_LENGTH . ' caracteres.');
        }
        if (filter_var($value, FILTER_VALIDATE_URL) === false) {
            throw new InvalidInput('Informe uma URL válida.');
        }
        $scheme = strtolower((string) parse_url($value, PHP_URL_SCHEME));
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new InvalidInput('A URL deve usar o esquema HTTP ou HTTPS.');
        }
        if (parse_url($value, PHP_URL_USER) !== null || parse_url($value, PHP_URL_PASS) !== null) {
            throw new InvalidInput('A URL não pode conter credenciais embutidas.');
        }
        return new self($value);
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
