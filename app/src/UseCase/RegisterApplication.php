<?php

declare(strict_types=1);

namespace App\UseCase;

use App\Domain\Contract\ApplicationRepository;
use App\Domain\Exception\InvalidInput;
use App\Domain\Model\Application;

/**
 * Registers an application for analysis.
 *
 * The explicit authorization checkbox is a domain precondition, not a form detail: the project
 * only ever scans targets the user states they may scan, so the use case refuses to register
 * one without it.
 */
final class RegisterApplication
{
    public function __construct(private readonly ApplicationRepository $applications)
    {
    }

    public function execute(string $name, string $baseUrl, bool $authorizationConfirmed): Application
    {
        if (!$authorizationConfirmed) {
            throw new InvalidInput('Confirme que você possui autorização para analisar este alvo.');
        }
        return $this->applications->save(Application::register($name, $baseUrl));
    }
}
