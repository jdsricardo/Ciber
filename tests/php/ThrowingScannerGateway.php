<?php

declare(strict_types=1);

namespace Tests\Php;

use App\Domain\Contract\ScannerGateway;
use App\Domain\Model\ScanMode;
use App\Domain\Model\ScanResult;
use App\Domain\Model\TargetUrl;
use Throwable;

/**
 * A {@see ScannerGateway} that fails instead of answering, so the use case can be tested for
 * what it does when the engine is unreachable — not only for what it does when the engine
 * reports a failed scan.
 */
final class ThrowingScannerGateway implements ScannerGateway
{
    public function __construct(private readonly Throwable $error)
    {
    }

    public function scan(TargetUrl $target, ScanMode $mode, string $sessionCookie = ''): ScanResult
    {
        throw $this->error;
    }
}
