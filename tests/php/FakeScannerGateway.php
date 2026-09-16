<?php

declare(strict_types=1);

namespace Tests\Php;

use App\Domain\Contract\ScannerGateway;
use App\Domain\Model\ScanMode;
use App\Domain\Model\ScanResult;
use App\Domain\Model\TargetUrl;

/**
 * A {@see ScannerGateway} that answers with a prepared result instead of running Python.
 * It also records what it was asked, so a test can assert that the mode and the session
 * credential reached the gateway unchanged.
 */
final class FakeScannerGateway implements ScannerGateway
{
    public ?TargetUrl $lastTarget = null;
    public ?ScanMode $lastMode = null;
    public string $lastSessionCookie = '';
    public int $calls = 0;

    public function __construct(private readonly ScanResult $result)
    {
    }

    public function scan(TargetUrl $target, ScanMode $mode, string $sessionCookie = ''): ScanResult
    {
        $this->calls++;
        $this->lastTarget = $target;
        $this->lastMode = $mode;
        $this->lastSessionCookie = $sessionCookie;
        return $this->result;
    }
}
