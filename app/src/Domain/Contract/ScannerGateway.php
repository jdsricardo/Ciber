<?php

declare(strict_types=1);

namespace App\Domain\Contract;

use App\Domain\Model\ScanMode;
use App\Domain\Model\ScanResult;
use App\Domain\Model\TargetUrl;

/**
 * The scanner seen from the domain: something that, given an authorized target and a mode,
 * returns a ScanResult. That the real implementation runs a Python process is an
 * infrastructure detail this interface exists to hide.
 */
interface ScannerGateway
{
    /**
     * @param string $sessionCookie optional session credential for authenticated areas; used
     *                              only for this run and never persisted
     */
    public function scan(TargetUrl $target, ScanMode $mode, string $sessionCookie = ''): ScanResult;
}
