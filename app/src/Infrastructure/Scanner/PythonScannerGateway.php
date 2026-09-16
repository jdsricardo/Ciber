<?php

declare(strict_types=1);

namespace App\Infrastructure\Scanner;

use App\Domain\Contract\ScannerGateway;
use App\Domain\Exception\ScannerUnavailable;
use App\Domain\Model\ScanMode;
use App\Domain\Model\ScanResult;
use App\Domain\Model\TargetUrl;
use App\Infrastructure\Config;

/**
 * Runs the Python engine as a child process and turns its JSON answer into a ScanResult.
 *
 * Every argument is passed through escapeshellarg, so no user-supplied value can extend the
 * command line. A reply that is not decodable JSON is an infrastructure failure and is
 * reported as ScannerUnavailable rather than as an empty scan — an empty scan and a broken
 * scanner must never look the same to the user.
 */
final class PythonScannerGateway implements ScannerGateway
{
    public function scan(TargetUrl $target, ScanMode $mode, string $sessionCookie = ''): ScanResult
    {
        $command = escapeshellarg((string) Config::get('python_binary')) . ' '
            . escapeshellarg(ROOT . '/scanner/scanner.py') . ' '
            . escapeshellarg($target->value) . ' '
            . '--mode=' . escapeshellarg($mode->value);
        if (Config::get('allow_private_targets')) {
            $command .= ' --allow-private';
        }
        if ($sessionCookie !== '') {
            $command .= ' --cookie=' . escapeshellarg($sessionCookie);
        }

        $output = shell_exec($command . ' 2>&1');
        $payload = json_decode(trim((string) $output), true);
        if (!is_array($payload)) {
            throw new ScannerUnavailable(
                'O scanner retornou uma resposta inválida. Verifique a configuração do Python.'
            );
        }
        return ScanResult::fromEnginePayload($payload);
    }
}
