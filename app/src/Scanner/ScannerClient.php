<?php

declare(strict_types=1);

namespace App\Scanner;

use App\Config;
use RuntimeException;

final class ScannerClient
{
    public const MODE_PASSIVE = 'passive';
    public const MODE_SAFE_ACTIVE = 'safe_active';

    /**
     * Invokes the Python engine and returns its decoded JSON result.
     *
     * $sessionCookie, when provided, enables authenticated scanning: it is passed to the
     * engine as a Cookie header sent only to the authorized target. It is used transiently
     * for this run and is never persisted.
     */
    public function scan(string $url, string $mode = self::MODE_PASSIVE, string $sessionCookie = ''): array
    {
        $cmd = escapeshellarg(Config::get('python_binary')) . ' '
            . escapeshellarg(ROOT . '/scanner/scanner.py') . ' '
            . escapeshellarg($url) . ' '
            . '--mode=' . escapeshellarg($mode);
        if (Config::get('allow_private_targets')) {
            $cmd .= ' --allow-private';
        }
        if ($sessionCookie !== '') {
            $cmd .= ' --cookie=' . escapeshellarg($sessionCookie);
        }
        $output = shell_exec($cmd . ' 2>&1');
        $data = json_decode(trim((string) $output), true);
        if (!is_array($data)) {
            throw new RuntimeException('O scanner retornou uma resposta inválida. Verifique a configuração do Python.');
        }
        return $data;
    }
}
