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
 * Runs the Python engine as a child process and turns its JSON answer into a ScanResult,
 * following docs/INTEGRATION_CONTRACT.md.
 *
 * The process is started from an argument list, never through a shell: no user-supplied value
 * can extend the command line (rule R2), and the URL and session cookie reach the engine byte for
 * byte (rule R1) — escapeshellarg() on Windows replaces `%`, `!` and `"` with spaces, which
 * silently changed percent-encoded URLs and cookie values.
 *
 * Standard output and standard error go to two temporary files rather than to pipes. On Windows
 * PHP cannot wait on a pipe with a timeout, and a full stderr pipe would block the engine; with
 * files the gateway can poll the process, enforce its own deadline, and still read only stdout as
 * the document (§1 framing). A reply that is not decodable JSON is reported as ScannerUnavailable
 * rather than as an empty scan — an empty scan and a broken scanner must never look the same.
 */
final class PythonScannerGateway implements ScannerGateway
{
    /**
     * The engine's own global time budget per mode (`global_timeout_seconds` of PASSIVE_LIMITS and
     * ACTIVE_LIMITS in scanner/engine/runner.py), plus the start-up and serialization margin.
     */
    private const DEADLINE_SECONDS = ['passive' => 180 + 30, 'safe_active' => 600 + 30];

    private const POLL_MICROSECONDS = 100_000;

    public function scan(TargetUrl $target, ScanMode $mode, string $sessionCookie = ''): ScanResult
    {
        $deadline = self::DEADLINE_SECONDS[$mode->value] ?? self::DEADLINE_SECONDS['safe_active'];

        // On Windows max_execution_time counts wall-clock time, including the wait for the engine,
        // so the default 120 s killed long analyses midway and left them running (contract C5).
        // The request is given the engine's deadline plus time to store the result, and it keeps
        // going if the browser disconnects, so the analysis is always closed.
        set_time_limit($deadline + 60);
        ignore_user_abort(true);

        $output = tempnam(sys_get_temp_dir(), 'ssout');
        $errors = tempnam(sys_get_temp_dir(), 'sserr');
        try {
            $process = @proc_open(
                self::command($target, $mode, $sessionCookie, (bool) Config::get('allow_private_targets')),
                [1 => ['file', $output, 'w'], 2 => ['file', $errors, 'w']],
                $pipes,
                null,
                null,
                ['bypass_shell' => true],
            );
            if (!is_resource($process)) {
                throw new ScannerUnavailable(
                    'O scanner retornou uma resposta inválida. Verifique a configuração do Python.'
                );
            }

            $started = microtime(true);
            while (proc_get_status($process)['running']) {
                if (microtime(true) - $started > $deadline) {
                    proc_terminate($process);
                    proc_close($process);
                    throw new ScannerUnavailable(
                        'A análise excedeu o tempo máximo de ' . $deadline . ' segundos e foi interrompida.'
                    );
                }
                usleep(self::POLL_MICROSECONDS);
            }
            proc_close($process);

            $payload = json_decode(trim((string) file_get_contents($output)), true);
        } finally {
            // The document can carry evidence copied from the target; it lives only as long as
            // this request.
            @unlink($output);
            @unlink($errors);
        }

        if (!is_array($payload)) {
            throw new ScannerUnavailable(
                'O scanner retornou uma resposta inválida. Verifique a configuração do Python.'
            );
        }
        return ScanResult::fromEnginePayload($payload);
    }

    /**
     * The engine's argument list (contract §2.1). Public so the argument rules can be tested
     * without starting a process.
     *
     * @return list<string>
     */
    public static function command(TargetUrl $target, ScanMode $mode, string $sessionCookie, bool $allowPrivate): array
    {
        $command = [
            (string) Config::get('python_binary'),
            ROOT . '/scanner/scanner.py',
            $target->value,
            '--mode=' . $mode->value,
        ];
        if ($allowPrivate) {
            $command[] = '--allow-private';
        }
        if ($sessionCookie !== '') {
            $command[] = '--cookie=' . $sessionCookie;
        }
        return $command;
    }
}
