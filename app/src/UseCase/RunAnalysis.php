<?php

declare(strict_types=1);

namespace App\UseCase;

use App\Domain\Contract\AnalysisRepository;
use App\Domain\Contract\ApplicationRepository;
use App\Domain\Contract\FindingRepository;
use App\Domain\Contract\ScannerGateway;
use App\Domain\Contract\TransactionManager;
use App\Domain\Exception\DomainError;
use App\Domain\Exception\InvalidInput;
use App\Domain\Exception\NotFound;
use App\Domain\Model\Analysis;
use App\Domain\Model\ScanMode;
use Throwable;

/**
 * Runs the check catalogue against a registered application and stores the result.
 *
 * The order matters and is the reason this is a use case rather than a controller branch: the
 * `running` analysis is recorded *before* the scan starts, so a run that crashes or is
 * cancelled still leaves a trace instead of disappearing. On success, findings and the
 * completed analysis are written as one unit, so a history entry never shows a score that its
 * findings do not explain.
 */
final class RunAnalysis
{
    public function __construct(
        private readonly ApplicationRepository $applications,
        private readonly AnalysisRepository $analyses,
        private readonly FindingRepository $findings,
        private readonly ScannerGateway $scanner,
        private readonly TransactionManager $transactions,
    ) {
    }

    /**
     * @param bool $activeAuthorized the separate confirmation required for safe-active probing
     * @return int the identifier of the analysis, completed or failed
     */
    public function execute(
        int $applicationId,
        bool $activeRequested,
        bool $activeAuthorized,
        string $sessionCookie = '',
    ): int {
        $application = $this->applications->find($applicationId)
            ?? throw new NotFound('Aplicação não encontrada.');

        if ($activeRequested && !$activeAuthorized) {
            throw new InvalidInput('Autorize o envio de payloads de teste ativos para usar a análise completa.');
        }
        $mode = $activeRequested ? ScanMode::SafeActive : ScanMode::Passive;

        $analysis = $this->analyses->start(Analysis::start($application->requireId(), $mode));
        $analysisId = $analysis->requireId();

        try {
            $result = $this->scanner->scan($application->baseUrl, $mode, $sessionCookie);
        } catch (DomainError $error) {
            // The gateway could not deliver a result at all (the engine is unreachable, or
            // answered something unreadable). The analysis row already exists, so it is closed
            // with the reason rather than left running forever.
            $this->analyses->markFailed($analysisId, $error->getMessage());
            return $analysisId;
        } catch (Throwable $error) {
            // An unexpected failure is a defect, not an operational condition: the record is
            // still closed so the history stays consistent, and the error keeps propagating.
            $this->analyses->markFailed($analysisId, 'Falha inesperada ao executar a análise.');
            throw $error;
        }

        if (!$result->ok) {
            $this->analyses->markFailed($analysisId, (string) $result->error);
            return $analysisId;
        }

        try {
            $this->transactions->transactional(function () use ($analysisId, $result): void {
                $this->findings->saveAll($analysisId, $result->findings);
                $this->analyses->markCompleted(
                    $analysisId,
                    $result->score(),
                    $result->checksRun,
                    $result->durationMs,
                    $result->httpStatus,
                );
            });
        } catch (Throwable $error) {
            // The transaction has rolled back, so no partial findings remain; the analysis row,
            // written before it, must still be closed (contract C2). The error keeps travelling:
            // a write the database refused is a defect or an environment failure to be logged.
            $this->closeAsFailed($analysisId, 'Falha ao gravar o resultado da análise. Consulte o log do servidor.');
            throw $error;
        }

        return $analysisId;
    }

    private function closeAsFailed(int $analysisId, string $reason): void
    {
        try {
            $this->analyses->markFailed($analysisId, $reason);
        } catch (Throwable) {
            // The database that refused the findings may refuse to record the failure as well (it
            // may be down).
            // Nothing more can be recorded then; the original error, which is what explains the
            // failure, is the one the caller must see, so this one is not allowed to replace it.
        }
    }
}
