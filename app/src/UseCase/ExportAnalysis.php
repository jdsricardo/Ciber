<?php

declare(strict_types=1);

namespace App\UseCase;

use App\Domain\Contract\AnalysisRepository;
use App\Domain\Contract\FindingRepository;
use App\Domain\Exception\NotFound;
use App\Domain\Model\Analysis;
use App\Domain\Model\Finding;

/**
 * Builds the machine-readable (JSON) representation of a completed analysis and its findings,
 * for CI pipelines or ticketing. It owns no I/O: it returns the document, and the caller
 * decides what to do with it.
 */
final class ExportAnalysis
{
    public function __construct(
        private readonly AnalysisRepository $analyses,
        private readonly FindingRepository $findings,
    ) {
    }

    /** @return array<string,mixed> JSON-serializable document */
    public function execute(int $analysisId): array
    {
        $analysis = $this->analyses->find($analysisId) ?? throw new NotFound('Análise não encontrada.');
        return self::document($analysis, $this->findings->byAnalysis($analysis->requireId()));
    }

    /**
     * @param list<Finding> $findings
     * @return array<string,mixed>
     */
    public static function document(Analysis $analysis, array $findings): array
    {
        return [
            'tool' => 'SentinelScope',
            'analysis' => [
                'id' => $analysis->requireId(),
                'application' => $analysis->applicationName,
                'base_url' => $analysis->baseUrl?->value,
                'mode' => $analysis->mode->value,
                'status' => $analysis->status->value,
                'security_score' => $analysis->score?->value,
                'checks_run' => $analysis->checksRun,
                'http_status' => $analysis->httpStatus,
                'duration_ms' => $analysis->durationMs,
                'started_at' => $analysis->startedAt->format('Y-m-d H:i:s'),
                'completed_at' => $analysis->completedAt?->format('Y-m-d H:i:s'),
            ],
            'summary' => ['findings' => count($findings)],
            'findings' => array_map([self::class, 'mapFinding'], $findings),
        ];
    }

    /** @return array<string,mixed> */
    private static function mapFinding(Finding $finding): array
    {
        return [
            'fingerprint' => $finding->fingerprint,
            'title' => $finding->title,
            'category' => $finding->category,
            'severity' => $finding->severity->value,
            'confidence' => $finding->confidence,
            'status' => $finding->status,
            'cwe' => $finding->cwe,
            'owasp' => $finding->owasp,
            'wstg' => $finding->wstg,
            'affected_url' => $finding->affectedUrl,
            'method' => $finding->method,
            'parameter' => $finding->parameter,
            'parameter_location' => $finding->parameterLocation,
            'manual_review_required' => $finding->manualReviewRequired,
            'observed' => $finding->observed(),
            'developer_impact' => $finding->developerImpact,
            'remediation' => $finding->remediation,
            'remediation_example' => [
                'language' => $finding->example?->language,
                'vulnerable' => $finding->example?->vulnerable,
                'fixed' => $finding->example?->fixed,
                'note' => $finding->example?->note,
            ],
            'evidence' => $finding->evidence,
        ];
    }
}
