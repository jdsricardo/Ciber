<?php

declare(strict_types=1);

namespace App\Infrastructure\Persistence;

use App\Domain\Contract\FindingRepository;
use App\Domain\Model\Finding;
use App\Infrastructure\Database;

/** MariaDB adapter for {@see FindingRepository}. The only place finding SQL is written. */
final class PdoFindingRepository implements FindingRepository
{
    public function byAnalysis(int $analysisId): array
    {
        // Served by idx_finding_analysis (analysis_id). The severity ordering is expressed in
        // SQL rather than in PHP so the report of a large analysis is ordered before it is
        // materialised, not after.
        $rows = Database::all(
            "SELECT * FROM findings WHERE analysis_id=?
             ORDER BY FIELD(severity,'critical','high','medium','low'),title",
            [$analysisId]
        );
        return array_map(Finding::fromRow(...), $rows);
    }

    public function saveAll(int $analysisId, array $findings): void
    {
        // One prepared statement, executed once per finding: the statement is parsed a single
        // time and each execution only sends the parameters. The use case wraps this call in a
        // transaction, so an analysis is never left with a partial set of findings.
        $insert = Database::pdo()->prepare(
            'INSERT INTO findings(
                analysis_id,fingerprint,title,category,cwe,owasp,wstg,severity,confidence,status,
                description,evidence_summary,affected_url,method,parameter,parameter_location,
                evidence,developer_impact,remediation,manual_review_required,
                remediation_example_vulnerable,remediation_example_fixed,
                remediation_example_language,remediation_example_note
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
        );
        foreach ($findings as $finding) {
            $insert->execute([
                $analysisId,
                $finding->fingerprint,
                $finding->title,
                $finding->category,
                $finding->cwe,
                $finding->owasp,
                $finding->wstg,
                $finding->severity->value,
                $finding->confidence,
                $finding->status,
                $finding->description,
                $finding->evidenceSummary,
                $finding->affectedUrl,
                $finding->method,
                $finding->parameter,
                $finding->parameterLocation,
                json_encode($finding->evidence, JSON_UNESCAPED_SLASHES),
                $finding->developerImpact,
                $finding->remediation,
                $finding->manualReviewRequired ? 1 : 0,
                $finding->example?->vulnerable,
                $finding->example?->fixed,
                $finding->example?->language,
                $finding->example?->note,
            ]);
        }
    }
}
