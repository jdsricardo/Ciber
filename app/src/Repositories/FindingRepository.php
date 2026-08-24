<?php

declare(strict_types=1);

namespace App\Repositories;

use App\Database;

final class FindingRepository
{
    public function byAnalysis(int $analysisId): array
    {
        return Database::all(
            "SELECT * FROM findings WHERE analysis_id=? ORDER BY FIELD(severity,'critical','high','medium','low'),title",
            [$analysisId]
        );
    }

    /** @param array<int,array<string,mixed>> $findings decoded finding objects from the Python engine */
    public function insertMany(int $analysisId, array $findings): void
    {
        $insert = Database::pdo()->prepare(
            'INSERT INTO findings(
                analysis_id,fingerprint,title,category,cwe,owasp,wstg,severity,confidence,status,
                description,evidence_summary,affected_url,method,parameter,parameter_location,
                evidence,developer_impact,remediation,manual_review_required
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
        );
        foreach ($findings as $f) {
            $insert->execute([
                $analysisId,
                $f['fingerprint'],
                $f['title'],
                $f['category'] ?? null,
                $f['cwe'] ?? null,
                $f['owasp'] ?? null,
                $f['wstg'] ?? null,
                $f['severity'],
                $f['confidence'] ?? null,
                $f['status'] ?? null,
                $f['description'] ?? null,
                $f['evidence_summary'] ?? null,
                $f['affected_url'],
                $f['method'] ?? null,
                $f['parameter'] ?? null,
                $f['parameter_location'] ?? null,
                json_encode($f['evidence'] ?? [], JSON_UNESCAPED_SLASHES),
                $f['developer_impact'],
                $f['remediation'],
                !empty($f['manual_review_required']) ? 1 : 0,
            ]);
        }
    }
}
