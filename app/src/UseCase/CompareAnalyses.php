<?php

declare(strict_types=1);

namespace App\UseCase;

use App\Domain\Contract\AnalysisRepository;
use App\Domain\Contract\FindingRepository;
use App\Domain\Exception\InvalidInput;
use App\Domain\Exception\NotFound;
use App\Domain\Model\Analysis;
use App\Domain\Service\AnalysisComparison;

/**
 * Answers "what changed between these two analyses?" — the question that turns a list of
 * findings into feedback on a fix.
 */
final class CompareAnalyses
{
    public function __construct(
        private readonly AnalysisRepository $analyses,
        private readonly FindingRepository $findings,
    ) {
    }

    /**
     * @return array{older:Analysis,newer:Analysis,new:array<string,array<string,mixed>>,persistent:array<string,array<string,mixed>>,fixed:array<string,array<string,mixed>>}
     */
    public function execute(int $olderId, int $newerId): array
    {
        $older = $this->analyses->find($olderId) ?? throw new NotFound('Análise não encontrada.');
        $newer = $this->analyses->find($newerId) ?? throw new NotFound('Análise não encontrada.');
        if (!$older->isComparableWith($newer)) {
            throw new InvalidInput('Escolha duas análises da mesma aplicação.');
        }

        $diff = AnalysisComparison::diff(
            self::toRows($this->findings->byAnalysis($older->requireId())),
            self::toRows($this->findings->byAnalysis($newer->requireId())),
        );

        return ['older' => $older, 'newer' => $newer] + $diff;
    }

    /**
     * @param list<\App\Domain\Model\Finding> $findings
     * @return array<int,array<string,mixed>>
     */
    private static function toRows(array $findings): array
    {
        return array_map(
            static fn($finding): array => [
                'fingerprint' => $finding->fingerprint,
                'title' => $finding->title,
                'severity' => $finding->severity->value,
            ],
            $findings,
        );
    }
}
