<?php

declare(strict_types=1);

namespace App\Domain\Model;

/**
 * Which pages of the target an analysis actually covered, and which it found but left out.
 *
 * A scan that silently skips part of a site looks exactly like a scan of a site with fewer
 * problems. Recording the analysed pages, the pages left out (page limit, depth or budget) and
 * how many variants of one template were deliberately not repeated lets the user judge how much
 * of the application the result speaks for (limitation L-06 of the final report).
 */
final class CrawlCoverage
{
    /**
     * @param list<string> $analysedUrls pages that went through every check, in visiting order
     * @param int $notVisitedCount pages discovered in scope but not analysed
     * @param list<string> $notVisitedUrls the first of those pages, as reported by the engine
     * @param int $templateVariantsSkipped variants recognised as one template already analysed
     * @param int $scriptsRead script files read for the URLs they call
     */
    public function __construct(
        public readonly array $analysedUrls,
        public readonly int $notVisitedCount = 0,
        public readonly array $notVisitedUrls = [],
        public readonly int $templateVariantsSkipped = 0,
        public readonly int $scriptsRead = 0,
    ) {
    }

    public function pagesAnalysed(): int
    {
        return count($this->analysedUrls);
    }

    /**
     * Reads the coverage fields of the engine's JSON document (contract §3.1). Missing fields —
     * an engine older than these fields — give empty, zero values.
     *
     * @param array<string,mixed> $payload
     */
    public static function fromEnginePayload(array $payload): self
    {
        return new self(
            self::strings($payload['crawled_urls'] ?? []),
            max(0, (int) ($payload['pages_not_visited'] ?? 0)),
            self::strings($payload['not_visited_urls'] ?? []),
            max(0, (int) ($payload['template_variants_skipped'] ?? 0)),
            max(0, (int) ($payload['scripts_read'] ?? 0)),
        );
    }

    public function toJson(): string
    {
        return (string) json_encode([
            'analysed_urls' => $this->analysedUrls,
            'not_visited_count' => $this->notVisitedCount,
            'not_visited_urls' => $this->notVisitedUrls,
            'template_variants_skipped' => $this->templateVariantsSkipped,
            'scripts_read' => $this->scriptsRead,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /** The stored form; null for analyses recorded before coverage was kept. */
    public static function fromJson(?string $json): ?self
    {
        $data = $json === null || $json === '' ? null : json_decode($json, true);
        if (!is_array($data)) {
            return null;
        }
        return new self(
            self::strings($data['analysed_urls'] ?? []),
            max(0, (int) ($data['not_visited_count'] ?? 0)),
            self::strings($data['not_visited_urls'] ?? []),
            max(0, (int) ($data['template_variants_skipped'] ?? 0)),
            max(0, (int) ($data['scripts_read'] ?? 0)),
        );
    }

    /** @return list<string> */
    private static function strings(mixed $values): array
    {
        if (!is_array($values)) {
            return [];
        }
        return array_values(array_map('strval', array_filter($values, 'is_scalar')));
    }
}
