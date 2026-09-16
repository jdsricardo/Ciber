<?php

declare(strict_types=1);

namespace App\Domain\Model;

/**
 * The concrete "vulnerable → fixed" pair shown with a finding. It is a value object rather
 * than four loose strings on Finding, so "does this finding have an example?" is one question
 * with one answer instead of a condition repeated in every consumer.
 */
final class RemediationExample
{
    public function __construct(
        public readonly string $vulnerable = '',
        public readonly string $fixed = '',
        public readonly string $language = '',
        public readonly string $note = '',
    ) {
    }

    /** @param array<string,mixed> $row */
    public static function fromRow(array $row): ?self
    {
        $example = new self(
            (string) ($row['remediation_example_vulnerable'] ?? ''),
            (string) ($row['remediation_example_fixed'] ?? ''),
            (string) ($row['remediation_example_language'] ?? ''),
            (string) ($row['remediation_example_note'] ?? ''),
        );
        return $example->isEmpty() ? null : $example;
    }

    public function isEmpty(): bool
    {
        return $this->vulnerable === '' && $this->fixed === '';
    }
}
