<?php

declare(strict_types=1);

namespace App\Presentation;

use App\Domain\Model\Finding;
use App\Domain\Model\RemediationExample;
use App\Domain\Model\Severity;

/**
 * Renders one Finding as HTML. It reads the entity and produces markup — it decides nothing
 * about security, so a change in how a finding is judged never has to be made here as well.
 */
final class FindingPresenter
{
    private const STATUS_LABELS = [
        'confirmed' => 'Confirmado',
        'high_confidence' => 'Alta Confiança',
        'probable' => 'Provável',
        'possible' => 'Possível',
        'informational' => 'Informativo',
        'manual_review_required' => 'Revisão Manual Necessária',
    ];

    public static function severityLabel(Severity $severity): string
    {
        return $severity->label();
    }

    public static function statusLabel(string $status): string
    {
        return self::STATUS_LABELS[$status] ?? ucwords(str_replace('_', ' ', $status));
    }

    public static function render(Finding $finding): string
    {
        return '<article class="finding" data-severity="' . Html::escape($finding->severity->value) . '">'
            . '<div class="finding-title">'
            . '<span class="severity ' . Html::escape($finding->severity->value) . '">'
            . Html::escape($finding->severity->label()) . '</span>'
            . self::statusBadge($finding)
            . self::manualBadge($finding)
            . '<h3>' . Html::escape($finding->title) . '</h3></div>'
            . '<p class="location-line">' . self::location($finding) . '</p>'
            . '<div class="explain">'
            . '<p><b>O que o scanner observou</b><br>' . Html::escape($finding->observed()) . '</p>'
            . '<p><b>Por que isso importa para sua aplicação</b><br>'
            . Html::escape($finding->developerImpact) . '</p>'
            . '<p><b>Como corrigir</b><br>' . Html::escape($finding->remediation) . '</p>'
            . self::renderExample($finding->example)
            . '</div>'
            . self::technicalPanel($finding)
            . '</article>';
    }

    private static function statusBadge(Finding $finding): string
    {
        if ($finding->status === null) {
            return '';
        }
        $confidence = $finding->confidence !== null
            ? ' &middot; ' . Html::escape($finding->confidence . '% de confiança')
            : '';
        return '<span class="status-badge">' . Html::escape(self::statusLabel($finding->status))
            . $confidence . '</span>';
    }

    private static function manualBadge(Finding $finding): string
    {
        return $finding->manualReviewRequired
            ? '<span class="badge manual">Revisão manual necessária</span>'
            : '';
    }

    private static function location(Finding $finding): string
    {
        $method = $finding->method !== null ? strtoupper($finding->method) . ' ' : '';
        $location = '📍 ' . Html::escape($method . ($finding->affectedUrl ?: '—'));
        if ($finding->parameter !== null) {
            $location .= ' &middot; parâmetro <code>' . Html::escape($finding->parameter) . '</code>'
                . ' (' . Html::escape($finding->parameterLocation ?? 'local desconhecido') . ')';
        }
        return $location;
    }

    private static function technicalPanel(Finding $finding): string
    {
        $taxonomy = 'Categoria: ' . Html::escape($finding->category ?? '—')
            . '<br>CWE: ' . Html::escape($finding->cwe ?? '—')
            . '<br>OWASP: ' . Html::escape($finding->owasp ?? '—')
            . '<br>WSTG: ' . Html::escape($finding->wstg ?? '—');
        if ($finding->parameter !== null) {
            $taxonomy .= '<br>Parâmetro: ' . Html::escape($finding->parameter)
                . ' (' . Html::escape($finding->parameterLocation ?? 'local desconhecido') . ')';
        }
        $evidenceJson = $finding->evidence !== []
            ? json_encode($finding->evidence, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
            : '';

        return '<details><summary>Contexto técnico</summary>'
            . '<p>ID da verificação: <code>' . Html::escape($finding->fingerprint) . '</code><br>'
            . $taxonomy . '<br>URL afetada: <code>' . Html::escape($finding->affectedUrl) . '</code></p>'
            . ($evidenceJson !== '' ? '<pre class="evidence-json">' . Html::escape($evidenceJson) . '</pre>' : '')
            . '</details>';
    }

    /**
     * Concrete "vulnerable vs. fixed" code example for the finding, when one exists.
     * This is the developer-facing differentiator: remediation is shown, not only described.
     */
    private static function renderExample(?RemediationExample $example): string
    {
        if ($example === null || $example->isEmpty()) {
            return '';
        }
        $language = $example->language !== ''
            ? '<span class="example-lang">' . Html::escape($example->language) . '</span>'
            : '';
        $note = $example->note !== ''
            ? '<p class="example-note">💡 ' . Html::escape($example->note) . '</p>'
            : '';
        $vulnerableBlock = $example->vulnerable !== ''
            ? '<figure class="code-example bad"><figcaption>❌ Padrão vulnerável</figcaption><pre>'
                . Html::escape($example->vulnerable) . '</pre></figure>'
            : '';
        $fixedBlock = $example->fixed !== ''
            ? '<figure class="code-example good"><figcaption>✅ Como corrigir ' . $language
                . '<button type="button" class="copy-fix no-print" data-copied="Copiado!">Copiar</button>'
                . '</figcaption><pre>' . Html::escape($example->fixed) . '</pre></figure>'
            : '';

        return '<div class="example-wrap"><p class="example-heading">Exemplo prático</p>'
            . '<div class="code-columns">' . $vulnerableBlock . $fixedBlock . '</div>'
            . $note . '</div>';
    }
}
