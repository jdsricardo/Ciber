<?php

declare(strict_types=1);

namespace App\Presentation;

use App\Support\Html;

final class FindingPresenter
{
    private const SEVERITY_LABELS = ['critical' => 'CRÍTICO', 'high' => 'ALTO', 'medium' => 'MÉDIO', 'low' => 'BAIXO'];
    private const STATUS_LABELS = [
        'confirmed' => 'Confirmado',
        'high_confidence' => 'Alta Confiança',
        'probable' => 'Provável',
        'possible' => 'Possível',
        'informational' => 'Informativo',
        'manual_review_required' => 'Revisão Manual Necessária',
    ];

    public static function severityLabel(string $severity): string
    {
        return self::SEVERITY_LABELS[$severity] ?? strtoupper($severity);
    }

    public static function statusLabel(string $status): string
    {
        return self::STATUS_LABELS[$status] ?? ucwords(str_replace('_', ' ', $status));
    }

    public static function render(array $finding): string
    {
        $confidence = $finding['confidence'] !== null ? (int) $finding['confidence'] . '% de confiança' : '';
        $status = $finding['status'] ? self::statusLabel($finding['status']) : '';
        $statusBadge = $status
            ? '<span class="status-badge">' . Html::escape($status) . ($confidence ? ' &middot; ' . Html::escape($confidence) : '') . '</span>'
            : '';
        $manualBadge = !empty($finding['manual_review_required'])
            ? '<span class="badge manual">Revisão manual necessária</span>'
            : '';
        $observed = $finding['evidence_summary'] ?: ($finding['description'] ?: '');
        $evidenceJson = $finding['evidence']
            ? json_encode(json_decode($finding['evidence'], true), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
            : '';

        $method = $finding['method'] ? strtoupper($finding['method']) . ' ' : '';
        $location = '📍 ' . Html::escape($method . ($finding['affected_url'] ?: '—'));
        if ($finding['parameter']) {
            $location .= ' &middot; parâmetro <code>' . Html::escape($finding['parameter']) . '</code>'
                . ' (' . Html::escape($finding['parameter_location'] ?: 'local desconhecido') . ')';
        }

        $taxonomy = 'Categoria: ' . Html::escape($finding['category'] ?: '—')
            . '<br>CWE: ' . Html::escape($finding['cwe'] ?: '—')
            . '<br>OWASP: ' . Html::escape($finding['owasp'] ?: '—')
            . '<br>WSTG: ' . Html::escape($finding['wstg'] ?: '—');
        if ($finding['parameter']) {
            $taxonomy .= '<br>Parâmetro: ' . Html::escape($finding['parameter'])
                . ' (' . Html::escape($finding['parameter_location'] ?: 'local desconhecido') . ')';
        }

        return '<article class="finding"><div class="finding-title">'
            . '<span class="severity ' . Html::escape($finding['severity']) . '">' . Html::escape(self::severityLabel($finding['severity'])) . '</span>'
            . $statusBadge . $manualBadge . '<h3>' . Html::escape($finding['title']) . '</h3></div>'
            . '<p class="location-line">' . $location . '</p>'
            . '<div class="explain">'
            . '<p><b>O que o scanner observou</b><br>' . Html::escape($observed) . '</p>'
            . '<p><b>Por que isso importa para sua aplicação</b><br>' . Html::escape($finding['developer_impact']) . '</p>'
            . '<p><b>Como corrigir</b><br>' . Html::escape($finding['remediation']) . '</p>'
            . '</div>'
            . '<details><summary>Contexto técnico</summary><p>ID da verificação: <code>' . Html::escape($finding['fingerprint']) . '</code><br>'
            . $taxonomy . '<br>URL afetada: <code>' . Html::escape($finding['affected_url']) . '</code></p>'
            . ($evidenceJson ? '<pre class="evidence-json">' . Html::escape($evidenceJson) . '</pre>' : '')
            . '</details></article>';
    }
}
