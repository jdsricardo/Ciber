<?php

declare(strict_types=1);

namespace App\Presentation;

use App\Domain\Model\Analysis;
use App\Domain\Model\AnalysisStatus;
use App\Domain\Model\Application;
use App\Domain\Model\Finding;
use App\Domain\Model\ScanMode;
use App\Domain\Model\Severity;

/**
 * The HTML of each page, one method per screen. Views read entities and produce markup; they
 * never query, never write and never decide — that is what keeps the front controller short
 * enough to read in one sitting.
 */
final class Views
{
    public static function addApplication(string $csrfToken): string
    {
        return '<section class="intro compact"><p class="eyebrow">ALVO AUTORIZADO</p>'
            . '<h1>Registrar uma aplicação</h1>'
            . '<p>O scanner envia apenas requisições de teste seguras e não destrutivas. '
            . 'Analise apenas alvos que você possui ou está autorizado a avaliar.</p></section>'
            . '<form class="card form" method="post" action="index.php?page=create">'
            . '<input type="hidden" name="csrf" value="' . Html::escape($csrfToken) . '">'
            . '<label>Nome da aplicação<input name="name" maxlength="' . Application::MAX_NAME_LENGTH
            . '" required placeholder="Portal do Cliente"></label>'
            . '<label>URL base<input name="url" type="url" required placeholder="https://staging.example.com/"></label>'
            . '<label class="check"><input type="checkbox" name="authorized" value="1" required>'
            . '<span>Confirmo que sou o proprietário deste alvo ou possuo autorização explícita.</span></label>'
            . '<button>Registrar aplicação</button></form>';
    }

    public static function about(): string
    {
        return '<section class="intro"><p class="eyebrow">FEITO PARA DESENVOLVEDORES</p>'
            . '<h1>Achados de segurança que você pode transformar em mudanças de código.</h1>'
            . '<p>O SentinelScope traduz observações HTTP em impacto compreensível e remediação '
            . 'prática. O modo passivo apenas observa; o modo completo testa ativamente parâmetros '
            . 'com payloads seguros (SQL Injection, XSS e outros) e sempre para assim que a '
            . 'evidência mínima necessária é obtida.</p></section>';
    }

    public static function error(string $message): string
    {
        return '<div class="error"><b>A requisição não pôde ser concluída.</b><br>'
            . Html::escape($message) . '</div><a href="index.php">Voltar ao painel</a>';
    }

    /**
     * @param list<Application> $applications
     * @param array<int,list<Analysis>> $historyByApplication analyses keyed by application id
     */
    public static function dashboard(array $applications, array $historyByApplication, string $csrfToken): string
    {
        $cards = '';
        foreach ($applications as $application) {
            $cards .= self::applicationCard(
                $application,
                $historyByApplication[$application->requireId()] ?? [],
                $csrfToken,
            );
        }

        return '<section class="intro"><p class="eyebrow">BANCADA DE SEGURANÇA PARA DESENVOLVEDORES</p>'
            . '<h1>Encontre o risco.<br><span>Entregue a correção.</span></h1>'
            . '<p>Execute verificações autorizadas, passivas ou ativas e não destrutivas, e receba '
            . 'evidências que sua equipe de desenvolvimento entende e consegue agir.</p>'
            . '<a class="button" href="index.php?page=add">Adicionar uma aplicação</a></section>'
            . '<div class="section-head"><h2>Aplicações</h2><span>' . count($applications)
            . ' registrada(s)</span></div>'
            . ($cards !== '' ? $cards : '<div class="empty">Nenhuma aplicação registrada ainda.</div>');
    }

    /**
     * @param list<Finding> $findings
     * @param bool $printable the print/PDF variant of the same page
     */
    public static function analysisResult(Analysis $analysis, array $findings, bool $printable): string
    {
        $analysisId = $analysis->requireId();
        $buttons = $printable
            ? '<button onclick="print()">Imprimir / Salvar como PDF</button>'
            : '<a class="button secondary" href="index.php?page=report&id=' . $analysisId . '">'
                . 'Relatório para impressão</a> '
                . '<a class="button secondary" href="index.php?page=export&id=' . $analysisId . '">'
                . 'Exportar JSON</a>';

        $body = '<div class="toolbar no-print"><a href="index.php">&larr; Painel</a>' . $buttons . '</div>'
            . '<section class="result-header"><div><p class="eyebrow">ANÁLISE #' . $analysisId
            . ' &middot; MODO: ' . Html::escape(mb_strtoupper($analysis->mode->label())) . '</p>'
            . '<h1>' . Html::escape($analysis->applicationName ?? '—') . '</h1>'
            . '<p>' . Html::escape((string) $analysis->baseUrl) . ' &middot; '
            . Html::escape(($analysis->completedAt ?? $analysis->startedAt)->format('Y-m-d H:i:s'))
            . ' UTC</p></div>'
            . '<div class="score"><strong>' . ($analysis->score?->value ?? 'N/D') . '</strong>'
            . '<span>Pontuação de Segurança</span></div></section>';

        if ($analysis->status === AnalysisStatus::Failed) {
            return $body . '<div class="error"><b>A análise não pôde ser concluída.</b><br>'
                . Html::escape((string) $analysis->errorMessage) . '</div>';
        }

        $rendered = '';
        foreach ($findings as $finding) {
            $rendered .= FindingPresenter::render($finding);
        }

        return $body
            . '<div class="metrics">'
            . '<div><span>Verificações executadas</span><b>' . $analysis->checksRun . '</b></div>'
            . '<div><span>Achados</span><b>' . count($findings) . '</b></div>'
            . '<div><span>Status HTTP</span><b>' . $analysis->httpStatus . '</b></div>'
            . '<div><span>Duração</span><b>' . $analysis->durationMs . ' ms</b></div></div>'
            . '<h2>O que sua equipe deve corrigir</h2>'
            . self::severityFilter($findings)
            . ($rendered !== '' ? $rendered
                : '<div class="empty">Nenhum problema foi detectado pelas verificações configuradas.</div>')
            . '<section class="limitations"><h2>Escopo e limitações</h2><p>'
            . ($analysis->mode === ScanMode::Passive
                ? 'Esta é uma avaliação passiva: apenas observação de respostas, sem envio de payloads de teste.'
                : 'Esta análise incluiu testes ativos com payloads seguros e não destrutivos.')
            . ' Ela não prova a ausência de vulnerabilidades e não substitui um teste de intrusão '
            . 'profissional.</p></section>';
    }

    /** @param array{older:Analysis,newer:Analysis,new:array,persistent:array,fixed:array} $diff */
    public static function comparison(array $diff): string
    {
        return '<div class="toolbar"><a href="index.php">← Painel</a></div><h1>O que mudou?</h1>'
            . '<p>Análise #' . $diff['older']->requireId() . ' → #' . $diff['newer']->requireId()
            . ' · Pontuação ' . ($diff['older']->score?->value ?? '—')
            . ' → ' . ($diff['newer']->score?->value ?? '—') . '</p>'
            . '<div class="comparison">'
            . self::comparisonSection('Novos problemas', $diff['new'], 'new')
            . self::comparisonSection('Ainda presentes', $diff['persistent'], 'same')
            . self::comparisonSection('Corrigidos', $diff['fixed'], 'fixed')
            . '</div>';
    }

    /** @param list<Analysis> $history */
    private static function applicationCard(Application $application, array $history, string $csrfToken): string
    {
        $options = '';
        $rows = '';
        foreach ($history as $analysis) {
            $analysisId = $analysis->requireId();
            $startedAt = Html::escape($analysis->startedAt->format('Y-m-d H:i:s'));
            $options .= '<option value="' . $analysisId . '">#' . $analysisId . ' · ' . $startedAt . '</option>';
            $rows .= '<tr><td><a href="index.php?page=result&id=' . $analysisId . '">#' . $analysisId . '</a></td>'
                . '<td>' . $startedAt . '</td>'
                . '<td>' . Html::escape($analysis->mode->label()) . '</td>'
                . '<td>' . Html::escape($analysis->status->value) . '</td>'
                . '<td>' . ($analysis->score?->value ?? '—') . '</td>'
                . '<td>' . $analysis->checksRun . '</td></tr>';
        }

        $compareForm = count($history) > 1
            ? '<form class="compare-form" action="index.php"><input type="hidden" name="page" value="compare">'
                . '<select name="old">' . $options . '</select><span>até</span>'
                . '<select name="new">' . $options . '</select>'
                . '<button class="secondary">Comparar</button></form>'
            : '';

        $historyTable = $rows !== ''
            ? '<div class="scroll"><table><thead><tr><th>ID</th><th>Data (UTC)</th><th>Modo</th>'
                . '<th>Status</th><th>Pontuação</th><th>Verificações</th></tr></thead>'
                . '<tbody>' . $rows . '</tbody></table></div>'
            : '<p class="muted">Nenhuma análise ainda.</p>';

        return '<section class="card"><div class="app-head"><div>'
            . '<h2>' . Html::escape($application->name) . '</h2>'
            . '<p>' . Html::escape($application->baseUrl->value) . '</p></div></div>'
            . self::runForm($application, $csrfToken)
            . $compareForm
            . $historyTable
            . '</section>';
    }

    private static function runForm(Application $application, string $csrfToken): string
    {
        return '<form method="post" action="index.php?page=run" class="run-form">'
            . '<input type="hidden" name="csrf" value="' . Html::escape($csrfToken) . '">'
            . '<input type="hidden" name="application_id" value="' . $application->requireId() . '">'
            . '<label class="check"><input type="checkbox" name="mode_active" value="1" '
            . 'data-toggles="authorized_active">'
            . '<span>Análise completa (ativa) — testa parâmetros com SQL Injection, XSS e outros '
            . 'payloads seguros</span></label>'
            . '<label class="check" data-requires="mode_active">'
            . '<input type="checkbox" name="authorized_active" value="1">'
            . '<span>Autorizo o envio de payloads de teste ativos e não destrutivos contra este '
            . 'alvo.</span></label>'
            . '<details class="auth-details"><summary>Área autenticada (opcional)</summary>'
            . '<label>Cookie de sessão<input name="session_cookie" placeholder="PHPSESSID=...; outro=valor" '
            . 'autocomplete="off"></label>'
            . '<p class="muted">Enviado apenas ao alvo autorizado nesta análise e não armazenado.</p></details>'
            . '<button>Executar análise</button></form>';
    }

    /** @param list<Finding> $findings */
    private static function severityFilter(array $findings): string
    {
        if ($findings === []) {
            return '';
        }
        $counts = [];
        foreach ($findings as $finding) {
            $counts[$finding->severity->value] = ($counts[$finding->severity->value] ?? 0) + 1;
        }

        $chips = '<button data-filter="all" class="sev-chip active">Todos <b>'
            . count($findings) . '</b></button>';
        foreach (Severity::cases() as $severity) {
            $count = $counts[$severity->value] ?? 0;
            if ($count > 0) {
                $chips .= '<button data-filter="' . $severity->value . '" class="sev-chip '
                    . $severity->value . '">' . Html::escape($severity->label())
                    . ' <b>' . $count . '</b></button>';
            }
        }
        return '<div class="sev-filter no-print" data-severity-filter>' . $chips . '</div>';
    }

    /** @param array<string,array<string,mixed>> $findings */
    private static function comparisonSection(string $title, array $findings, string $type): string
    {
        $html = '<section class="card"><h2>' . Html::escape($title) . ' <small>'
            . count($findings) . '</small></h2>';
        foreach ($findings as $finding) {
            $html .= '<div class="compare ' . $type . '">'
                . '<b>' . Html::escape((string) ($finding['title'] ?? '')) . '</b>'
                . '<span>' . Html::escape((string) ($finding['severity'] ?? '')) . '</span></div>';
        }
        return $html . '</section>';
    }
}
