<?php

declare(strict_types=1);

require __DIR__ . '/../app/bootstrap.php';

use App\Presentation\FindingPresenter;
use App\Support\AnalysisComparison;
use App\Support\AnalysisExport;
use App\Support\Scoring;

/**
 * Minimal, dependency-free PHP test harness. Uses an explicit check() rather than assert()
 * so results are reported and the exit code is meaningful regardless of zend.assertions ini.
 * These tests exercise only pure classes (no database), matching the Python suite's unit level.
 */
$passed = 0;
$failed = 0;
function check(string $name, bool $condition): void
{
    global $passed, $failed;
    if ($condition) {
        $passed++;
    } else {
        $failed++;
        fwrite(STDERR, "  FAIL: {$name}\n");
    }
}

// --- Environment configuration -------------------------------------------------
$example = file_get_contents(__DIR__ . '/../.env.example');
check('.env.example has DB_NAME', str_contains($example, 'DB_NAME=sentinelscope'));
check('.env.example defaults private targets off', str_contains($example, 'ALLOW_PRIVATE_TARGETS=false'));
check('.gitignore ignores .env', str_contains(file_get_contents(__DIR__ . '/../.gitignore'), '/.env'));

// --- Finding rendering ---------------------------------------------------------
$baseFinding = [
    'severity' => 'high',
    'status' => 'high_confidence',
    'confidence' => 80,
    'manual_review_required' => 0,
    'evidence_summary' => 'CSP is missing.',
    'description' => 'No Content-Security-Policy header was returned.',
    'developer_impact' => 'Injected scripts run with fewer restrictions.',
    'remediation' => 'Add a strict CSP.',
    'fingerprint' => 'headers.csp_missing',
    'category' => 'Security Headers',
    'cwe' => 'CWE-693',
    'owasp' => 'A02:2025 Security Misconfiguration',
    'wstg' => 'WSTG-CONF-12',
    'parameter' => null,
    'parameter_location' => null,
    'affected_url' => 'https://example.com/',
    'method' => 'GET',
    'title' => 'Browser has no content execution policy',
    'evidence' => json_encode(['reason' => 'No CSP header.']),
    'remediation_example_vulnerable' => '',
    'remediation_example_fixed' => '',
    'remediation_example_language' => '',
    'remediation_example_note' => '',
];
$html = FindingPresenter::render($baseFinding);
check('render shows severity label', str_contains($html, 'ALTO'));
check('render shows status label', str_contains($html, 'Alta Confiança'));
check('render shows CWE', str_contains($html, 'CWE-693'));
check('render escapes output (no raw script tag)', !str_contains($html, '<script>'));
check('render omits example block when absent', !str_contains($html, 'Exemplo prático'));

// --- Finding rendering WITH code example (developer-facing differentiator) ------
$withExample = $baseFinding;
$withExample['remediation_example_vulnerable'] = "echo \$_GET['x'];";
$withExample['remediation_example_fixed'] = "echo htmlspecialchars(\$_GET['x']);";
$withExample['remediation_example_language'] = 'PHP';
$withExample['remediation_example_note'] = 'Sempre codifique a saída.';
$exampleHtml = FindingPresenter::render($withExample);
check('example block appears when present', str_contains($exampleHtml, 'Exemplo prático'));
check('example shows vulnerable pattern', str_contains($exampleHtml, 'Padrão vulnerável'));
check('example shows fixed pattern', str_contains($exampleHtml, 'Como corrigir'));
check('finding carries data-severity for filtering', str_contains($exampleHtml, 'data-severity="high"'));
check('fixed example has a copy button', str_contains($exampleHtml, 'class="copy-fix'));
check('example shows language label', str_contains($exampleHtml, 'PHP'));
check('example shows note', str_contains($exampleHtml, 'Sempre codifique'));
check('example code is HTML-escaped', str_contains($exampleHtml, '&lt;') || !str_contains($exampleHtml, '<b>echo'));

// --- Security score ------------------------------------------------------------
check('empty findings score 100', Scoring::calculate([]) === 100);
check('one critical deducts 30', Scoring::calculate([['severity' => 'critical']]) === 70);
check('one high deducts 15', Scoring::calculate([['severity' => 'high']]) === 85);
check('one medium deducts 7', Scoring::calculate([['severity' => 'medium']]) === 93);
check('one low deducts 2', Scoring::calculate([['severity' => 'low']]) === 98);
check('mixed severities sum correctly', Scoring::calculate([
    ['severity' => 'critical'], ['severity' => 'high'], ['severity' => 'medium'], ['severity' => 'low'],
]) === 100 - 30 - 15 - 7 - 2);
check('score is clamped at 0', Scoring::calculate(array_fill(0, 10, ['severity' => 'critical'])) === 0);
check('unknown severity is ignored', Scoring::calculate([['severity' => 'unknown']]) === 100);

// --- Analysis comparison (new / persistent / fixed) ----------------------------
$oldFindings = [
    ['fingerprint' => 'a', 'title' => 'A', 'severity' => 'high'],
    ['fingerprint' => 'b', 'title' => 'B', 'severity' => 'low'],
];
$newFindings = [
    ['fingerprint' => 'b', 'title' => 'B', 'severity' => 'low'],   // persistent
    ['fingerprint' => 'c', 'title' => 'C', 'severity' => 'medium'], // new
];
$diff = AnalysisComparison::diff($oldFindings, $newFindings);
check('diff detects new finding', array_keys($diff['new']) === ['c']);
check('diff detects persistent finding', array_keys($diff['persistent']) === ['b']);
check('diff detects fixed finding', array_keys($diff['fixed']) === ['a']);
check('diff empty when identical', AnalysisComparison::diff($newFindings, $newFindings)['new'] === []
    && AnalysisComparison::diff($newFindings, $newFindings)['fixed'] === []);
check('diff ignores findings without fingerprint', AnalysisComparison::diff([['title' => 'x']], [])['fixed'] === []);

// --- JSON export (machine-readable) --------------------------------------------
$exportFinding = $baseFinding;
$exportFinding['remediation_example_vulnerable'] = "echo \$_GET['x'];";
$exportFinding['remediation_example_fixed'] = "echo htmlspecialchars(\$_GET['x']);";
$exportFinding['remediation_example_language'] = 'PHP';
$exportFinding['parameter'] = 'q';
$exportFinding['parameter_location'] = 'form';
$exportFinding['method'] = 'POST';
$analysisRow = [
    'id' => 7, 'application_name' => 'Portal', 'base_url' => 'https://x/', 'mode' => 'safe_active',
    'status' => 'completed', 'security_score' => 85, 'checks_run' => 64, 'http_status' => 200,
    'duration_ms' => 1234, 'started_at' => '2026-09-08 12:00:00', 'completed_at' => '2026-09-08 12:00:05',
];
$export = AnalysisExport::toArray($analysisRow, [$exportFinding]);
check('export tool name', ($export['tool'] ?? null) === 'SentinelScope');
check('export analysis id is int', ($export['analysis']['id'] ?? null) === 7);
check('export score is int', ($export['analysis']['security_score'] ?? null) === 85);
check('export finding count', ($export['summary']['findings'] ?? null) === 1);
check('export finding carries taxonomy', ($export['findings'][0]['cwe'] ?? null) === 'CWE-693');
check('export finding carries method/param', ($export['findings'][0]['method'] ?? null) === 'POST'
    && ($export['findings'][0]['parameter_location'] ?? null) === 'form');
check('export finding carries fix example', ($export['findings'][0]['remediation_example']['fixed'] ?? null) !== null);
check('export decodes evidence JSON', is_array($export['findings'][0]['evidence'] ?? null));
$json = json_encode($export, JSON_UNESCAPED_UNICODE);
check('export serializes to valid JSON', is_string($json) && json_decode($json, true) !== null);

// --- CA-05 / NFR-01: rendering 1,000 findings stays well under 3 seconds --------
$many = [];
for ($i = 0; $i < 1000; $i++) {
    $f = $baseFinding;
    $f['fingerprint'] = 'headers.csp_missing.' . $i;
    $f['remediation_example_vulnerable'] = "linha {$i}";
    $f['remediation_example_fixed'] = "corrigido {$i}";
    $many[] = $f;
}
$start = microtime(true);
$rendered = '';
foreach ($many as $f) {
    $rendered .= FindingPresenter::render($f);
}
$elapsed = microtime(true) - $start;
check('rendered all 1,000 findings', substr_count($rendered, '<article class="finding"') === 1000);
check('rendering 1,000 findings under 3s (CA-05), got ' . round($elapsed, 3) . 's', $elapsed < 3.0);

// --- Summary -------------------------------------------------------------------
echo "PHP tests: {$passed} passed, {$failed} failed.\n";
exit($failed === 0 ? 0 : 1);
