<?php

declare(strict_types=1);

/**
 * Minimal, dependency-free PHP test harness. Uses an explicit check() rather than assert()
 * so results are reported and the exit code is meaningful regardless of zend.assertions ini.
 *
 * The suite loads app/autoload.php — not bootstrap.php — so it needs neither a `.env` nor a
 * database: the domain is exercised through in-memory implementations of the same contracts
 * the PDO adapters implement.
 */

require __DIR__ . '/../app/autoload.php';

use App\Domain\Exception\DomainError;
use App\Domain\Exception\InvalidInput;
use App\Domain\Exception\NotFound;
use App\Domain\Exception\ScannerUnavailable;
use App\Domain\Model\Analysis;
use App\Domain\Model\AnalysisStatus;
use App\Domain\Model\Application;
use App\Domain\Model\Finding;
use App\Domain\Model\ScanMode;
use App\Domain\Model\ScanResult;
use App\Domain\Model\SecurityScore;
use App\Domain\Model\Severity;
use App\Domain\Model\TargetUrl;
use App\Domain\Service\AnalysisComparison;
use App\Presentation\FindingPresenter;
use App\UseCase\CompareAnalyses;
use App\UseCase\ExportAnalysis;
use App\UseCase\RegisterApplication;
use App\UseCase\RunAnalysis;
use Tests\Php\FakeScannerGateway;
use Tests\Php\ImmediateTransactionManager;
use Tests\Php\InMemoryAnalysisRepository;
use Tests\Php\InMemoryApplicationRepository;
use Tests\Php\InMemoryFindingRepository;
use Tests\Php\ThrowingScannerGateway;

spl_autoload_register(static function (string $class): void {
    if (!str_starts_with($class, 'Tests\\Php\\')) {
        return;
    }
    $path = __DIR__ . '/php/' . substr($class, strlen('Tests\\Php\\')) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

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

/** Asserts that $work throws $expected, and that the message is not empty. */
function checkThrows(string $name, string $expected, callable $work): void
{
    try {
        $work();
    } catch (Throwable $error) {
        check($name, $error instanceof $expected && $error->getMessage() !== '');
        return;
    }
    check($name, false);
}

/** @param array<string,mixed> $overrides */
function makeFinding(array $overrides = []): Finding
{
    return Finding::fromRow($overrides + [
        'fingerprint' => 'headers.csp_missing',
        'title' => 'Browser has no content execution policy',
        'severity' => 'high',
        'affected_url' => 'https://example.com/',
        'developer_impact' => 'Injected scripts run with fewer restrictions.',
        'remediation' => 'Add a strict CSP.',
        'confidence' => 80,
        'status' => 'high_confidence',
        'category' => 'Security Headers',
        'cwe' => 'CWE-693',
        'owasp' => 'A02:2025 Security Misconfiguration',
        'wstg' => 'WSTG-CONF-12',
        'method' => 'GET',
        'description' => 'No Content-Security-Policy header was returned.',
        'evidence_summary' => 'CSP is missing.',
        'evidence' => json_encode(['reason' => 'No CSP header.']),
        'manual_review_required' => 0,
    ]);
}

// --- Environment configuration -------------------------------------------------
$example = file_get_contents(__DIR__ . '/../.env.example');
check('.env.example has DB_NAME', str_contains($example, 'DB_NAME=sentinelscope'));
check('.env.example defaults private targets off', str_contains($example, 'ALLOW_PRIVATE_TARGETS=false'));
check('.gitignore ignores .env', str_contains(file_get_contents(__DIR__ . '/../.gitignore'), '/.env'));

// --- Layering: the domain must not reference any outer layer --------------------
$domainFiles = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator(__DIR__ . '/../app/src/Domain', FilesystemIterator::SKIP_DOTS)
);
$leaks = [];
foreach ($domainFiles as $file) {
    if ($file->getExtension() !== 'php') {
        continue;
    }
    // Comments are stripped first: a docblock may legitimately mention the PDO adapter, while
    // a reference to it in actual code would invert the dependency this check protects.
    $code = '';
    foreach (token_get_all((string) file_get_contents($file->getPathname())) as $token) {
        if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }
        $code .= is_array($token) ? $token[1] : $token;
    }
    foreach (['App\\Infrastructure', 'App\\Presentation', 'App\\UseCase', 'PDO'] as $outer) {
        if (str_contains($code, $outer)) {
            $leaks[] = $file->getFilename() . ' -> ' . $outer;
        }
    }
}
check('domain depends on no outer layer (' . implode(', ', $leaks) . ')', $leaks === []);

// --- Coding standard: the rules docs/CODING_STANDARD.md marks as verified ------
$sourceFiles = [];
$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator(__DIR__ . '/../app/src', FilesystemIterator::SKIP_DOTS)
);
foreach ($iterator as $file) {
    if ($file->getExtension() === 'php') {
        $sourceFiles[$file->getPathname()] = (string) file_get_contents($file->getPathname());
    }
}

$missingStrictTypes = [];
$multipleTypes = [];
$nonFinal = [];
$untypedReturns = [];
$sqlOutsidePersistence = [];
foreach ($sourceFiles as $path => $source) {
    $name = basename($path);
    if (!str_contains($source, 'declare(strict_types=1);')) {
        $missingStrictTypes[] = $name;
    }
    if (preg_match_all('/^(?:final |abstract )?(?:class|interface|enum) /m', $source) > 1) {
        $multipleTypes[] = $name;
    }
    // Only DomainError may be extended, so only it may be declared without `final`.
    if (preg_match('/^class /m', $source) || (preg_match('/^abstract class /m', $source) && $name !== 'DomainError.php')) {
        $nonFinal[] = $name;
    }
    // Token-based, because a signature may span several lines and a constructor legitimately
    // has no return type.
    $tokens = array_values(array_filter(
        token_get_all($source),
        static fn($token): bool => !is_array($token)
            || !in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)
    ));
    foreach ($tokens as $index => $token) {
        if (!is_array($token) || $token[0] !== T_FUNCTION) {
            continue;
        }
        $next = $tokens[$index + 1] ?? null;
        if (!is_array($next) || $next[1] === '__construct') {
            continue;
        }
        $depth = 0;
        for ($cursor = $index + 2; $cursor < count($tokens); $cursor++) {
            $current = $tokens[$cursor];
            if ($current === '(') {
                $depth++;
            } elseif ($current === ')') {
                $depth--;
                if ($depth === 0) {
                    if (($tokens[$cursor + 1] ?? null) !== ':') {
                        $untypedReturns[] = $name . '::' . $next[1];
                    }
                    break;
                }
            }
        }
    }
    $code = preg_replace('/\'[^\']*\'|"[^"]*"/', "''", $source);
    if (!str_contains($path, 'Persistence') && preg_match('/\b(SELECT|INSERT INTO|UPDATE|DELETE FROM)\b/i', $source)
        && preg_match('/(SELECT|INSERT INTO|UPDATE|DELETE FROM)\s+[a-z_]+\s/i', $source)) {
        $sqlOutsidePersistence[] = $name;
    }
}
check('every source file declares strict_types (' . implode(', ', $missingStrictTypes) . ')',
    $missingStrictTypes === []);
check('one class, interface or enum per file (' . implode(', ', $multipleTypes) . ')',
    $multipleTypes === []);
check('classes are final except the abstract DomainError (' . implode(', ', $nonFinal) . ')',
    $nonFinal === []);
check('every method declares a return type (' . implode(', ', $untypedReturns) . ')',
    $untypedReturns === []);
check('SQL lives only in Infrastructure/Persistence (' . implode(', ', $sqlOutsidePersistence) . ')',
    $sqlOutsidePersistence === []);
check('every domain contract is an interface',
    count(array_filter(
        array_keys($sourceFiles),
        static fn(string $path): bool => str_contains($path, 'Domain' . DIRECTORY_SEPARATOR . 'Contract')
            && !str_contains($sourceFiles[$path], 'interface ')
    )) === 0);

// --- Value objects: validation happens in the constructor ----------------------
check('target url accepts https', TargetUrl::fromString('https://example.com/')->value === 'https://example.com/');
checkThrows('target url rejects empty', InvalidInput::class, static fn() => TargetUrl::fromString('  '));
checkThrows('target url rejects non-http scheme', InvalidInput::class, static fn() => TargetUrl::fromString('ftp://x.com'));
checkThrows('target url rejects malformed', InvalidInput::class, static fn() => TargetUrl::fromString('not a url'));
checkThrows('target url rejects embedded credentials', InvalidInput::class, static fn() => TargetUrl::fromString('https://u:p@x.com/'));

check('score clamps at 0', SecurityScore::fromInt(0)->value === 0);
checkThrows('score rejects above 100', InvalidInput::class, static fn() => SecurityScore::fromInt(101));
checkThrows('score rejects negative', InvalidInput::class, static fn() => SecurityScore::fromInt(-1));

check('severity weights: critical 30', Severity::Critical->weight() === 30);
check('severity weights: high 15', Severity::High->weight() === 15);
check('severity weights: medium 7', Severity::Medium->weight() === 7);
check('severity weights: low 2', Severity::Low->weight() === 2);
checkThrows('unknown severity is rejected', InvalidInput::class, static fn() => Severity::fromString('fatal'));

// --- Entities: invariants enforced in the constructor --------------------------
$application = Application::register('  Portal do Cliente  ', 'https://example.com/');
check('application trims its name', $application->name === 'Portal do Cliente');
check('application starts unpersisted', $application->id === null);
checkThrows('application requires a name', InvalidInput::class, static fn() => Application::register('   ', 'https://x.com'));
checkThrows('application name is bounded', InvalidInput::class, static fn() => Application::register(str_repeat('a', 121), 'https://x.com'));
checkThrows('unpersisted application has no id', InvalidInput::class, static fn() => $application->requireId());

checkThrows('finding requires a fingerprint', InvalidInput::class, static fn() => makeFinding(['fingerprint' => '']));
checkThrows('finding requires a title', InvalidInput::class, static fn() => makeFinding(['title' => '']));
checkThrows('finding requires an affected url', InvalidInput::class, static fn() => makeFinding(['affected_url' => '']));
checkThrows('finding confidence is bounded', InvalidInput::class, static fn() => makeFinding(['confidence' => 101]));
check('finding decodes evidence JSON', makeFinding()->evidence === ['reason' => 'No CSP header.']);
check('finding prefers the evidence summary', makeFinding()->observed() === 'CSP is missing.');
check('finding falls back to the description', makeFinding(['evidence_summary' => ''])->observed()
    === 'No Content-Security-Policy header was returned.');
check('finding has no example by default', makeFinding()->example === null);

checkThrows('completed analysis needs a score', InvalidInput::class, static fn() => new Analysis(
    1, 1, ScanMode::Passive, AnalysisStatus::Completed, new DateTimeImmutable('now')
));
checkThrows('failed analysis needs a reason', InvalidInput::class, static fn() => new Analysis(
    1, 1, ScanMode::Passive, AnalysisStatus::Failed, new DateTimeImmutable('now')
));
checkThrows('analysis needs an application', InvalidInput::class, static fn() => new Analysis(
    1, 0, ScanMode::Passive, AnalysisStatus::Running, new DateTimeImmutable('now')
));

// --- Error convention ----------------------------------------------------------
check('InvalidInput is a DomainError', is_subclass_of(InvalidInput::class, DomainError::class));
check('NotFound is a DomainError', is_subclass_of(NotFound::class, DomainError::class));
check('InvalidInput maps to 400', (new InvalidInput('x'))->httpStatus() === 400);
check('NotFound maps to 404', (new NotFound('x'))->httpStatus() === 404);

// --- Security score derived from findings --------------------------------------
check('empty findings score 100', SecurityScore::fromFindings([])->value === 100);
check('one critical deducts 30', SecurityScore::fromFindings([makeFinding(['severity' => 'critical'])])->value === 70);
check('one high deducts 15', SecurityScore::fromFindings([makeFinding(['severity' => 'high'])])->value === 85);
check('one medium deducts 7', SecurityScore::fromFindings([makeFinding(['severity' => 'medium'])])->value === 93);
check('one low deducts 2', SecurityScore::fromFindings([makeFinding(['severity' => 'low'])])->value === 98);
check('mixed severities sum correctly', SecurityScore::fromFindings([
    makeFinding(['severity' => 'critical']),
    makeFinding(['severity' => 'high']),
    makeFinding(['severity' => 'medium']),
    makeFinding(['severity' => 'low']),
])->value === 100 - 30 - 15 - 7 - 2);
check('score is clamped at 0', SecurityScore::fromFindings(
    array_fill(0, 10, makeFinding(['severity' => 'critical']))
)->value === 0);
check('unknown severity is ignored by the row form', SecurityScore::fromRows([['severity' => 'unknown']])->value === 100);

// --- Finding rendering ---------------------------------------------------------
$html = FindingPresenter::render(makeFinding());
check('render shows severity label', str_contains($html, 'ALTO'));
check('render shows status label', str_contains($html, 'Alta Confiança'));
check('render shows CWE', str_contains($html, 'CWE-693'));
check('render escapes output (no raw script tag)', !str_contains($html, '<script>'));
check('render omits example block when absent', !str_contains($html, 'Exemplo prático'));
check('render escapes a hostile title', !str_contains(
    FindingPresenter::render(makeFinding(['title' => '<script>alert(1)</script>'])),
    '<script>alert(1)</script>'
));

$withExample = makeFinding([
    'remediation_example_vulnerable' => "echo \$_GET['x'];",
    'remediation_example_fixed' => "echo htmlspecialchars(\$_GET['x']);",
    'remediation_example_language' => 'PHP',
    'remediation_example_note' => 'Sempre codifique a saída.',
]);
$exampleHtml = FindingPresenter::render($withExample);
check('example block appears when present', str_contains($exampleHtml, 'Exemplo prático'));
check('example shows vulnerable pattern', str_contains($exampleHtml, 'Padrão vulnerável'));
check('example shows fixed pattern', str_contains($exampleHtml, 'Como corrigir'));
check('finding carries data-severity for filtering', str_contains($exampleHtml, 'data-severity="high"'));
check('fixed example has a copy button', str_contains($exampleHtml, 'class="copy-fix'));
check('example shows language label', str_contains($exampleHtml, 'PHP'));
check('example shows note', str_contains($exampleHtml, 'Sempre codifique'));
check('example code is HTML-escaped', str_contains($exampleHtml, '&#039;') || str_contains($exampleHtml, '&lt;'));

// --- Analysis comparison (new / persistent / fixed) ----------------------------
$oldFindings = [
    ['fingerprint' => 'a', 'title' => 'A', 'severity' => 'high'],
    ['fingerprint' => 'b', 'title' => 'B', 'severity' => 'low'],
];
$newFindings = [
    ['fingerprint' => 'b', 'title' => 'B', 'severity' => 'low'],    // persistent
    ['fingerprint' => 'c', 'title' => 'C', 'severity' => 'medium'], // new
];
$diff = AnalysisComparison::diff($oldFindings, $newFindings);
check('diff detects new finding', array_keys($diff['new']) === ['c']);
check('diff detects persistent finding', array_keys($diff['persistent']) === ['b']);
check('diff detects fixed finding', array_keys($diff['fixed']) === ['a']);
check('diff empty when identical', AnalysisComparison::diff($newFindings, $newFindings)['new'] === []
    && AnalysisComparison::diff($newFindings, $newFindings)['fixed'] === []);
check('diff ignores findings without fingerprint', AnalysisComparison::diff([['title' => 'x']], [])['fixed'] === []);

// --- ScanResult: reading the engine payload ------------------------------------
$failedResult = ScanResult::fromEnginePayload(['ok' => false, 'error' => 'Alvo inacessível.']);
check('engine failure is not ok', !$failedResult->ok && $failedResult->error === 'Alvo inacessível.');
$okResult = ScanResult::fromEnginePayload([
    'ok' => true, 'checks_run' => 64, 'duration_ms' => 120, 'status_code' => 200,
    'findings' => [[
        'fingerprint' => 'headers.csp_missing', 'title' => 'T', 'severity' => 'medium',
        'affected_url' => 'https://example.com/', 'developer_impact' => 'i', 'remediation' => 'r',
    ]],
]);
check('engine success carries findings', $okResult->ok && count($okResult->findings) === 1);
check('engine success carries metrics', $okResult->checksRun === 64 && $okResult->httpStatus === 200);
check('scan result derives the score', $okResult->score()->value === 93);
checkThrows('a failure needs a reason', InvalidInput::class, static fn() => ScanResult::failure('  '));

// --- Use cases, driven through in-memory repositories --------------------------
$makeWorld = static function (ScanResult $result): array {
    $applications = new InMemoryApplicationRepository();
    $analyses = new InMemoryAnalysisRepository();
    $findings = new InMemoryFindingRepository();
    $scanner = new FakeScannerGateway($result);
    $transactions = new ImmediateTransactionManager();
    return [
        'applications' => $applications,
        'analyses' => $analyses,
        'findings' => $findings,
        'scanner' => $scanner,
        'transactions' => $transactions,
        'register' => new RegisterApplication($applications),
        'run' => new RunAnalysis($applications, $analyses, $findings, $scanner, $transactions),
        'compare' => new CompareAnalyses($analyses, $findings),
        'export' => new ExportAnalysis($analyses, $findings),
    ];
};

$world = $makeWorld($okResult);
$registered = $world['register']->execute('Portal', 'https://example.com/', true);
check('register assigns an id', $registered->requireId() === 1);
check('register stores the application', $world['applications']->find(1)?->name === 'Portal');
checkThrows('register demands authorization', InvalidInput::class,
    static fn() => $world['register']->execute('Portal', 'https://example.com/', false));
checkThrows('register validates the url', InvalidInput::class,
    static fn() => $world['register']->execute('Portal', 'javascript:alert(1)', true));

$analysisId = $world['run']->execute(1, false, false);
$stored = $world['analyses']->find($analysisId);
check('run completes the analysis', $stored?->status === AnalysisStatus::Completed);
check('run stores the derived score', $stored?->score?->value === 93);
check('run stores the findings', count($world['findings']->byAnalysis($analysisId)) === 1);
check('run wraps the write in a transaction', $world['transactions']->calls === 1);
check('run defaults to the passive mode', $world['scanner']->lastMode === ScanMode::Passive);
check('run passes the target to the scanner', $world['scanner']->lastTarget?->value === 'https://example.com/');
checkThrows('run rejects an unknown application', NotFound::class,
    static fn() => $world['run']->execute(999, false, false));
checkThrows('run rejects active mode without its authorization', InvalidInput::class,
    static fn() => $world['run']->execute(1, true, false));

$activeWorld = $makeWorld($okResult);
$activeWorld['register']->execute('Portal', 'https://example.com/', true);
$activeWorld['run']->execute(1, true, true, 'PHPSESSID=abc');
check('run honours the authorized active mode', $activeWorld['scanner']->lastMode === ScanMode::SafeActive);
check('run forwards the session cookie', $activeWorld['scanner']->lastSessionCookie === 'PHPSESSID=abc');

$failWorld = $makeWorld(ScanResult::failure('Alvo inacessível.'));
$failWorld['register']->execute('Portal', 'https://example.com/', true);
$failedId = $failWorld['run']->execute(1, false, false);
$failedAnalysis = $failWorld['analyses']->find($failedId);
check('a failed scan is recorded, not lost', $failedAnalysis?->status === AnalysisStatus::Failed);
check('a failed scan keeps its reason', $failedAnalysis?->errorMessage === 'Alvo inacessível.');
check('a failed scan writes no findings', $failWorld['findings']->byAnalysis($failedId) === []);
check('a failed scan opens no transaction', $failWorld['transactions']->calls === 0);

// An unreachable engine must close the analysis too, or the history keeps a row stuck running.
$unreachable = $makeWorld($okResult);
$unreachable['register']->execute('Portal', 'https://example.com/', true);
$unreachableRun = new RunAnalysis(
    $unreachable['applications'],
    $unreachable['analyses'],
    $unreachable['findings'],
    new ThrowingScannerGateway(new ScannerUnavailable('O scanner retornou uma resposta inválida.')),
    $unreachable['transactions'],
);
$unreachableId = $unreachableRun->execute(1, false, false);
$unreachableAnalysis = $unreachable['analyses']->find($unreachableId);
check('an unreachable engine closes the analysis', $unreachableAnalysis?->status === AnalysisStatus::Failed);
check('an unreachable engine records the reason',
    $unreachableAnalysis?->errorMessage === 'O scanner retornou uma resposta inválida.');
check('an unreachable engine opens no transaction', $unreachable['transactions']->calls === 0);

// A defect must not leave the row running either: it is closed, then the error keeps travelling.
$defect = $makeWorld($okResult);
$defect['register']->execute('Portal', 'https://example.com/', true);
$defectRun = new RunAnalysis(
    $defect['applications'],
    $defect['analyses'],
    $defect['findings'],
    new ThrowingScannerGateway(new LogicException('boom')),
    $defect['transactions'],
);
$propagated = false;
try {
    $defectRun->execute(1, false, false);
} catch (LogicException) {
    $propagated = true;
}
check('an unexpected failure keeps propagating', $propagated);
check('an unexpected failure still closes the analysis',
    $defect['analyses']->find(1)?->status === AnalysisStatus::Failed);

// Two analyses of the same application, so the comparison has something real to classify.
$compareWorld = $makeWorld($okResult);
$compareWorld['register']->execute('Portal', 'https://example.com/', true);
$first = $compareWorld['run']->execute(1, false, false);
$compareWorld['findings']->saveAll($first, [makeFinding(['fingerprint' => 'cookies.no_secure', 'severity' => 'low'])]);
$second = $compareWorld['run']->execute(1, false, false);
$compareWorld['findings']->saveAll($second, [makeFinding(['fingerprint' => 'transport.no_hsts', 'severity' => 'medium'])]);
$comparison = $compareWorld['compare']->execute($first, $second);
check('compare finds the new finding', array_keys($comparison['new']) === ['transport.no_hsts']);
check('compare finds the persistent finding', array_keys($comparison['persistent']) === ['headers.csp_missing']);
check('compare finds the fixed finding', array_keys($comparison['fixed']) === ['cookies.no_secure']);
checkThrows('compare rejects an unknown analysis', NotFound::class,
    static fn() => $compareWorld['compare']->execute($first, 999));

$otherApplication = $compareWorld['register']->execute('Outro', 'https://other.example/', true);
$otherAnalysis = $compareWorld['run']->execute($otherApplication->requireId(), false, false);
checkThrows('compare rejects analyses of different applications', InvalidInput::class,
    static fn() => $compareWorld['compare']->execute($first, $otherAnalysis));

// --- JSON export (machine-readable) --------------------------------------------
$exportWorld = $makeWorld(ScanResult::success([$withExample], 64, 1234, 200));
$exportWorld['register']->execute('Portal', 'https://example.com/', true);
$exportedId = $exportWorld['run']->execute(1, true, true);
$export = $exportWorld['export']->execute($exportedId);
check('export tool name', ($export['tool'] ?? null) === 'SentinelScope');
check('export analysis id is int', ($export['analysis']['id'] ?? null) === $exportedId);
check('export score is int', ($export['analysis']['security_score'] ?? null) === 85);
check('export carries the mode', ($export['analysis']['mode'] ?? null) === 'safe_active');
check('export finding count', ($export['summary']['findings'] ?? null) === 1);
check('export finding carries taxonomy', ($export['findings'][0]['cwe'] ?? null) === 'CWE-693');
check('export finding carries fix example', ($export['findings'][0]['remediation_example']['fixed'] ?? null) !== null);
check('export carries decoded evidence', is_array($export['findings'][0]['evidence'] ?? null));
$json = json_encode($export, JSON_UNESCAPED_UNICODE);
check('export serializes to valid JSON', is_string($json) && json_decode($json, true) !== null);
checkThrows('export rejects an unknown analysis', NotFound::class,
    static fn() => $exportWorld['export']->execute(999));

// --- CA-05 / NFR-01: rendering 1,000 findings stays well under 3 seconds --------
$many = [];
for ($i = 0; $i < 1000; $i++) {
    $many[] = makeFinding([
        'fingerprint' => 'headers.csp_missing.' . $i,
        'remediation_example_vulnerable' => "linha {$i}",
        'remediation_example_fixed' => "corrigido {$i}",
    ]);
}
$start = microtime(true);
$rendered = '';
foreach ($many as $finding) {
    $rendered .= FindingPresenter::render($finding);
}
$elapsed = microtime(true) - $start;
check('rendered all 1,000 findings', substr_count($rendered, '<article class="finding"') === 1000);
check('rendering 1,000 findings under 3s (CA-05), got ' . round($elapsed, 3) . 's', $elapsed < 3.0);

// --- Summary -------------------------------------------------------------------
echo "PHP tests: {$passed} passed, {$failed} failed.\n";
exit($failed === 0 ? 0 : 1);
