<?php

declare(strict_types=1);

/**
 * Front controller: wires the adapters to the use cases, dispatches one request, and turns any
 * domain error into a response. It holds no rules of its own — reading a route here should tell
 * you which use case runs, and nothing more.
 */

require __DIR__ . '/../app/bootstrap.php';

use App\Domain\Exception\DomainError;
use App\Domain\Exception\NotFound;
use App\Infrastructure\Database;
use App\Infrastructure\Persistence\PdoAnalysisRepository;
use App\Infrastructure\Persistence\PdoApplicationRepository;
use App\Infrastructure\Persistence\PdoFindingRepository;
use App\Infrastructure\Persistence\PdoTransactionManager;
use App\Infrastructure\Scanner\PythonScannerGateway;
use App\Infrastructure\Security\Csrf;
use App\Presentation\Layout;
use App\Presentation\Views;
use App\UseCase\CompareAnalyses;
use App\UseCase\ExportAnalysis;
use App\UseCase\RegisterApplication;
use App\UseCase\RunAnalysis;

$applications = new PdoApplicationRepository();
$analyses = new PdoAnalysisRepository();
$findings = new PdoFindingRepository();

$registerApplication = new RegisterApplication($applications);
$runAnalysis = new RunAnalysis(
    $applications,
    $analyses,
    $findings,
    new PythonScannerGateway(),
    new PdoTransactionManager(),
);
$compareAnalyses = new CompareAnalyses($analyses, $findings);
$exportAnalysis = new ExportAnalysis($analyses, $findings);

$page = (string) ($_GET['page'] ?? 'home');

try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        Csrf::check();

        if ($page === 'create') {
            $registerApplication->execute(
                (string) ($_POST['name'] ?? ''),
                (string) ($_POST['url'] ?? ''),
                isset($_POST['authorized']),
            );
            $_SESSION['notice'] = 'Aplicação registrada.';
            go('index.php');
        }

        if ($page === 'run') {
            $analysisId = $runAnalysis->execute(
                (int) ($_POST['application_id'] ?? 0),
                !empty($_POST['mode_active']),
                !empty($_POST['authorized_active']),
                // Used only for this analysis and never persisted.
                trim((string) ($_POST['session_cookie'] ?? '')),
            );
            go('index.php?page=result&id=' . $analysisId);
        }
    }

    if ($page === 'add') {
        Layout::render('Adicionar aplicação', Views::addApplication(Csrf::token()));
        exit;
    }

    if ($page === 'about') {
        Layout::render('Sobre', Views::about());
        exit;
    }

    if ($page === 'result' || $page === 'report') {
        $analysis = $analyses->find((int) ($_GET['id'] ?? 0))
            ?? throw new NotFound('Análise não encontrada.');
        $printable = $page === 'report';
        Layout::render(
            $printable ? 'Relatório de segurança' : 'Resultado da análise',
            Views::analysisResult($analysis, $findings->byAnalysis($analysis->requireId()), $printable),
        );
        exit;
    }

    if ($page === 'export') {
        $analysisId = (int) ($_GET['id'] ?? 0);
        $document = $exportAnalysis->execute($analysisId);
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="sentinelscope-analise-' . $analysisId . '.json"');
        echo json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }

    if ($page === 'compare') {
        $diff = $compareAnalyses->execute((int) ($_GET['old'] ?? 0), (int) ($_GET['new'] ?? 0));
        Layout::render('Comparação', Views::comparison($diff));
        exit;
    }

    $registered = $applications->all();
    $history = [];
    foreach ($registered as $application) {
        $history[$application->requireId()] = $analyses->listByApplication($application->requireId());
    }
    Layout::render('Painel', Views::dashboard($registered, $history, Csrf::token()));
} catch (DomainError $error) {
    // A rule the request broke: the message is already written for the developer using the app.
    Database::rollBackIfActive();
    http_response_code($error->httpStatus());
    Layout::render('Erro', Views::error($error->getMessage()));
} catch (Throwable $error) {
    // Anything else is a defect or an environment failure: log the detail, show a generic page.
    Database::rollBackIfActive();
    error_log('SentinelScope: ' . $error);
    http_response_code(500);
    Layout::render('Erro', Views::error('Ocorreu um erro inesperado. Consulte o log do servidor.'));
}
