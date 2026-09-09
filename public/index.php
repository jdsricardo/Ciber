<?php
require __DIR__.'/../app/bootstrap.php';

use App\Database;
use App\Presentation\FindingPresenter;
use App\Presentation\Layout;
use App\Repositories\AnalysisRepository;
use App\Repositories\ApplicationRepository;
use App\Repositories\FindingRepository;
use App\Scanner\ScannerClient;
use App\Security\Csrf;
use App\Support\Scoring;

$applicationRepository = new ApplicationRepository();
$analysisRepository = new AnalysisRepository();
$findingRepository = new FindingRepository();
$scannerClient = new ScannerClient();

$page=$_GET['page']??'home';
try {
if($_SERVER['REQUEST_METHOD']==='POST'){
    Csrf::check();
    if($page==='create'){
        $name=trim($_POST['name']??'');$url=trim($_POST['url']??'');$scheme=parse_url($url,PHP_URL_SCHEME);
        if($name===''||!filter_var($url,FILTER_VALIDATE_URL)||!in_array($scheme,['http','https'],true)||!isset($_POST['authorized']))throw new InvalidArgumentException('Informe um nome, uma URL HTTP(S) válida e confirme a autorização.');
        $applicationRepository->create($name,$url);
        $_SESSION['notice']='Aplicação registrada.';go('index.php');
    }
    if($page==='run'){
        $app=$applicationRepository->find((int)($_POST['application_id']??0));if(!$app)throw new InvalidArgumentException('Aplicação não encontrada.');
        $mode=(!empty($_POST['mode_active'])&&!empty($_POST['authorized_active']))?ScannerClient::MODE_SAFE_ACTIVE:ScannerClient::MODE_PASSIVE;
        $id=$analysisRepository->createRunning($app['id'],$mode);
        $sessionCookie=trim($_POST['session_cookie']??''); // usado só nesta análise, nunca persistido
        $result=$scannerClient->scan($app['base_url'],$mode,$sessionCookie);
        if(empty($result['ok'])){$analysisRepository->markFailed($id,$result['error']??'Erro desconhecido');go('index.php?page=result&id='.$id);}
        Database::transaction(function() use ($findingRepository,$analysisRepository,$id,$result){
            $findingRepository->insertMany($id,$result['findings']);
            $analysisRepository->markCompleted($id,Scoring::calculate($result['findings']),(int)$result['checks_run'],(int)$result['duration_ms'],(int)$result['status_code']);
        });
        go('index.php?page=result&id='.$id);
    }
}
if($page==='add'){
    Layout::render('Adicionar aplicação','<section class="intro compact"><p class="eyebrow">ALVO AUTORIZADO</p><h1>Registrar uma aplicação</h1><p>O scanner envia apenas requisições de teste seguras e não destrutivas. Analise apenas alvos que você possui ou está autorizado a avaliar.</p></section><form class="card form" method="post" action="index.php?page=create"><input type="hidden" name="csrf" value="'.Csrf::token().'"><label>Nome da aplicação<input name="name" maxlength="120" required placeholder="Portal do Cliente"></label><label>URL base<input name="url" type="url" required placeholder="https://staging.example.com/"></label><label class="check"><input type="checkbox" name="authorized" value="1" required><span>Confirmo que sou o proprietário deste alvo ou possuo autorização explícita.</span></label><button>Registrar aplicação</button></form>');exit;
}
if($page==='result'||$page==='report'){
    $a=$analysisRepository->find((int)($_GET['id']??0));if(!$a)throw new InvalidArgumentException('Análise não encontrada.');$rows=$findingRepository->byAnalysis((int)$a['id']);$list='';
    foreach($rows as $f)$list.=FindingPresenter::render($f);
    $modeLabel=$a['mode']===ScannerClient::MODE_SAFE_ACTIVE?'Completa (ativa)':'Passiva';
    $sevCounts=['critical'=>0,'high'=>0,'medium'=>0,'low'=>0];foreach($rows as $r){if(isset($sevCounts[$r['severity']]))$sevCounts[$r['severity']]++;}
    $sevBar='';if($rows){$chips='<button data-filter="all" class="sev-chip active">Todos <b>'.count($rows).'</b></button>';foreach($sevCounts as $sev=>$n){if($n>0)$chips.='<button data-filter="'.$sev.'" class="sev-chip '.$sev.'">'.e(FindingPresenter::severityLabel($sev)).' <b>'.$n.'</b></button>';}$sevBar='<div class="sev-filter no-print" data-severity-filter>'.$chips.'</div>';}
    $buttons=$page==='report'?'<button onclick="print()">Imprimir / Salvar como PDF</button>':'<a class="button secondary" href="index.php?page=report&id='.$a['id'].'">Relatório para impressão</a> <a class="button secondary" href="index.php?page=export&id='.$a['id'].'">Exportar JSON</a>';
    $body='<div class="toolbar no-print"><a href="index.php">&larr; Painel</a>'.$buttons.'</div><section class="result-header"><div><p class="eyebrow">ANÁLISE #'.(int)$a['id'].' &middot; MODO: '.e(strtoupper($modeLabel)).'</p><h1>'.e($a['application_name']).'</h1><p>'.e($a['base_url']).' &middot; '.e($a['completed_at']??$a['started_at']).' UTC</p></div><div class="score"><strong>'.($a['security_score']??'N/D').'</strong><span>Pontuação de Segurança</span></div></section>';
    if($a['status']==='failed')$body.='<div class="error"><b>A análise não pôde ser concluída.</b><br>'.e($a['error_message']).'</div>';else $body.='<div class="metrics"><div><span>Verificações executadas</span><b>'.(int)$a['checks_run'].'</b></div><div><span>Achados</span><b>'.count($rows).'</b></div><div><span>Status HTTP</span><b>'.(int)$a['http_status'].'</b></div><div><span>Duração</span><b>'.(int)$a['duration_ms'].' ms</b></div></div><h2>O que sua equipe deve corrigir</h2>'.$sevBar.($list !== '' ? $list : '<div class="empty">Nenhum problema foi detectado pelas verificações configuradas.</div>').'<section class="limitations"><h2>Escopo e limitações</h2><p>'.($modeLabel==='Passiva'?'Esta é uma avaliação passiva: apenas observação de respostas, sem envio de payloads de teste.':'Esta análise incluiu testes ativos com payloads seguros e não destrutivos.').' Ela não prova a ausência de vulnerabilidades e não substitui um teste de intrusão profissional.</p></section>';
    Layout::render($page==='report'?'Relatório de segurança':'Resultado da análise',$body);exit;
}
if($page==='export'){
    $a=$analysisRepository->find((int)($_GET['id']??0));if(!$a)throw new InvalidArgumentException('Análise não encontrada.');
    $doc=App\Support\AnalysisExport::toArray($a,$findingRepository->byAnalysis((int)$a['id']));
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="sentinelscope-analise-'.(int)$a['id'].'.json"');
    echo json_encode($doc,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);exit;
}
if($page==='compare'){
    $old=$analysisRepository->find((int)($_GET['old']??0));$new=$analysisRepository->find((int)($_GET['new']??0));if(!$old||!$new||$old['application_id']!==$new['application_id'])throw new InvalidArgumentException('Escolha análises da mesma aplicação.');
    $diff=App\Support\AnalysisComparison::diff($findingRepository->byAnalysis((int)$old['id']),$findingRepository->byAnalysis((int)$new['id']));
    $section=function(string $title,array $rows,string $type){$html='<section class="card"><h2>'.$title.' <small>'.count($rows).'</small></h2>';foreach($rows as $r)$html.='<div class="compare '.$type.'"><b>'.e($r['title']).'</b><span>'.e($r['severity']).'</span></div>';return $html.'</section>';};
    Layout::render('Comparação','<div class="toolbar"><a href="index.php">← Painel</a></div><h1>O que mudou?</h1><p>Análise #'.$old['id'].' → #'.$new['id'].' · Pontuação '.$old['security_score'].' → '.$new['security_score'].'</p><div class="comparison">'.$section('Novos problemas',$diff['new'],'new').$section('Ainda presentes',$diff['persistent'],'same').$section('Corrigidos',$diff['fixed'],'fixed').'</div>');exit;
}
if($page==='about'){Layout::render('Sobre','<section class="intro"><p class="eyebrow">FEITO PARA DESENVOLVEDORES</p><h1>Achados de segurança que você pode transformar em mudanças de código.</h1><p>O SentinelScope traduz observações HTTP em impacto compreensível e remediação prática. O modo passivo apenas observa; o modo completo testa ativamente parâmetros com payloads seguros (SQL Injection, XSS e outros) e sempre para assim que a evidência mínima necessária é obtida.</p></section>');exit;}
$apps=$applicationRepository->all();$cards='';
foreach($apps as $app){$history=$analysisRepository->listByApplication((int)$app['id']);$options='';$table='';foreach($history as $h){$options.='<option value="'.$h['id'].'">#'.$h['id'].' · '.e($h['started_at']).'</option>';$table.='<tr><td><a href="index.php?page=result&id='.$h['id'].'">#'.$h['id'].'</a></td><td>'.e($h['started_at']).'</td><td>'.($h['mode']===ScannerClient::MODE_SAFE_ACTIVE?'Ativa':'Passiva').'</td><td>'.e($h['status']).'</td><td>'.($h['security_score']??'—').'</td><td>'.(int)($h['checks_run']??0).'</td></tr>';}$compare=count($history)>1?'<form class="compare-form" action="index.php"><input type="hidden" name="page" value="compare"><select name="old">'.$options.'</select><span>até</span><select name="new">'.$options.'</select><button class="secondary">Comparar</button></form>':'';$cards.='<section class="card"><div class="app-head"><div><h2>'.e($app['name']).'</h2><p>'.e($app['base_url']).'</p></div></div><form method="post" action="index.php?page=run" class="run-form"><input type="hidden" name="csrf" value="'.Csrf::token().'"><input type="hidden" name="application_id" value="'.$app['id'].'"><label class="check"><input type="checkbox" name="mode_active" value="1" onchange="this.form.authorized_active.closest(\'label\').style.display=this.checked?\'flex\':\'none\'"><span>Análise completa (ativa) — testa parâmetros com SQL Injection, XSS e outros payloads seguros</span></label><label class="check" style="display:none"><input type="checkbox" name="authorized_active" value="1"><span>Autorizo o envio de payloads de teste ativos e não destrutivos contra este alvo.</span></label><details class="auth-details"><summary>Área autenticada (opcional)</summary><label>Cookie de sessão<input name="session_cookie" placeholder="PHPSESSID=...; outro=valor" autocomplete="off"></label><p class="muted">Enviado apenas ao alvo autorizado nesta análise e não armazenado.</p></details><button>Executar análise</button></form>'.$compare.($table?'<div class="scroll"><table><thead><tr><th>ID</th><th>Data (UTC)</th><th>Modo</th><th>Status</th><th>Pontuação</th><th>Verificações</th></tr></thead><tbody>'.$table.'</tbody></table></div>':'<p class="muted">Nenhuma análise ainda.</p>').'</section>';}
Layout::render('Painel','<section class="intro"><p class="eyebrow">BANCADA DE SEGURANÇA PARA DESENVOLVEDORES</p><h1>Encontre o risco.<br><span>Entregue a correção.</span></h1><p>Execute verificações autorizadas, passivas ou ativas e não destrutivas, e receba evidências que sua equipe de desenvolvimento entende e consegue agir.</p><a class="button" href="index.php?page=add">Adicionar uma aplicação</a></section><div class="section-head"><h2>Aplicações</h2><span>'.count($apps).' registrada(s)</span></div>'.($cards !== '' ? $cards : '<div class="empty">Nenhuma aplicação registrada ainda.</div>'));
} catch(Throwable $error){Database::rollBackIfActive();http_response_code(400);Layout::render('Erro','<div class="error"><b>A requisição não pôde ser concluída.</b><br>'.e($error->getMessage()).'</div><a href="index.php">Voltar ao painel</a>');}
