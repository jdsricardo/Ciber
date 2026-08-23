<?php
declare(strict_types=1);
const ROOT = __DIR__ . '/..';
function loadEnvironment(string $file): void {
    if (!is_file($file)) { http_response_code(503); exit('Setup required: copy .env.example to .env and import database.sql.'); }
    foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line=trim($line); if($line===''||str_starts_with($line,'#')||!str_contains($line,'='))continue;
        [$name,$value]=array_map('trim',explode('=',$line,2));
        if(!preg_match('/^[A-Z][A-Z0-9_]*$/',$name))continue;
        if(strlen($value)>=2 && (($value[0]==='"'&&$value[-1]==='"')||($value[0]==="'"&&$value[-1]==="'")))$value=substr($value,1,-1);
        if(getenv($name)===false){putenv($name.'='.$value);$_ENV[$name]=$value;}
    }
}
function env(string $name, ?string $default=null): string { $value=getenv($name);return $value===false?$default??'':$value; }
function envBool(string $name, bool $default=false): bool { return filter_var(env($name,$default?'true':'false'),FILTER_VALIDATE_BOOLEAN); }
loadEnvironment(ROOT.'/.env');
$config=[
    'db'=>['host'=>env('DB_HOST','127.0.0.1'),'port'=>(int)env('DB_PORT','3306'),'name'=>env('DB_NAME','sentinelscope'),'user'=>env('DB_USER'),'password'=>env('DB_PASSWORD'),'charset'=>'utf8mb4'],
    'python_binary'=>env('PYTHON_BINARY','python'),
    'allow_private_targets'=>envBool('ALLOW_PRIVATE_TARGETS'),
];
date_default_timezone_set('UTC');
session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Lax', 'use_strict_mode' => true]);

function config(?string $key = null): mixed { global $config; return $key === null ? $config : ($config[$key] ?? null); }
function db(): PDO {
    static $pdo;
    if (!$pdo) {
        $c = config('db');
        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $c['host'], $c['port'], $c['name'], $c['charset']);
        $pdo = new PDO($dsn, $c['user'], $c['password'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
    }
    return $pdo;
}
function e(mixed $value): string { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function csrf(): string { return $_SESSION['csrf'] ??= bin2hex(random_bytes(32)); }
function checkCsrf(): void { if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) throw new RuntimeException('Your session token expired. Refresh the page and try again.'); }
function go(string $url): never { header('Location: ' . $url); exit; }
function one(string $sql, array $params): array|false { $s=db()->prepare($sql);$s->execute($params);return $s->fetch(); }
function all(string $sql, array $params=[]): array { $s=db()->prepare($sql);$s->execute($params);return $s->fetchAll(); }
function analysis(int $id): array|false { return one('SELECT n.*,a.name application_name,a.base_url FROM analyses n JOIN applications a ON a.id=n.application_id WHERE n.id=?',[$id]); }
function findings(int $id): array { return all("SELECT * FROM findings WHERE analysis_id=? ORDER BY FIELD(severity,'critical','high','medium','low'),title",[$id]); }
function calculateScore(array $rows): int { $weights=['critical'=>30,'high'=>15,'medium'=>7,'low'=>2];$penalty=0;foreach($rows as $row)$penalty+=$weights[$row['severity']]??0;return max(0,100-$penalty); }
function scanner(string $url): array {
    $cmd=escapeshellarg(config('python_binary')).' '.escapeshellarg(ROOT.'/scanner/scanner.py').' '.escapeshellarg($url);
    if(config('allow_private_targets'))$cmd.=' --allow-private';
    $output=shell_exec($cmd.' 2>&1');$data=json_decode(trim((string)$output),true);
    if(!is_array($data))throw new RuntimeException('The scanner returned an invalid response. Verify the Python configuration.');
    return $data;
}
function page(string $title,string $content): void {
    $notice=$_SESSION['notice']??'';unset($_SESSION['notice']);
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.e($title).' · SentinelScope</title><link rel="stylesheet" href="assets/app.css"></head><body><header><a class="brand" href="index.php">Sentinel<span>Scope</span></a><nav><a href="index.php">Dashboard</a><a href="index.php?page=add">Add application</a><a href="index.php?page=about">About</a></nav></header><main>'.($notice?'<div class="notice">'.e($notice).'</div>':'').$content.'</main><footer>SentinelScope 1.0 · Developer-first, authorized security assessment</footer></body></html>';
}
