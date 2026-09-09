"""Exemplos de código "vulnerável -> corrigido" por verificação (check_id).

Camada de explicabilidade orientada ao desenvolvedor: além do texto de remediação
(uma frase acionável, no catálogo), cada achado pode trazer um par de trechos de
código — o padrão inseguro e a forma corrigida — para que a correção deixe de ser
abstrata. Os identificadores de verificação são os mesmos usados no catálogo passivo
(plugins/catalog.py) e nos catálogos dos plugins ativos (plugins/active/*.py), então
uma única tabela central serve aos dois modos.

O texto e os comentários estão em português (público-alvo: desenvolvedores). Os exemplos
usam PHP para lógica de aplicação e configuração de Apache (.htaccess) para cabeçalhos,
por ser a pilha do projeto e a mais provável do público; a técnica, porém, é a mesma em
qualquer linguagem. Cada entrada é um dicionário com as chaves `vulnerable` e `fixed`, e
opcionalmente `language` (rótulo exibido) e `note` (uma observação curta).

`get(check_id)` devolve um dicionário vazio para verificações sem exemplo, de modo que a
ausência de um exemplo nunca quebra a construção de um achado.
"""
from __future__ import annotations

# --- Blocos reutilizados dentro de uma mesma família ------------------------
# Quando toda a família compartilha exatamente a mesma correção (ex.: toda SQLi
# se corrige com consulta parametrizada), o mesmo par é reaproveitado, evitando
# divergência de orientação entre sub-verificações irmãs.

_SQLI = {
    "language": "PHP (PDO)",
    "vulnerable": (
        "// Entrada do usuario concatenada direto na consulta.\n"
        "$id = $_GET['id'];\n"
        "$sql = \"SELECT * FROM usuarios WHERE id = \" . $id;\n"
        "$linha = $pdo->query($sql)->fetch();"
    ),
    "fixed": (
        "// Consulta parametrizada: o valor nunca vira parte do comando SQL.\n"
        "$stmt = $pdo->prepare('SELECT * FROM usuarios WHERE id = ?');\n"
        "$stmt->execute([$_GET['id']]);\n"
        "$linha = $stmt->fetch();"
    ),
    "note": "Use prepared statements/binding em TODO ponto que recebe entrada; nunca concatene.",
}

_XSS = {
    "language": "PHP",
    "vulnerable": (
        "// Valor refletido na pagina sem codificacao.\n"
        "echo \"<p>Ola, \" . $_GET['nome'] . \"</p>\";"
    ),
    "fixed": (
        "// Codificacao de saida contextual (HTML) neutraliza tags/scripts injetados.\n"
        "$nome = htmlspecialchars($_GET['nome'], ENT_QUOTES | ENT_HTML5, 'UTF-8');\n"
        "echo \"<p>Ola, {$nome}</p>\";"
    ),
    "note": "Codifique na saída conforme o contexto (HTML, atributo, JS, URL) e adote uma CSP restritiva.",
}

_PATH_TRAVERSAL = {
    "language": "PHP",
    "vulnerable": (
        "// '../../etc/passwd' escapa do diretorio pretendido.\n"
        "$arquivo = $_GET['doc'];\n"
        "readfile('/var/app/uploads/' . $arquivo);"
    ),
    "fixed": (
        "$base = '/var/app/uploads/';\n"
        "// Resolve o caminho e exige que continue dentro da base permitida.\n"
        "$alvo = realpath($base . basename($_GET['doc']));\n"
        "if ($alvo === false || !str_starts_with($alvo, realpath($base))) {\n"
        "    http_response_code(400); exit('Caminho invalido');\n"
        "}\n"
        "readfile($alvo);"
    ),
    "note": "Canonicalize com realpath() e valide contra uma allowlist de diretório; prefira um id mapeado ao invés do nome do arquivo.",
}

_OPEN_REDIRECT = {
    "language": "PHP",
    "vulnerable": (
        "// Redireciona para qualquer URL informada pelo usuario.\n"
        "header('Location: ' . $_GET['next']);"
    ),
    "fixed": (
        "// So permite destinos internos (allowlist de rotas conhecidas).\n"
        "$rotas = ['/painel', '/perfil', '/inicio'];\n"
        "$destino = in_array($_GET['next'], $rotas, true) ? $_GET['next'] : '/inicio';\n"
        "header('Location: ' . $destino);"
    ),
    "note": "Nunca redirecione para uma URL crua do usuário; use uma lista de destinos internos permitidos.",
}

_CMD_INJECTION = {
    "language": "PHP",
    "vulnerable": (
        "// Entrada concatenada em um comando de shell.\n"
        "$host = $_GET['host'];\n"
        "system('ping -c 1 ' . $host);"
    ),
    "fixed": (
        "// Sem shell: argumentos passados como lista, escapados individualmente.\n"
        "$host = $_GET['host'];\n"
        "if (!filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {\n"
        "    exit('Host invalido');\n"
        "}\n"
        "$proc = proc_open(['ping', '-c', '1', $host], [1 => ['pipe','w']], $pipes);"
    ),
    "note": "Evite o shell; passe argumentos como array e valide a entrada. Se o shell for inevitável, use escapeshellarg().",
}

_SSTI = {
    "language": "PHP (Twig)",
    "vulnerable": (
        "// Entrada do usuario vira o proprio template (avaliada como codigo).\n"
        "echo $twig->createTemplate('Ola ' . $_GET['nome'])->render();"
    ),
    "fixed": (
        "// A entrada e DADO passado ao template, nunca o template em si.\n"
        "$template = $twig->createTemplate('Ola {{ nome }}');\n"
        "echo $template->render(['nome' => $_GET['nome']]);"
    ),
    "note": "Nunca construa o template com entrada do usuário; passe-a como variável de contexto.",
}

_XXE = {
    "language": "PHP (libxml)",
    "vulnerable": (
        "// Parser processa entidades externas do XML enviado.\n"
        "$doc = new DOMDocument();\n"
        "$doc->loadXML($xmlDoUsuario);"
    ),
    "fixed": (
        "// Desabilita entidades externas antes de carregar XML nao confiavel.\n"
        "libxml_set_external_entity_loader(fn() => null);\n"
        "$doc = new DOMDocument();\n"
        "$doc->loadXML($xmlDoUsuario, LIBXML_NONET | LIBXML_NOENT ^ LIBXML_NOENT);"
    ),
    "note": "Desative resolução de entidades externas (DTD/XXE) no parser e prefira formatos como JSON quando possível.",
}

_CRLF = {
    "language": "PHP",
    "vulnerable": (
        "// \\r\\n na entrada injeta cabecalhos/quebra a resposta.\n"
        "header('Location: /busca?q=' . $_GET['q']);"
    ),
    "fixed": (
        "// Remove CR/LF e codifica antes de usar em cabecalho.\n"
        "$q = str_replace([\"\\r\", \"\\n\"], '', $_GET['q']);\n"
        "header('Location: /busca?q=' . rawurlencode($q));"
    ),
    "note": "Rejeite ou remova CR/LF de qualquer valor que entre em um cabeçalho de resposta.",
}

_HOST_HEADER = {
    "language": "PHP",
    "vulnerable": (
        "// Confia no Host enviado pelo cliente para montar links absolutos.\n"
        "$link = 'https://' . $_SERVER['HTTP_HOST'] . '/redefinir?token=' . $t;"
    ),
    "fixed": (
        "// Usa um host canonico fixo, nao o cabecalho controlado pelo cliente.\n"
        "$HOST_CANONICO = 'app.exemplo.com';\n"
        "$link = 'https://' . $HOST_CANONICO . '/redefinir?token=' . $t;"
    ),
    "note": "Defina um host canônico na aplicação/servidor e valide o cabeçalho Host contra uma allowlist.",
}

_CORS = {
    "language": "PHP",
    "vulnerable": (
        "// Reflete qualquer Origin e ainda libera credenciais.\n"
        "header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);\n"
        "header('Access-Control-Allow-Credentials: true');"
    ),
    "fixed": (
        "// So ecoa a Origin se estiver na allowlist explicita.\n"
        "$permitidas = ['https://app.exemplo.com'];\n"
        "$origin = $_SERVER['HTTP_ORIGIN'] ?? '';\n"
        "if (in_array($origin, $permitidas, true)) {\n"
        "    header('Access-Control-Allow-Origin: ' . $origin);\n"
        "    header('Access-Control-Allow-Credentials: true');\n"
        "}"
    ),
    "note": "Nunca reflita a Origin sem verificar; jamais combine curinga (*) com credenciais.",
}

_NOSQL = {
    "language": "PHP (MongoDB)",
    "vulnerable": (
        "// {\"senha\": {\"$ne\": null}} contorna a autenticacao.\n"
        "$colecao->findOne(['usuario' => $_POST['u'], 'senha' => $_POST['p']]);"
    ),
    "fixed": (
        "// Force o tipo: operadores ($ne, $gt...) so chegam se voce aceitar arrays.\n"
        "$u = (string)($_POST['u'] ?? '');\n"
        "$p = (string)($_POST['p'] ?? '');\n"
        "$colecao->findOne(['usuario' => $u, 'senha' => hash('sha256', $p)]);"
    ),
    "note": "Force os tipos de entrada para string e valide o schema; não repasse arrays crus do corpo à query.",
}

_SSRF = {
    "language": "PHP",
    "vulnerable": (
        "// Busca qualquer URL que o usuario pedir (pode alcancar a rede interna).\n"
        "$conteudo = file_get_contents($_GET['url']);"
    ),
    "fixed": (
        "// Allowlist de host + bloqueio de IPs privados/loopback.\n"
        "$host = parse_url($_GET['url'], PHP_URL_HOST);\n"
        "$ip = gethostbyname($host);\n"
        "if (!in_array($host, ['api.parceiro.com'], true) ||\n"
        "    !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {\n"
        "    exit('Destino nao permitido');\n"
        "}\n"
        "$conteudo = file_get_contents('https://' . $host . '/...');"
    ),
    "note": "Restrinja destinos por allowlist, bloqueie faixas privadas/loopback e não siga redirecionamentos cegamente.",
}

# --- Cabeçalhos e configuração de transporte (correção no servidor) ---------

def _htaccess(header_line: str, extra_note: str = "") -> dict:
    return {
        "language": "Apache (.htaccess) / PHP",
        "vulnerable": "# Resposta atual: o cabecalho abaixo NAO e enviado.",
        "fixed": (
            "# .htaccess (ou vhost) — modulo headers habilitado:\n"
            f"Header always set {header_line}\n\n"
            "// Alternativa em PHP, antes de qualquer saida:\n"
            f"header('{header_line}');"
        ),
        "note": extra_note or "Aplique no servidor web ou em um middleware global, não página a página.",
    }

EXAMPLES: dict[str, dict[str, str]] = {
    # ---- Transporte / TLS -------------------------------------------------
    "transport.https": {
        "language": "Apache (.htaccess)",
        "vulnerable": "# Site servido por http:// simples, sem redirecionamento.",
        "fixed": (
            "# Forca HTTPS para todo o trafego:\n"
            "RewriteEngine On\n"
            "RewriteCond %{HTTPS} off\n"
            "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]"
        ),
        "note": "Redirecione todo HTTP para HTTPS e instale um certificado TLS válido (ex.: Let's Encrypt).",
    },
    "tls.legacy_protocol": {
        "language": "Apache (mod_ssl)",
        "vulnerable": "SSLProtocol all           # permite TLS 1.0/1.1 obsoletos",
        "fixed": "SSLProtocol -all +TLSv1.2 +TLSv1.3   # apenas versoes atuais",
        "note": "Habilite somente TLS 1.2 e 1.3 e desative protocolos e cifras legados.",
    },
    "tls.certificate_expiry": {
        "language": "Shell (certbot)",
        "vulnerable": "# Certificado renovado manualmente e proximo do vencimento.",
        "fixed": (
            "# Renovacao automatica + alerta antes de 30 dias restantes:\n"
            "certbot renew --deploy-hook 'systemctl reload apache2'\n"
            "# agende via cron/systemd-timer duas vezes ao dia"
        ),
        "note": "Automatize a renovação e monitore o prazo restante com alerta.",
    },
    # ---- Cabeçalhos de segurança -----------------------------------------
    "headers.hsts_missing": _htaccess('Strict-Transport-Security "max-age=31536000; includeSubDomains"',
                                      "Só habilite HSTS após confirmar HTTPS em todos os subdomínios."),
    "headers.hsts_weak": _htaccess('Strict-Transport-Security "max-age=31536000; includeSubDomains"',
                                   "Aumente o max-age para pelo menos 31536000 segundos (1 ano)."),
    "headers.csp_missing": {
        "language": "Apache (.htaccess) / PHP",
        "vulnerable": "# Nenhuma Content-Security-Policy e enviada.",
        "fixed": (
            "# Comece em modo relatorio, inventarie as origens e depois aplique:\n"
            "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'self'\""
        ),
        "note": "Implante primeiro como Report-Only, ajuste as origens e então aplique sem unsafe-inline.",
    },
    "headers.csp_report_only": {
        "language": "Apache (.htaccess)",
        "vulnerable": "Header set Content-Security-Policy-Report-Only \"default-src 'self'\"   # nao bloqueia",
        "fixed": "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'\"",
        "note": "Depois de corrigir as violações relatadas, publique a mesma política em Content-Security-Policy.",
    },
    "headers.csp_unsafe_inline": {
        "language": "CSP + HTML",
        "vulnerable": "Content-Security-Policy: script-src 'self' 'unsafe-inline'",
        "fixed": (
            "# Autorize scripts por nonce em vez de 'unsafe-inline':\n"
            "Content-Security-Policy: script-src 'self' 'nonce-r4nd0m'\n"
            "<script nonce=\"r4nd0m\">...</script>"
        ),
        "note": "Troque scripts inline por arquivos externos ou autorize-os por nonce/hash.",
    },
    "headers.csp_unsafe_eval": {
        "language": "CSP + JS",
        "vulnerable": "Content-Security-Policy: script-src 'self' 'unsafe-eval'",
        "fixed": (
            "# Remova APIs tipo eval() do codigo e retire 'unsafe-eval':\n"
            "Content-Security-Policy: script-src 'self'\n"
            "// ex.: JSON.parse(texto) no lugar de eval('(' + texto + ')')"
        ),
        "note": "Elimine eval()/new Function() e remova unsafe-eval da política.",
    },
    "headers.csp_wildcard": {
        "language": "CSP",
        "vulnerable": "Content-Security-Policy: script-src *   # confia em qualquer origem",
        "fixed": "Content-Security-Policy: script-src 'self' https://cdn.confiavel.com",
        "note": "Substitua o curinga pela menor lista explícita de origens necessárias.",
    },
    "headers.frame_options_missing": _htaccess('Content-Security-Policy "frame-ancestors \'none\'"',
                                               "frame-ancestors no CSP é o mecanismo atual; X-Frame-Options: DENY é fallback legado."),
    "headers.nosniff_missing": _htaccess('X-Content-Type-Options "nosniff"',
                                         "Impede o navegador de adivinhar (sniff) o tipo de conteúdo."),
    "headers.referrer_policy_missing": _htaccess('Referrer-Policy "strict-origin-when-cross-origin"',
                                                 "Evita vazar a URL completa (com tokens) para terceiros."),
    "headers.permissions_policy_missing": _htaccess('Permissions-Policy "geolocation=(), camera=(), microphone=()"',
                                                    "Desabilite recursos do navegador que a aplicação não usa."),
    "headers.coop_missing": _htaccess('Cross-Origin-Opener-Policy "same-origin"',
                                      "Isola o contexto de navegação de janelas de outras origens."),
    "headers.corp_missing": _htaccess('Cross-Origin-Resource-Policy "same-origin"',
                                      "Impede que outras origens embutam este recurso."),
    "headers.content_type_missing": {
        "language": "PHP",
        "vulnerable": "// Resposta sem Content-Type explicito (navegador adivinha).",
        "fixed": "header('Content-Type: text/html; charset=UTF-8');",
        "note": "Sempre declare Content-Type e charset explicitamente.",
    },
    # ---- Cookies ----------------------------------------------------------
    "cookies.missing_secure": {
        "language": "PHP",
        "vulnerable": "setcookie('sessao', $id);   // trafega tambem em HTTP",
        "fixed": "setcookie('sessao', $id, ['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);",
        "note": "Marque cookies de sessão como Secure, HttpOnly e SameSite.",
    },
    "cookies.missing_httponly": {
        "language": "PHP",
        "vulnerable": "setcookie('sessao', $id, ['secure' => true]);   // acessivel via JS",
        "fixed": "setcookie('sessao', $id, ['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);",
        "note": "HttpOnly impede que scripts (XSS) leiam o cookie de sessão.",
    },
    "cookies.missing_samesite": {
        "language": "PHP",
        "vulnerable": "setcookie('sessao', $id, ['secure' => true, 'httponly' => true]);",
        "fixed": "setcookie('sessao', $id, ['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);",
        "note": "SameSite=Lax (ou Strict) reduz a superfície de CSRF.",
    },
    "cookies.broad_domain": {
        "language": "PHP",
        "vulnerable": "setcookie('sessao', $id, ['domain' => '.exemplo.com']);   // vale p/ todo subdominio",
        "fixed": "setcookie('sessao', $id, ['domain' => 'app.exemplo.com', 'secure' => true, 'httponly' => true]);",
        "note": "Restrinja o domínio do cookie ao host exato que precisa dele.",
    },
    "cookies.samesite_none_insecure": {
        "language": "PHP",
        "vulnerable": "setcookie('sessao', $id, ['samesite' => 'None']);   // sem Secure",
        "fixed": "setcookie('sessao', $id, ['samesite' => 'None', 'secure' => true, 'httponly' => true]);",
        "note": "SameSite=None exige obrigatoriamente o atributo Secure.",
    },
    # ---- CORS passivo -----------------------------------------------------
    "cors.wildcard_origin": _CORS,
    "cors.credentials_with_wildcard": _CORS,
    # ---- Cache ------------------------------------------------------------
    "cache.sensitive_no_store_missing": {
        "language": "PHP",
        "vulnerable": "// Pagina autenticada sem diretiva de cache (pode ser guardada).",
        "fixed": (
            "header('Cache-Control: no-store, no-cache, must-revalidate, private');\n"
            "header('Pragma: no-cache');"
        ),
        "note": "Em respostas com dados sensíveis, use Cache-Control: no-store.",
    },
    # ---- Exposição de informação -----------------------------------------
    "disclosure.server_header": {
        "language": "Apache",
        "vulnerable": "ServerTokens Full          # expoe versao exata do servidor",
        "fixed": "ServerTokens Prod\nServerSignature Off",
        "note": "Reduza a informação de versão nos cabeçalhos do servidor.",
    },
    "disclosure.powered_by_header": {
        "language": "PHP (php.ini)",
        "vulnerable": "expose_php = On            # envia X-Powered-By: PHP/8.x",
        "fixed": "expose_php = Off\n; ou: header_remove('X-Powered-By');",
        "note": "Remova cabeçalhos que revelam a tecnologia e a versão.",
    },
    "disclosure.stack_trace": {
        "language": "PHP (php.ini / app)",
        "vulnerable": "display_errors = On        // stack trace vai para o usuario final",
        "fixed": (
            "// Producao: registre o erro, mostre mensagem generica.\n"
            "display_errors = Off\n"
            "log_errors = On\n"
            "// e capture excecoes com um handler que responde 500 sem detalhes"
        ),
        "note": "Nunca exiba stack traces ao usuário; registre-os no servidor e responda algo genérico.",
    },
    "disclosure.directory_listing": {
        "language": "Apache",
        "vulnerable": "Options +Indexes           # lista o conteudo de diretorios",
        "fixed": "Options -Indexes",
        "note": "Desative a listagem de diretórios no servidor.",
    },
    "disclosure.source_map": {
        "language": "Build / Deploy",
        "vulnerable": "// app.js.map publicado em producao (expoe o codigo-fonte).",
        "fixed": (
            "// Nao publique source maps em producao, ou restrinja o acesso:\n"
            "// webpack: devtool: false  (em producao)\n"
            "<Files \"*.map\">Require ip 10.0.0.0/8</Files>"
        ),
        "note": "Não sirva arquivos .map publicamente em produção.",
    },
    "disclosure.mixed_content": {
        "language": "HTML",
        "vulnerable": "<script src=\"http://cdn.exemplo.com/app.js\"></script>",
        "fixed": "<script src=\"https://cdn.exemplo.com/app.js\"></script>",
        "note": "Sirva todos os recursos por HTTPS; use upgrade-insecure-requests na CSP como rede de segurança.",
    },
    "disclosure.password_over_http": {
        "language": "HTML + servidor",
        "vulnerable": "<form action=\"http://exemplo.com/login\" method=\"post\">   <!-- senha em claro -->",
        "fixed": "<form action=\"https://exemplo.com/login\" method=\"post\">   <!-- + HSTS no servidor -->",
        "note": "Formulários com senha só devem ser enviados por HTTPS.",
    },
    # ---- Segredos ---------------------------------------------------------
    "secrets.high_confidence_pattern": {
        "language": "PHP / config",
        "vulnerable": "$apiKey = 'AKIA1234567890ABCDEF';   // credencial no codigo",
        "fixed": (
            "// Leia de variavel de ambiente; nunca versione o segredo.\n"
            "$apiKey = getenv('API_KEY');\n"
            "// e ROTACIONE a chave exposta imediatamente"
        ),
        "note": "Mova segredos para variáveis de ambiente/cofre e rotacione qualquer credencial exposta.",
    },
    "secrets.heuristic_pattern": {
        "language": "PHP / config",
        "vulnerable": "define('DB_PASS', 's3nh4Sup3rSecreta!');   // no repositorio",
        "fixed": "define('DB_PASS', getenv('DB_PASS'));   // fora do codigo, via ambiente",
        "note": "Não deixe valores de alta entropia (chaves/senhas) embutidos no código.",
    },
    # ---- Injeção de SQL (ativo) -------------------------------------------
    "sqli.error_based": _SQLI,
    "sqli.boolean_differential": _SQLI,
    "sqli.time_based": _SQLI,
    # ---- XSS refletido (ativo) -------------------------------------------
    "xss.reflected_html_text": _XSS,
    "xss.reflected_html_attribute": _XSS,
    "xss.reflected_script_context": _XSS,
    # ---- Travessia de diretório (ativo) ----------------------------------
    "path_traversal.file_disclosure": _PATH_TRAVERSAL,
    "path_traversal.suspicious_behavior": _PATH_TRAVERSAL,
    # ---- Redirecionamento aberto (ativo) ---------------------------------
    "open_redirect.confirmed_header": _OPEN_REDIRECT,
    "open_redirect.client_side_suspected": _OPEN_REDIRECT,
    # ---- Injeção de comando (ativo) --------------------------------------
    "command_injection.marker_confirmed": _CMD_INJECTION,
    "command_injection.marker_suspected": _CMD_INJECTION,
    "command_injection.timing_suspected": _CMD_INJECTION,
    # ---- SSTI (ativo) -----------------------------------------------------
    "ssti.expression_evaluated": _SSTI,
    # ---- XXE (ativo) ------------------------------------------------------
    "xxe.internal_entity_expansion": _XXE,
    "xxe.external_entity_processing_suspected": _XXE,
    # ---- CRLF (ativo) -----------------------------------------------------
    "crlf.header_injection_confirmed": _CRLF,
    # ---- Host header (ativo) ---------------------------------------------
    "host_header.reflected_in_redirect": _HOST_HEADER,
    "host_header.reflected_in_body": _HOST_HEADER,
    # ---- Adulteração de verbo HTTP (ativo) -------------------------------
    "http_verb_tampering.destructive_method_accepted": {
        "language": "Apache / app",
        "vulnerable": "# Todos os metodos aceitos indistintamente em qualquer rota.",
        "fixed": (
            "# Restrinja metodos por rota e desabilite os nao usados:\n"
            "<LimitExcept GET POST>Require all denied</LimitExcept>\n"
            "// na aplicacao, valide $_SERVER['REQUEST_METHOD'] explicitamente"
        ),
        "note": "Aceite apenas os métodos que cada rota realmente precisa.",
    },
    "http_verb_tampering.method_bypass_suspected": {
        "language": "app",
        "vulnerable": "// Autorizacao verificada so no GET; outros verbos passam.",
        "fixed": "// Aplique a mesma checagem de autorizacao a TODOS os metodos da rota.",
        "note": "Não vincule controle de acesso a um verbo específico; valide todos.",
    },
    "http_verb_tampering.trace_enabled": {
        "language": "Apache",
        "vulnerable": "# Metodo TRACE habilitado (Cross-Site Tracing).",
        "fixed": "TraceEnable off",
        "note": "Desabilite o método TRACE no servidor.",
    },
    # ---- Injeção NoSQL (ativo) -------------------------------------------
    "nosql_injection.operator_bypass_confirmed": _NOSQL,
    "nosql_injection.array_type_confusion_suspected": _NOSQL,
    # ---- CORS ativo -------------------------------------------------------
    "cors.origin_reflected": _CORS,
    "cors.credentials_with_reflected_origin": _CORS,
    "cors.null_origin_allowed": _CORS,
    "cors.lookalike_origin_accepted": _CORS,
    # ---- SSRF (ativo) -----------------------------------------------------
    "ssrf.error_signature_suspected": _SSRF,
    "ssrf.timing_signature_suspected": _SSRF,
}

def get(check_id: str) -> dict[str, str]:
    """Devolve {'language','vulnerable','fixed','note'} para o check_id, ou {} se não houver."""
    return EXAMPLES.get(check_id, {})
