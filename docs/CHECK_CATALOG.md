# Catálogo de verificações

> Gerado a partir do código (`checks` de cada plugin e seus catálogos de texto). Total: **34 verificações passivas** em 7 plugins e **30 verificações ativas** em 13 plugins — **64 no modo completo**.

Cada arquivo de `scanner/plugins/` é **um plugin**, responsável por **uma família** de
vulnerabilidade, e cada plugin contém **várias verificações** (os ids listados em
`metadata.checks`). O número "verificações executadas" de uma análise é a soma desses ids
(`ScanRunner.rule_count`): indica quantas regras rodaram em cada página, não quantas se
aplicaram — cada verificação só é avaliada quando a página tem o que ela examina (coluna
**Quando é avaliado**).

A **severidade** não é fixa: o plugin a define na execução conforme o contexto da página (por
exemplo, falta de CSP é *alta* numa página com formulário e *média* numa página estática). A
**confiança** é calculada à parte, em `scanner/engine/confidence.py`.

- **Passivo** (`--mode=passive`): só lê as duas respostas normais (baselines) de cada página;
  nenhuma requisição extra.
- **Completo** (`--mode=safe_active`): passivo + plugins de `scanner/plugins/active/`, que enviam
  sondas seguras e limitadas (orçamento por página e por análise em `ACTIVE_LIMITS`).


## Verificações passivas


### Transport Security — 5 verificação(ões)

Arquivo: [`scanner/plugins/transport.py`](../scanner/plugins/transport.py) · classe `TransportSecurityPlugin` · OWASP A04:2025 Cryptographic Failures · WSTG WSTG-CRYP-01,WSTG-CONF-07

**Quando é avaliado:** Toda página. Se a URL for `http://`, registra só `transport.https` e para; as de TLS e HSTS só são avaliadas em `https://`.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `transport.https` | Conexão não é criptografada | A página foi obtida via HTTP simples em vez de HTTPS. | CWE-319 |
| `tls.legacy_protocol` | Protocolo TLS obsoleto em uso | O servidor negociou uma versão de TLS descontinuada. | CWE-326 |
| `tls.certificate_expiry` | Certificado TLS expira em breve | O tempo restante de validade do certificado TLS é curto. | CWE-298 |
| `headers.hsts_missing` | Navegador pode ser rebaixado para HTTP | A resposta HTTPS não envia o cabeçalho Strict-Transport-Security. | CWE-319 |
| `headers.hsts_weak` | Política de HSTS é muito curta | Strict-Transport-Security está presente, mas seu max-age é curto. | CWE-693 |


### Security Headers — 12 verificação(ões)

Arquivo: [`scanner/plugins/headers.py`](../scanner/plugins/headers.py) · classe `SecurityHeadersPlugin` · OWASP A02:2025 Security Misconfiguration · WSTG WSTG-CONF-12,WSTG-CLNT-09

**Quando é avaliado:** Somente respostas HTML. As de CSP fraca (`unsafe-inline`, `unsafe-eval`, curinga) só quando existe CSP; `frame_options_missing` só quando a CSP não tem `frame-ancestors`.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `headers.csp_missing` | Navegador não possui política de execução de conteúdo | Nenhum cabeçalho Content-Security-Policy foi retornado. | CWE-693 |
| `headers.csp_report_only` | Política de conteúdo está em modo somente-relatório | Apenas Content-Security-Policy-Report-Only foi retornado, sem um CSP aplicado. | CWE-693 |
| `headers.csp_unsafe_inline` | CSP permite execução de script inline | O CSP aplicado contém `unsafe-inline`. | CWE-693 |
| `headers.csp_unsafe_eval` | CSP permite avaliação dinâmica de código | O CSP aplicado contém `unsafe-eval`. | CWE-693 |
| `headers.csp_wildcard` | CSP confia em uma origem coringa | Uma diretiva do CSP aceita `*` como origem. | CWE-693 |
| `headers.frame_options_missing` | Página pode ser incorporada em outro site | Nem CSP frame-ancestors nem X-Frame-Options foram retornados. | CWE-1021 |
| `headers.nosniff_missing` | Navegador pode adivinhar o tipo de conteúdo da resposta | X-Content-Type-Options está ausente ou não é `nosniff`. | CWE-693 |
| `headers.referrer_policy_missing` | URLs podem vazar pelo cabeçalho Referer | Referrer-Policy está ausente. | CWE-200 |
| `headers.permissions_policy_missing` | Capacidades do navegador não são explicitamente restringidas | Permissions-Policy está ausente. | CWE-693 |
| `headers.coop_missing` | Janela de nível superior não está isolada | Cross-Origin-Opener-Policy está ausente. | CWE-693 |
| `headers.corp_missing` | Política de carregamento de recursos não é explícita | Cross-Origin-Resource-Policy está ausente. | CWE-693 |
| `headers.content_type_missing` | Resposta não possui tipo de conteúdo explícito | Uma resposta que parece textual foi recebida sem o cabeçalho Content-Type. | CWE-116 |


### Cookie Security — 5 verificação(ões)

Arquivo: [`scanner/plugins/cookies.py`](../scanner/plugins/cookies.py) · classe `CookieSecurityPlugin` · OWASP A07:2025 Authentication Failures · WSTG WSTG-SESS-02

**Quando é avaliado:** Somente respostas que definem cookie (`Set-Cookie`). `missing_secure` só em `https://`.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `cookies.missing_secure` | Cookie pode ser enviado por conexão não criptografada | Ao menos um cabeçalho Set-Cookie não possui o atributo Secure. | CWE-614 |
| `cookies.missing_httponly` | JavaScript pode ler um cookie | Ao menos um cabeçalho Set-Cookie não possui HttpOnly. | CWE-1004 |
| `cookies.missing_samesite` | Cookie não possui política explícita entre sites | Ao menos um cabeçalho Set-Cookie não possui SameSite. | CWE-352 |
| `cookies.broad_domain` | Cookie é compartilhado com todos os subdomínios | Ao menos um cabeçalho Set-Cookie inclui um atributo Domain explícito. | CWE-284 |
| `cookies.samesite_none_insecure` | Cookie SameSite=None está sem Secure | Um cookie SameSite=None não define também Secure. | CWE-614 |


### CORS Baseline — 2 verificação(ões)

Arquivo: [`scanner/plugins/cors.py`](../scanner/plugins/cors.py) · classe `CorsPassivePlugin` · OWASP A01:2025 Broken Access Control · WSTG WSTG-CLNT-07

**Quando é avaliado:** Somente respostas com `Access-Control-Allow-Origin: *` (origem curinga). Origens refletidas são testadas pelo plugin de CORS ativo.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `cors.wildcard_origin` | CORS permite qualquer origem | Access-Control-Allow-Origin é `*` em uma requisição de baseline, sem autenticação. | CWE-942 |
| `cors.credentials_with_wildcard` | CORS combina credenciais com origem coringa | A resposta define tanto uma origem coringa quanto Access-Control-Allow-Credentials: true. | CWE-942 |


### Cache Security — 1 verificação(ões)

Arquivo: [`scanner/plugins/cache.py`](../scanner/plugins/cache.py) · classe `CacheSecurityPlugin` · OWASP A02:2025 Security Misconfiguration · WSTG WSTG-CONF-12

**Quando é avaliado:** Somente respostas que definem cookie ou variam por `Authorization`.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `cache.sensitive_no_store_missing` | Resposta potencialmente vinculada à sessão sem política no-store | A resposta define cookies (ou varia por Authorization), mas Cache-Control não contém no-store. | CWE-525 |


### Information Disclosure — 7 verificação(ões)

Arquivo: [`scanner/plugins/disclosure.py`](../scanner/plugins/disclosure.py) · classe `InformationDisclosurePlugin` · OWASP A02:2025 Security Misconfiguration · WSTG WSTG-INFO-02,WSTG-INFO-05,WSTG-INFO-08,WSTG-ERRH-01,WSTG-CONF-04

**Quando é avaliado:** Toda página; cada verificação procura seu próprio sinal (cabeçalho, trecho do corpo, formulário de senha em HTTP).

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `disclosure.server_header` | Detalhes do servidor web são expostos | O cabeçalho de resposta Server expõe informações de produto ou versão. | CWE-200 |
| `disclosure.powered_by_header` | Tecnologia da aplicação é exposta | O cabeçalho de resposta X-Powered-By expõe detalhes de framework ou runtime. | CWE-200 |
| `disclosure.stack_trace` | Erro detalhado da aplicação pode estar exposto | O corpo da resposta corresponde a um padrão comum de stack trace, erro de banco de dados ou erro de runtime. | CWE-209 |
| `disclosure.directory_listing` | Listagem de diretório parece estar habilitada | O título ou cabeçalho da página corresponde a um índice automático de diretório comum. | CWE-548 |
| `disclosure.source_map` | Resposta de produção anuncia um source map | Um cabeçalho de source map ou referência `sourceMappingURL` está presente. | CWE-540 |
| `disclosure.mixed_content` | Página HTTPS referencia recursos HTTP | Um documento HTTPS referencia um recurso absoluto `http://` ou uma action de formulário. | CWE-319 |
| `disclosure.password_over_http` | Formulário de senha é entregue sem HTTPS | Uma resposta HTTP contém um campo de entrada do tipo password. | CWE-319 |


### Secrets Exposure — 2 verificação(ões)

Arquivo: [`scanner/plugins/secrets.py`](../scanner/plugins/secrets.py) · classe `SecretsExposurePlugin` · OWASP A02:2025 Security Misconfiguration · WSTG WSTG-INFO-05

**Quando é avaliado:** Toda página; procura padrões de credenciais no corpo da resposta.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `secrets.high_confidence_pattern` | Provável credencial ou chave privada exposta na resposta | O corpo da resposta contém texto que corresponde a um formato conhecido de credencial ou chave privada. | CWE-798 |
| `secrets.heuristic_pattern` | Possível valor semelhante a credencial na resposta | O corpo da resposta contém um valor de alta entropia, com nome de campo genérico, que se assemelha a uma credencial. | CWE-798 |


## Verificações ativas (modo completo)


### SQL Injection — 3 verificação(ões)

Arquivo: [`scanner/plugins/active/sql_injection.py`](../scanner/plugins/active/sql_injection.py) · classe `SqlInjectionPlugin` · OWASP A05:2025 Injection · WSTG WSTG-INPV-05

**Quando é avaliado:** Cada parâmetro da URL e campo de formulário. Técnicas em ordem de custo (erro → booleano → tempo); para na primeira confirmada.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `sqli.error_based` | SQL Injection confirmada por mensagem de erro de banco de dados | Um caractere de controle SQL enviado em um parâmetro produziu uma mensagem de erro de banco de dados ausente na resposta de baseline. | CWE-89 |
| `sqli.boolean_differential` | SQL Injection confirmada por diferencial booleano | Uma condição SQL logicamente verdadeira produziu uma resposta equivalente à baseline, enquanto uma condição logicamente falsa produziu uma resposta estruturalmente diferente, e um probe de controle inócuo não alterou o comportamento. | CWE-89 |
| `sqli.time_based` | SQL Injection provável por atraso de tempo controlado | Uma condição SQL contendo uma função de atraso controlado produziu um tempo de resposta consistentemente maior que a baseline, reproduzido em uma segunda medição, enquanto um probe de controle de complexidade equivalente não produziu o mesmo atraso. | CWE-89 |


### Reflected XSS — 3 verificação(ões)

Arquivo: [`scanner/plugins/active/reflected_xss.py`](../scanner/plugins/active/reflected_xss.py) · classe `ReflectedXssPlugin` · OWASP A05:2025 Injection · WSTG WSTG-INPV-01

**Quando é avaliado:** Cada parâmetro da URL e campo de formulário.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `xss.reflected_html_text` | Cross-Site Scripting refletido em contexto de texto HTML | Um marcador contendo caracteres HTML especiais foi refletido sem escaping no corpo da resposta, em uma posição de texto solto no HTML. | CWE-79 |
| `xss.reflected_html_attribute` | Cross-Site Scripting refletido em atributo HTML | Um marcador foi refletido dentro do valor de um atributo HTML de forma que permite encerrar o atributo e injetar novos atributos ou tags. | CWE-79 |
| `xss.reflected_script_context` | Cross-Site Scripting refletido em contexto de script | Um marcador foi refletido dentro de um bloco <script> de forma que permite encerrar uma string JavaScript e injetar código arbitrário. | CWE-79 |


### Path Traversal / LFI — 2 verificação(ões)

Arquivo: [`scanner/plugins/active/path_traversal.py`](../scanner/plugins/active/path_traversal.py) · classe `PathTraversalPlugin` · OWASP A01:2025 Broken Access Control · WSTG WSTG-ATHZ-01

**Quando é avaliado:** Parâmetros cujo nome sugere arquivo (`file`, `page`, `path`, `doc`, `template`, `include`, `lang`, `view`, `download`) ou cujo valor parece caminho.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `path_traversal.file_disclosure` | Divulgação de arquivo do sistema operacional via travessia de diretório | Um parâmetro que referencia um arquivo aceitou uma sequência de travessia de diretório e a resposta passou a conter o conteúdo de um arquivo do sistema operacional. | CWE-22 |
| `path_traversal.suspicious_behavior` | Parâmetro de arquivo reage de forma diferente a sequências de travessia | Um parâmetro que referencia um arquivo produziu uma resposta claramente diferente para uma sequência de travessia de diretório em comparação com um valor de controle inexistente, mas nenhum conteúdo de arquivo do sistema operacional foi confirmado. | CWE-22 |


### Open Redirect — 2 verificação(ões)

Arquivo: [`scanner/plugins/active/open_redirect.py`](../scanner/plugins/active/open_redirect.py) · classe `OpenRedirectPlugin` · OWASP A01:2025 Broken Access Control · WSTG WSTG-CLNT-04

**Quando é avaliado:** Parâmetros cujo nome sugere destino (`redirect`, `next`, `url`, `return`…) ou cujo valor é uma URL.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `open_redirect.confirmed_header` | Redirecionamento aberto confirmado via cabeçalho Location | Um parâmetro de query controla o destino de um redirecionamento HTTP e aceita um host externo arbitrário sem validação. | CWE-601 |
| `open_redirect.client_side_suspected` | Possível redirecionamento aberto no lado do cliente | Um parâmetro de query é refletido dentro de uma navegação client-side (window.location ou meta refresh) apontando para o host canário injetado. | CWE-601 |


### Command Injection — 3 verificação(ões)

Arquivo: [`scanner/plugins/active/command_injection.py`](../scanner/plugins/active/command_injection.py) · classe `CommandInjectionPlugin` · OWASP A05:2025 Injection · WSTG WSTG-INPV-12

**Quando é avaliado:** Parâmetros da URL e de formulário; com mais de 3, só os de nome suspeito.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `command_injection.marker_confirmed` | Injeção de Comandos do Sistema Operacional confirmada | Um parâmetro de URL foi manipulado com separadores de comando do shell e o resultado avaliado (um marcador exclusivo ou uma expressão aritmética) apareceu na resposta usando pelo menos dois separadores de comando distintos, ausente na linha de base e em um controle negativo inerte, sem que o texto do comando injetado fosse apenas refletido. | CWE-78 |
| `command_injection.marker_suspected` | Possível Injeção de Comandos do Sistema Operacional | Um parâmetro de URL mostrou um sinal de avaliação de comando (marcador exclusivo ou expressão aritmética) para um único separador de comando, ausente na linha de base e não explicado por reflexão literal, mas uma segunda variação de separador não reproduziu o mesmo resultado, ou o controle negativo foi ambíguo. | CWE-78 |
| `command_injection.timing_suspected` | Possível Injeção de Comandos baseada em atraso de tempo | Um comando de atraso limitado (sleep/ping) injetado em um parâmetro de URL produziu um atraso na resposta consistente com sua execução pelo sistema operacional, reproduzido em duas medições consecutivas, mas sem uma prova determinística (nenhum marcador ou valor avaliado apareceu na resposta). | CWE-78 |


### Server-Side Template Injection — 1 verificação(ões)

Arquivo: [`scanner/plugins/active/ssti.py`](../scanner/plugins/active/ssti.py) · classe `TemplateInjectionPlugin` · OWASP A05:2025 Injection · WSTG WSTG-INPV-18

**Quando é avaliado:** Parâmetros da URL e de formulário, exceto os que parecem identificador numérico (`id`, `page`, `limit`, `year`…).

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `ssti.expression_evaluated` | Injeção de template no lado do servidor (SSTI) | Uma expressão aritmética enviada em um parâmetro de consulta foi avaliada pelo motor de templates do servidor -- o resultado calculado apareceu na resposta em vez da sintaxe literal enviada, indicando que a entrada é interpretada como código de template e não apenas como texto. | CWE-1336 |


### XML External Entity — 2 verificação(ões)

Arquivo: [`scanner/plugins/active/xxe.py`](../scanner/plugins/active/xxe.py) · classe `XxePlugin` · OWASP A05:2025 Injection · WSTG WSTG-INPV-07

**Quando é avaliado:** Somente endpoints com sinal de XML (Content-Type com `xml` ou caminho com `/api/`, `/xml`, `/soap`, `/rest`, `.xml`).

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `xxe.internal_entity_expansion` | Processamento de entidades XML internas detectado | O endpoint aceita XML enviado via POST e substitui pelo valor declarado uma entidade interna definida em uma seção DOCTYPE, confirmando que o parser XML processa DOCTYPE e entidades. | CWE-611 |
| `xxe.external_entity_processing_suspected` | Possível resolução de entidade externa (XXE) habilitada | Uma entidade externa SYSTEM apontando para um domínio reservado e inexistente (.invalid) produziu uma resposta com tempo ou texto de erro observavelmente diferente da sonda apenas com entidade interna, sugerindo uma tentativa do servidor de resolver ou contatar a entidade externa. | CWE-611 |


### CRLF Injection — 1 verificação(ões)

Arquivo: [`scanner/plugins/active/crlf_injection.py`](../scanner/plugins/active/crlf_injection.py) · classe `CrlfInjectionPlugin` · OWASP A05:2025 Injection · WSTG WSTG-INPV-15

**Quando é avaliado:** Parâmetros da URL refletidos em cabeçalhos da resposta; se nenhum, os de nome de redirecionamento.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `crlf.header_injection_confirmed` | Injeção de cabeçalho HTTP via CRLF confirmada | Um parâmetro de query teve uma sequência CRLF (%0d%0a) codificada em URL aceita pela aplicação e refletida como uma quebra de linha real dentro dos cabeçalhos de resposta HTTP, permitindo a injeção de um cabeçalho ou cookie inteiramente novo. | CWE-93 |


### Host Header Injection — 2 verificação(ões)

Arquivo: [`scanner/plugins/active/host_header.py`](../scanner/plugins/active/host_header.py) · classe `HostHeaderInjectionPlugin` · OWASP A05:2025 Injection · WSTG WSTG-INPV-17

**Quando é avaliado:** Toda página (manipula o cabeçalho `Host`, não parâmetros).

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `host_header.reflected_in_redirect` | Cabeçalho Host é refletido em redirecionamento ou cookie de resposta | Um valor de Host (ou X-Forwarded-Host) manipulado e reservado para testes foi refletido verbatim no cabeçalho Location de um redirecionamento ou no atributo Domain de um Set-Cookie, indicando que a aplicação usa o cabeçalho Host recebido do cliente para construir URLs absolutas ou escopo de cookies do lado do servidor. | CWE-644 |
| `host_header.reflected_in_body` | Cabeçalho Host é refletido em URL absoluta no corpo da resposta | Um valor de Host (ou X-Forwarded-Host) manipulado e reservado para testes foi refletido verbatim como o host de uma URL absoluta (ou relativa a protocolo) no corpo HTML da resposta, por exemplo em um link, em uma action de formulário ou em uma tag canonical. | CWE-644 |


### HTTP Verb Tampering — 3 verificação(ões)

Arquivo: [`scanner/plugins/active/http_verb_tampering.py`](../scanner/plugins/active/http_verb_tampering.py) · classe `HttpVerbTamperingPlugin` · OWASP A01:2025 Broken Access Control · WSTG WSTG-CONF-06

**Quando é avaliado:** Toda página: pergunta os métodos aceitos com `OPTIONS` e testa POST/PUT/DELETE/PATCH. Pode alterar dados — só em homologação.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `http_verb_tampering.destructive_method_accepted` | Método HTTP potencialmente destrutivo foi aceito sem rejeição | Um método HTTP normalmente restrito e potencialmente destrutivo (DELETE, PUT ou PATCH) foi enviado ao endpoint e a resposta não apresentou nenhum sinal de rejeição, sugerindo que um filtro de autenticação ou autorização verifica apenas o método GET e deixa os demais métodos passarem direto para a lógica de negócio. | CWE-650 |
| `http_verb_tampering.method_bypass_suspected` | Troca de verbo HTTP pode contornar o controle de acesso | Um método HTTP diferente do esperado (por exemplo, POST em vez de GET) produziu uma resposta que se assemelha ao acesso legítimo, ou o cabeçalho Allow anunciou suporte a métodos além do necessário, ampliando a superfície de ataque disponível. | CWE-650 |
| `http_verb_tampering.trace_enabled` | Método TRACE está habilitado | O servidor respondeu a uma requisição TRACE sem rejeitá-la, em alguns casos refletindo de volta, no corpo da resposta, cabeçalhos enviados na requisição (Cross-Site Tracing). | CWE-650 |


### NoSQL Injection — 2 verificação(ões)

Arquivo: [`scanner/plugins/active/nosql_injection.py`](../scanner/plugins/active/nosql_injection.py) · classe `NoSqlInjectionPlugin` · OWASP A05:2025 Injection · WSTG WSTG-INPV-05

**Quando é avaliado:** Somente parâmetros da URL; com muitos parâmetros, só os de nome suspeito.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `nosql_injection.operator_bypass_confirmed` | Operador do MongoDB injetável via parâmetro de query | Um parâmetro de query aceitou a sintaxe de operador do MongoDB (`nome[$ne]=valor`) e o backend passou a interpretar o parâmetro como um filtro de comparação em vez de um valor literal, alterando a semântica da consulta original. | CWE-943 |
| `nosql_injection.array_type_confusion_suspected` | Possível confusão de tipo por parâmetro de query em formato de array | Enviar o mesmo parâmetro tanto na forma simples quanto na forma de array (`nome[]=valor`) produziu uma resposta que se assemelha ao mesmo padrão de 'sucesso' já observado na injeção de operador confirmada para este mesmo parâmetro, sugerindo que o backend também aceita entrada não-string aqui. | CWE-943 |


### CORS Active Testing — 4 verificação(ões)

Arquivo: [`scanner/plugins/active/cors_active.py`](../scanner/plugins/active/cors_active.py) · classe `CorsActivePlugin` · OWASP A01:2025 Broken Access Control · WSTG WSTG-CLNT-07

**Quando é avaliado:** Toda página (envia cabeçalhos `Origin` de teste).

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `cors.origin_reflected` | CORS reflete dinamicamente qualquer origem enviada | O servidor respondeu com Access-Control-Allow-Origin igual, byte a byte, a um valor de Origin arbitrário e não confiável enviado pelo scanner. | CWE-942 |
| `cors.credentials_with_reflected_origin` | CORS reflete a origem e permite credenciais simultaneamente | A resposta combina a reflexão de uma origem arbitrária com Access-Control-Allow-Credentials: true. | CWE-942 |
| `cors.null_origin_allowed` | CORS aceita a origem 'null' | O servidor respondeu com Access-Control-Allow-Origin: null para uma requisição com Origin: null. | CWE-942 |
| `cors.lookalike_origin_accepted` | CORS aceita uma origem parecida, mas diferente, da origem legítima | O servidor aceitou uma origem que apenas contém ou se assemelha ao domínio legítimo (ex.: um subdomínio ou domínio com prefixo/sufixo diferente), sugerindo validação por substring em vez de comparação exata. | CWE-942 |


### SSRF Candidate Detection — 2 verificação(ões)

Arquivo: [`scanner/plugins/active/ssrf.py`](../scanner/plugins/active/ssrf.py) · classe `SsrfPlugin` · OWASP A05:2025 Injection · WSTG WSTG-INPV-19

**Quando é avaliado:** Parâmetros cujo nome sugere URL (`url`, `callback`, `webhook`, `image`, `proxy`…) ou cujo valor começa com `http(s)://`.

| Id da verificação | Título | O que detecta | CWE |
|---|---|---|---|
| `ssrf.error_signature_suspected` | Possível SSRF: mensagem de erro sugere requisição de rede feita pelo servidor | Um parâmetro que aceita uma URL produziu uma mensagem de erro específica de rede/HTTP ao receber um host inexistente, sugerindo que o servidor tentou buscar a URL diretamente. | CWE-918 |
| `ssrf.timing_signature_suspected` | Possível SSRF: atraso de resposta sugere tentativa de conexão de rede pelo servidor | Um parâmetro que aceita uma URL apontando para um endereço não roteável (documentação/reservado) produziu um tempo de resposta consistentemente maior que a baseline, reproduzido em uma segunda medição, compatível com uma tentativa real de conexão de rede que expirou por timeout. | CWE-918 |

