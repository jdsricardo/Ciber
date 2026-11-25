# Motor de Varredura

Este documento descreve o motor Python (`scanner/`) como ele está hoje. Ele nasceu como a
"fundação da Fase 1" (apenas verificações passivas, uma página por varredura) e foi ampliado com
sondas ativas, teste de formulários, varredura autenticada e rastreamento; as seções abaixo
registram cada incremento. A visão geral das camadas está em [ARCHITECTURE.md](ARCHITECTURE.md) e o
formato da saída em [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md).

## Fundação

- Modelos comuns tipados para requisições, respostas, pontos de entrada, resumos, diferenças,
  evidências, achados, modos de varredura, contexto da página e limites (`engine/models.py`).
- Identificadores estáveis de entrada por canal e nome; descoberta na query string e em
  formulários HTML (`engine/discovery.py`).
- Normalização central de horários, UUIDs, valores aleatórios longos, nonce, CSRF e campos de
  token, além da inferência do contexto da página (formulários, campos de senha, cookies de sessão)
  (`engine/normalization.py`).
- Resumos de resposta centralizados e comparação de status, tamanho, conteúdo normalizado,
  estrutura HTML, cabeçalhos e tempo.
- *Matchers* positivos/negativos combináveis com E, OU e NÃO, além de primitivas de status,
  cabeçalho, texto/regex, tamanho, similaridade, tempo e redirecionamento, e extratores reutilizáveis
  por regex e por caminho JSON (`engine/matchers.py`). Hoje são exercitados pelos testes do motor;
  nenhum plugin os usa.
- Controle de escopo por host e porta, rejeição de esquemas perigosos, rejeição de credenciais na
  URL, bloqueio de redes privadas, fixação de DNS, orçamentos de requisições globais e por
  endpoint, limitação de taxa, tempos limite por requisição e global, arquivo de cancelamento,
  limite de tamanho das respostas e log de requisições em JSONL com cabeçalhos secretos mascarados
  (`engine/safety.py`).
- Um modelo central de pontuação de confiança, independente da severidade
  (`engine/confidence.py`): `confidence = 0.35*evidence_strength + 0.25*reproducibility +
  0.2*differential_quality + 0.2*independent_confirmation - 0.3*instability - 0.2*ambiguity`,
  mapeado para `confirmed / high_confidence / probable / possible / informational /
  manual_review_required`.
- Uma interface de plugin que declara categoria, CWE, OWASP, WSTG, tipo, risco operacional e o
  conjunto de ids de verificação que possui (`plugins/base.py`).
- Sete plugins passivos orientados a objetos (`plugins/transport.py`, `headers.py`, `cookies.py`,
  `cors.py`, `cache.py`, `disclosure.py`, `secrets.py`) cobrindo 34 verificações individuais,
  incluindo um detector de exposição de segredos (formatos de credencial de alta assinatura mais
  uma heurística baseada em entropia que ignora tokens por requisição/rotativos).
- `engine/runner.py` orquestra duas requisições de baseline independentes por meio de
  `HttpTransport`/`SafetyController`, monta o contexto da página, executa todos os plugins
  registrados e serializa o resultado no formato JSON consumido por
  `App\Infrastructure\Scanner\PythonScannerGateway` / `App\Domain\Model\ScanResult`.

## Ponto de entrada e persistência

`scanner/scanner.py` é um invólucro fino de linha de comando em torno de `engine.runner.run_scan`
(`run_passive_scan` continua existindo apenas como atalho para chamadas somente passivas). Do lado
PHP, os achados são gravados por `Infrastructure\Persistence\PdoFindingRepository` e exibidos por
`Presentation\Views` / `FindingPresenter` (severidade e confiança como selos separados; a evidência
estruturada completa aparece em JSON no painel de contexto técnico de cada achado). O
`database.sql` foi estendido de forma aditiva (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`) com
`category, cwe, owasp, wstg, method, parameter, parameter_location, confidence, status,
description, evidence_summary, manual_review_required`, depois com `analyses.mode` e com as quatro
colunas do exemplo de remediação.

## Detectores ativos (modo `safe_active`)

Treze famílias ativas, 30 verificações, carregadas por `default_active_plugins()` a partir de
`ACTIVE_PLUGIN_SPECS` em `engine/runner.py`: SQL injection, XSS refletido, path traversal, open
redirect, command injection, SSTI, XXE, CRLF, injeção no cabeçalho Host, troca de verbo HTTP,
NoSQL injection, CORS ativo e SSRF. Um arquivo de plugin que existe mas falha ao importar não some em
silêncio: aparece em `plugin_warnings` no resultado. Cada família tem testes com fixtures
vulneráveis e seguros (`tests/test_active_*.py`). O orçamento do modo ativo é maior, mas continua
explícito (`ACTIVE_LIMITS`: 2.500 requisições, 120 por endpoint, 600 s, 20 páginas, profundidade 2).

"Seguro" quer dizer que as sondas buscam a evidência mínima e não tentam extrair dados nem
explorar o achado. Não quer dizer que nenhuma requisição possa alterar estado: a verificação de
verbos HTTP envia PUT, DELETE e PATCH uma vez a cada página visitada (sem repetição para
confirmação), e os campos de formulário são submetidos via POST. Por isso o modo completo exige uma
segunda autorização e deve ser usado apenas em ambientes de teste.

## Confiança × severidade

Todo achado carrega as duas, de forma independente. Severidade é o impacto potencial se o achado
for real; confiança é o quanto o detector tem certeza. Um achado crítico pode ter baixa confiança —
ele continua `Critical / possible`, nunca é rebaixado em silêncio para uma severidade menor.
Verificações puramente passivas, de observação única, ficam abaixo de `confirmed` por construção
(nenhum `differential_quality` ou método realmente independente contribui para a sua pontuação);
`confirmed` fica reservado a detectores ativos que reproduzem um resultado por uma segunda técnica
independente (por exemplo, uma sonda de SQLi baseada em erro e uma diferencial booleana
concordando).

## Base de referência

Os mapeamentos usam o OWASP Top 10:2025. Os identificadores WSTG devem usar a forma estável e
versionada v4.2 na evidência persistida, enquanto o desenvolvimento pode consultar o conteúdo mais
recente do WSTG 5.0. Os identificadores CWE permanecem específicos de cada fraqueza e não devem ser
inferidos a partir de uma anomalia genérica.

## Incrementos de cobertura: teste de formulários/POST e varredura autenticada

- Os testes de parâmetros não dependem da origem do parâmetro: `plugins/support.build_probe`/
  `send_probe` enviam a sonda pelo canal certo — um parâmetro de query é testado na URL (GET), um
  campo de formulário é enviado em um corpo `application/x-www-form-urlencoded` (POST) com os
  campos vizinhos preservados. Os plugins ativos percorrem `testable_inputs` (query + formulário).
  O teste de formulário/POST está habilitado em todos os detectores de injeção de valor (SQL
  injection, XSS refletido, path traversal, open redirect, command injection, SSTI, SSRF); CRLF e
  NoSQL ficam apenas na query porque a construção da sonda depende do canal. As sondas de
  formulário são enviadas à URL da página analisada; formulários cujo `action` aponta para outro
  caminho são uma limitação conhecida (é a causa do falso negativo de SQLi no login da Altoro
  Mutual, ver [EVALUATION_RESULTS.md](EVALUATION_RESULTS.md)).
- Varredura autenticada: `ScanContext.auth_headers` é mesclado a toda requisição de saída pelo
  transporte, cobrindo verificações passivas e ativas de uma vez sem tocar em nenhum plugin. Os
  cabeçalhos de autenticação só chegam ao host/porta fixados (controle de escopo), são mascarados
  nos logs (`SENSITIVE_HEADERS`) e são fornecidos pela linha de comando (`--cookie`, `--header`
  repetível) ou, apenas durante a análise, pela aplicação web (nunca persistidos). A aplicação web
  usa somente `--cookie`.

## Incremento de cobertura: rastreamento de mesma origem

- `engine/crawler.py` expande uma única URL-semente para a superfície de mesma origem alcançável.
  `engine/runner.py` faz uma caminhada em largura: retira uma página da fila, analisa-a por completo
  (duas requisições de baseline + todos os plugins) e então enfileira seus links `<a>`, *actions*
  de formulários GET e o destino de redirecionamento para as profundidades seguintes. Isso fecha a
  lacuna em que a análise de uma página de login (ou de qualquer página de entrada) deixava de ver
  uma página desprotegida a um clique dali — o motor agora a descobre e a testa sozinho.
- Limites e segurança: o rastreamento é limitado por `max_pages` e pelos orçamentos de
  requisições e de tempo; `max_depth` define a ordem (perfis: passivo 30 páginas / profundidade 3,
  ativo 20 páginas / profundidade 2; ambos ajustáveis com `--max-pages`/`--max-depth`, e
  `max_pages=1` restaura a análise de página única). Páginas além de `max_depth` só são visitadas
  depois de todas as mais próximas (ver D-12 abaixo). A navegação é
  somente leitura — links de logout/sair e links que alteram estado (`?action=delete`,
  `?remove=`, …) nunca são seguidos, então um rastreamento autenticado não derruba a própria sessão
  nem altera o estado do servidor ao navegar. Todas as requisições compartilham um único orçamento
  do `SafetyController`, então rastreamento e sondagem ficam dentro do mesmo envelope de
  requisições/tempo, e toda URL é revalidada contra o host/porta fixados antes de ser buscada.
- Resiliência: estourar o orçamento de um endpoint (`EndpointBudgetExceeded`) encerra apenas aquele
  endpoint e o rastreamento segue; uma falha de rede transitória (`OSError`: tempo esgotado/reset)
  enquanto um plugin sonda pula apenas aquele plugin, e uma página que não pode ser obtida é pulada
  — assim, uma oscilação nunca descarta os achados já coletados. Só um orçamento global de
  requisições/tempo, uma violação de escopo durante a sondagem ou um cancelamento interrompem a
  varredura inteira (`stopped_early`), e em todos os casos os achados coletados até ali são
  devolvidos. Se nem a página-semente responde, o resultado é `ok:false` com uma mensagem em
  português.
- Os achados são consolidados entre páginas: um cabeçalho ausente no servidor inteiro é relatado
  uma vez, enquanto achados de injeção/exposição por endpoint são mantidos por URL e parâmetro. O
  JSON de resultado traz `pages_scanned` e `crawled_urls` e, desde o contrato 1.3, a cobertura
  (`pages_not_visited`, `not_visited_urls`, `template_variants_skipped`, `scripts_read`).

## Descoberta de páginas (rastreamento inteligente, 2026-11-25)

Defeito que motivou a mudança: as páginas eram agrupadas por *caminho + nomes* dos parâmetros,
ignorando os valores. Isso evitava visitar `/produto?id=1..N` mil vezes, mas também juntava
`index.php?p=12` e `index.php?p=14` — duas **telas diferentes** de uma aplicação PHP que roteia
por parâmetro (o padrão do Portal de Clientes e do PIM da empresa). Só a primeira tela do menu era
analisada, sem nenhum aviso. Além disso, endpoints chamados por JavaScript (`fetch`, `$.post`) não
eram descobertos, e o usuário não tinha como saber quais páginas a análise cobriu.

Como funciona agora (`engine/crawler.py`, `CrawlFrontier`; laço em `ScanRunner.run()`):

1. **Página exata × formato.** `page_signature` identifica a página com os *valores* dos
   parâmetros (`index.php?p=12` ≠ `?p=14`); `page_shape` ignora os valores (`index.php?p`) e
   agrupa as variações de um mesmo formato.
2. **Novidade primeiro.** A fila tem duas partes: páginas de um formato ainda não visto vão para
   a fila principal; outras variações de um formato conhecido esperam numa segunda fila, atendida
   depois. Assim o limite de páginas é gasto primeiro em telas diferentes.
3. **Reconhecimento de modelo.** De cada página buscada é extraída a estrutura
   (`page_structure`): a **identidade** — textos de rótulos, cabeçalhos de tabela, legendas e
   botões, nomes de campos, *actions* de formulários e scripts carregados — e o **layout** —
   trigramas da sequência de tags. Duas variações são o mesmo modelo quando têm a mesma identidade
   e layout ≥ 80% semelhante (similaridade de Jaccard ponderada); sem identidade nenhuma, só com
   layout ≥ 97%, para que um menu compartilhado não faça duas telas parecerem iguais. Uma variação
   que repete um modelo já analisado custa **uma** requisição e não passa pelos plugins; após
   **3 repetições seguidas** o formato é dado como modelo e as variações restantes são descartadas
   sem requisição. O total dessas buscas repetidas é limitado a `max_pages`.
4. **Parâmetros já testados.** Num formato com várias telas (`?p=12`, `?p=14`), o parâmetro de
   rota `p` é testado pelos plugins ativos só na primeira; os formulários de cada tela são sempre
   testados.
5. **URLs no JavaScript.** São lidos os `<script>` embutidos, os atributos `on*`
   (`onclick="location.href='…'"`), `data-url`/`data-href` e até 15 arquivos `.js` da própria
   origem por análise (bibliotecas conhecidas — jQuery, Bootstrap, DataTables… — são puladas).
   Uma string vira URL quando é claramente um endpoint (`*.php`, `*.asp(x)`, `*.jsp`, `…/api/…`)
   ou o destino de `location`/`location.href`/`location.assign`. Valores calculados em tempo de
   execução (`'?id=' + id`, `` `?q=${q}` ``) viram `1`, para que o parâmetro seja descoberto e
   testado. URLs relativas são resolvidas contra a página que executa o script.
6. **Somente leitura, mais rígido.** Além de logout e de `?action=delete`, nenhum caminho cujo
   segmento seja uma ação destrutiva é seguido (`/user/delete/5`, `delete_user_ajax.php`,
   `/pedido/excluir`), o que importa agora que endpoints de AJAX entram no rastreamento.
7. **Cobertura relatada.** O resultado informa as páginas analisadas, quantas foram encontradas e
   não analisadas (limite de páginas ou de requisições/tempo, ou página que não respondeu) com as
   primeiras 50, as variações de modelo não repetidas e os scripts lidos. A aplicação grava isso
   com a análise (`analyses.crawl_coverage`) e mostra na seção *Cobertura da análise* do resultado.

### Correção de cobertura em sistema com login (D-12, 2026-11-25)

Caso real: o Portal de Clientes (homologação), cadastrado como `…/index.php` com um `PHPSESSID`
válido, teve 5 páginas analisadas e **12 telas do menu listadas como "não analisadas"**, com o
orçamento quase intacto (23 s de uma análise que pode durar 600 s). Reproduzido com o laboratório
`GatedPortal` de `tests/test_crawler.py`, que imita o desenho do Portal. Causas e correções:

| Causa | Correção |
|---|---|
| A profundidade era um muro: o redirecionamento `index.php → ?p=2` e a tela de login (sem menu) gastavam os 2 níveis do modo completo antes de chegar ao painel `?p=12`, o primeiro com o menu; tudo o que o menu ligava ficava "além da profundidade". | Um redirecionamento mantém a profundidade da página (é onde ela realmente está, não um clique). E `max_depth` passa a **ordenar** o rastreamento em vez de cortá-lo: páginas mais distantes esperam numa terceira fila, visitada depois de todas as mais próximas, enquanto durarem os orçamentos de páginas, requisições e tempo — esses é que limitam a análise. |
| Orçamento "por endpoint" contado pelo caminho: todas as telas `index.php?p=N` são o mesmo `GET:/index.php`, então as primeiras telas gastariam as 120 requisições de todas as outras, que seriam puladas **sem aviso**. | O `SafetyController` conta as requisições ao caminho da página em análise por página (`begin_page`): cada tela tem seu próprio limite. O limite global (2.500) e o intervalo entre requisições não mudam. Uma página que não pôde ser buscada passa a constar como não analisada. |
| Um formulário GET (busca, filtro) era seguido só pelo `action`, sem os campos, e seus campos eram enviados por POST à página — uma busca vulnerável numa tela interna passava despercebida. | O formulário GET vira a URL que o envio dele pede (`index.php?p=33&nota=`), e seus campos são testados como parâmetros da URL. Senhas, arquivos e botões não entram. |

No laboratório `GatedPortal`, modo completo, limites padrão: antes 6 páginas e 12 telas não
analisadas, XSS da tela de busca não encontrado; depois 17 páginas, nenhuma deixada de fora, XSS
encontrado, 850 requisições em 86 s. Laboratório da suíte de sistema e `loja.py`: mesmas páginas,
mesmas requisições e mesmos achados antes e depois (137/14 e 124/14 → 120/1).

Medição antes/depois, com os sites de laboratório de `tests/test_crawler.py` (mesma máquina,
modo indicado, limites padrão):

| Site de laboratório | Versão | Páginas analisadas | Requisições | XSS encontrados |
|---|---|---:|---:|---:|
| `PortalLike` (rota `?p=`, 5 telas + endpoint AJAX), completo | anterior | 1 | 48 | 0 de 2 |
| | atual | 6 | 188 | 2 de 2 |
| `PortalLike`, passivo | anterior | 1 | 2 | — |
| | atual | 6 | 13 | — |
| `Catalog` (40 produtos, mesmo modelo), passivo | anterior | 2 | 4 | — |
| | atual | 2 | 7 | — |

O custo do reconhecimento de modelo é de três requisições por formato repetido (4 → 7 no
catálogo); o ganho é cobrir telas que antes eram silenciosamente ignoradas.

## Limitações conhecidas (conferidas no código em 2026-11-25)

- **TLS:** o transporte usa `ssl.create_default_context()`, que valida o certificado e exige TLS
  1.2+. Um alvo HTTPS com certificado inválido, expirado ou autoassinado, ou que só aceite TLS
  1.0/1.1, não pode ser analisado ("Nenhuma página pôde ser acessada no alvo."). Consequentemente,
  `tls.legacy_protocol` não tem como disparar e `tls.certificate_expiry` só aparece para
  certificados ainda válidos que expiram em menos de 30 dias.
- **Descoberta de páginas (o que o rastreador não alcança):**
  - não adivinha endereços: uma página para a qual nenhum link, formulário GET, redirecionamento
    ou script aponta não é encontrada (não há lista de palavras, `robots.txt` nem `sitemap.xml`);
  - não executa JavaScript: URLs escritas como texto no código são lidas (item 5 acima), mas
    links e telas *montados* em tempo de execução — típicos de SPAs em React/Angular/Vue — não;
  - endpoints que a aplicação chama com POST (`$.post`) são visitados com GET, como qualquer
    página; o corpo que a aplicação enviaria não é reproduzido;
  - formulários POST cujo `action` aponta para outra URL são testados contra a URL da página
    (limitação L-03 do documento final);
  - áreas com login só são alcançadas com um cookie de sessão válido, e a sessão cai se o usuário
    sair no navegador durante a análise;
  - o limite de páginas (30/20) pode deixar telas de fora num sistema grande — isso aparece na
    seção *Cobertura da análise* em vez de passar despercebido; a profundidade (3/2) só define a
    ordem de visita;
  - se o cookie de sessão for recusado pelo alvo (expirado, ou colado sem o nome `PHPSESSID=`), a
    análise segue como visitante sem avisar — o resultado mostra só as páginas públicas;
  - duas telas diferentes com exatamente os mesmos rótulos, campos e layout seriam tomadas pelo
    mesmo modelo; a segunda só seria analisada até a terceira repetição seguida do formato.
- **NoSQL:** uma página que devolve sempre o mesmo 404 pode gerar o falso positivo
  `nosql_injection.operator_bypass_confirmed`, porque `_looks_rejected` trata 404 como rejeição
  (ver [EVALUATION_RESULTS.md](EVALUATION_RESULTS.md)).
- **Verbos HTTP:** PUT, DELETE, PATCH e TRACE são enviados uma vez por página visitada, e não uma
  vez por varredura.

## Contrato de saída

O documento JSON que o motor imprime está especificado em
[INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md) e é verificado por
`tests/test_integration_contract.py`. Duas regras foram explicitadas na Fase 5: `duration_ms` é a
duração de relógio da varredura inteira (antes trazia o tempo de resposta da página-semente), e todo
campo de texto de um achado é ajustado à largura da coluna que o armazena (`FINDING_FIELD_LIMITS`
em `engine/models.py`), porque parte de um achado — um nome de campo de formulário, uma URL — vem
do alvo e não tem limite.
