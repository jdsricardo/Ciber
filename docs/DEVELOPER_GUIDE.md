# Guia do Desenvolvedor

Tudo o que um desenvolvedor precisa para ler, executar, alterar e testar o código do SentinelScope.
O *porquê* da estrutura está em [ARCHITECTURE.md](ARCHITECTURE.md); as regras que toda mudança
segue estão em [CODING_STANDARD.md](CODING_STANDARD.md); a fronteira entre a aplicação PHP e o motor
Python está especificada em [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md).

## 1. Estrutura do repositório

```
app/
  autoload.php            App\ → app/src/ (sem sessão, sem .env: é o que os testes carregam)
  bootstrap.php           ambiente web: autoload + .env + UTC + sessão + display_errors=0
  src/
    Domain/               entidades, objetos de valor, contratos, serviço de comparação, erros
      Contract/           interfaces que as camadas externas implementam (5)
      Exception/          DomainError e suas três subclasses
      Model/              Application, Analysis, Finding, TargetUrl, Period, SecurityScore, …
      Service/            AnalysisComparison
    UseCase/              uma classe por operação (4)
    Infrastructure/       repositórios PDO, gateway Python, Config, Database, Csrf
    Presentation/         Views, Layout, FindingPresenter, Html
public/
  index.php               front controller (o único ponto de entrada PHP)
  assets/app.css, app.js  estilos; script de aprimoramento progressivo
scanner/
  scanner.py              ponto de entrada de linha de comando que o gateway inicia
  engine/                 rastreamento, transporte, segurança, normalização, confiança, runner
  plugins/                uma classe por família de vulnerabilidade; plugins/active/ para as sondas
database.sql              esquema, índices, migrações aditivas (pode ser reexecutado com segurança)
tests/
  php_test.php, php/      suíte PHP e seus dublês de teste em memória
  test_*.py, support/     suíte Python e o servidor HTTP local auxiliar
  fixtures/               payload compartilhado pelos dois lados dos testes de contrato
  e2e/                    alvo de laboratório e o driver de testes de sistema/injeção de falhas
evaluation/               arcabouço de avaliação empírica e benchmarks
docs/                     documentação de engenharia (este arquivo e seus irmãos)
docs/test-evidence/       evidências brutas de cada execução da bateria de testes
docs/docsAula/            documentos entregues na disciplina (não editados pelo código)
docs/entrega-final/       documento da entrega final e suas evidências
```

## 2. Ambiente local

Os requisitos e a instalação passo a passo estão em
[INSTALLATION_AND_USER_MANUAL.md](INSTALLATION_AND_USER_MANUAL.md). Para desenvolvimento, a
versão curta é:

```bash
# MariaDB e Apache do XAMPP em execução; depois, na raiz do projeto:
mysql -u root < database.sql
cp .env.example .env            # defina DB_PASSWORD; ALLOW_PRIVATE_TARGETS=true para o laboratório
python -m unittest discover -s tests      # suíte Python (~4-5 min: sockets reais)
php tests/php_test.php                    # suíte PHP (segundos; não precisa de banco)
```

Lembre-se de criar também o usuário `sentinelscope_app` (passo A.4 do manual), pois o `.env` de
exemplo aponta para ele.

### 2.1 Configuração (`.env`)

| Chave | Padrão | Usada por | Significado |
|---|---|---|---|
| `DB_HOST`, `DB_PORT`, `DB_NAME` | `127.0.0.1`, `3306`, `sentinelscope` | `Infrastructure\Database` | Localização do MariaDB. |
| `DB_USER`, `DB_PASSWORD` | — | `Infrastructure\Database` | Um usuário dedicado com `SELECT, INSERT, UPDATE, DELETE` apenas no esquema. |
| `PYTHON_BINARY` | `python` | `PythonScannerGateway` | Executável que roda `scanner/scanner.py`; use o caminho completo quando o `PATH` do Apache não contém o Python. |
| `ALLOW_PRIVATE_TARGETS` | `false` | `PythonScannerGateway` → `--allow-private` | Permite que o motor analise endereços de loopback/privados. Apenas para laboratório. |
| `APP_ENV` | `development` | — | Informativa: nenhum código a lê. |

O `.env` é lido a cada requisição, então uma alteração vale imediatamente; ele é ignorado pelo Git.
Uma variável que já exista no ambiente do processo tem precedência sobre o valor do `.env`.

## 3. Ciclo de uma requisição

`public/index.php` é o único ponto de entrada. Uma requisição é tratada assim:

1. `app/bootstrap.php` registra o autoloader, carrega o `.env` (HTTP 503 com orientação quando ele
   não existe), coloca o PHP em UTC, inicia uma sessão endurecida (`httponly`, `SameSite=Lax`,
   `use_strict_mode`) e desliga `display_errors`.
2. O *front controller* constrói os adaptadores PDO e o gateway e os injeta nos casos de uso — é o
   único lugar onde as classes concretas são escolhidas.
3. Um POST só é aceito com o token CSRF da sessão (`Infrastructure\Security\Csrf`).
4. O parâmetro `page` seleciona uma rota:

| Rota | Método | Caso de uso / view | Resultado |
|---|---|---|---|
| *(nenhuma ou desconhecida)* | GET | `ApplicationRepository::all`, `AnalysisRepository::listByApplication`, `Views::dashboard` | Painel com todas as aplicações e seus históricos; `from` / `to` opcionais (`YYYY-MM-DD`, inclusivos) restringem o histórico a um período (400 quando malformados ou invertidos). |
| `add` | GET | `Views::addApplication` | Formulário de cadastro. |
| `create` | POST | `RegisterApplication` | 302 para o painel, ou 400 com o motivo. |
| `run` | POST | `RunAnalysis` | 302 para o resultado (concluído ou com falha), ou 400/404. |
| `result` / `report` | GET | `Views::analysisResult` | Página de resultado / relatório para impressão. |
| `export` | GET | `ExportAnalysis` | Anexo JSON. |
| `compare` | GET | `CompareAnalyses`, `Views::comparison` | Novos / persistentes / corrigidos. |
| `about` | GET | `Views::about` | Página estática. |

5. Um `DomainError` vira o seu status HTTP (`InvalidInput` 400, `NotFound` 404,
   `ScannerUnavailable` 502) com a sua mensagem; qualquer outro `Throwable` é registrado por
   completo no log e o usuário recebe HTTP 500 com uma mensagem genérica. Os dois caminhos desfazem
   antes uma transação aberta.

## 4. Referência dos módulos — PHP

### 4.1 Domínio (`app/src/Domain/`)

| Tipo | Natureza | Responsabilidade |
|---|---|---|
| `Model\Application` | entidade | Um alvo registrado: nome (1–120 caracteres), `TargetUrl`, instante da autorização. |
| `Model\Analysis` | entidade | Uma execução: modo, status, pontuação, métricas, horários, motivo da falha. Rejeita uma análise concluída sem pontuação e uma com falha sem motivo. |
| `Model\Finding` | entidade | Um problema observado, com taxonomia, severidade, confiança, evidência e o exemplo de correção. `identity()` e `endpoint()` implementam a regra de identidade do contrato (§5). |
| `Model\TargetUrl` | objeto de valor | Apenas HTTP(S), ≤ 2.048 caracteres, sem credenciais embutidas. |
| `Model\Period` | objeto de valor | Um intervalo de dias inteiros em UTC para a consulta do histórico por período; qualquer extremidade pode ficar aberta; rejeita data malformada (inclusive datas impossíveis como 2026-02-31) e intervalo invertido. |
| `Model\SecurityScore` | objeto de valor | 0–100; `fromFindings()` aplica a regra 30/15/7/2. |
| `Model\Severity`, `ScanMode`, `AnalysisStatus` | enums | Vocabulários fechados; `fromString()` rejeita valores desconhecidos. |
| `Model\RemediationExample` | objeto de valor | O par "vulnerável × corrigido". |
| `Model\ScanResult` | objeto de valor | O que o motor respondeu: achados e métricas, ou o motivo da falha. `fromEnginePayload()` é a validação do contrato do lado consumidor (regra C4). |
| `Service\AnalysisComparison` | serviço | Classifica os achados de duas análises como novos/persistentes/corrigidos com mapas hash indexados pela identidade. |
| `Contract\*` | interfaces | `ApplicationRepository`, `AnalysisRepository`, `FindingRepository`, `ScannerGateway`, `TransactionManager`. |
| `Exception\*` | erros | `DomainError` (abstrata, carrega o status HTTP) e `InvalidInput`, `NotFound`, `ScannerUnavailable`. |

### 4.2 Casos de uso (`app/src/UseCase/`)

| Classe | Faz | Observações |
|---|---|---|
| `RegisterApplication` | Valida e grava uma aplicação. | Recusa sem a autorização explícita. |
| `RunAnalysis` | Cria a análise `running`, chama o gateway e grava achados e pontuação em uma transação. | Garante o contrato C2: todo caminho de saída — falha do motor, documento inválido, exceção do gateway, defeito, banco recusando a gravação — encerra a análise como `completed` ou `failed`. O modo ativo seguro exige a segunda autorização. |
| `CompareAnalyses` | Carrega duas análises da mesma aplicação e calcula a diferença. | As linhas carregam identidade, endpoint e parâmetro para que a view diga *onde* está cada achado. |
| `ExportAnalysis` | Monta o documento JSON de uma análise: `tool`, `analysis` (metadados), `summary` (`findings`, `by_severity`, `manual_review_required`, `security_score`) e `findings`. | Puro: devolve um array; o controller o escreve. |

### 4.3 Infraestrutura (`app/src/Infrastructure/`)

| Classe | Implementa | Observações |
|---|---|---|
| `Persistence\PdoApplicationRepository`, `PdoAnalysisRepository`, `PdoFindingRepository` | os três repositórios | Os únicos arquivos com SQL. Apenas *prepared statements*. |
| `Persistence\PdoTransactionManager` | `TransactionManager` | Mapeia o "tudo ou nada" para uma transação de banco com *rollback* automático. |
| `Scanner\PythonScannerGateway` | `ScannerGateway` | Inicia o motor com `proc_open` a partir de uma lista de argumentos (sem shell), com stdout/stderr em arquivos temporários; consulta o processo até ele terminar ou até o prazo-limite (210 s passivo, 630 s ativo seguro) e encerra o motor no prazo-limite. Eleva o limite de tempo da requisição de acordo e ignora o abandono pelo cliente, para que a análise sempre seja encerrada. |
| `Database` | — | Conexão PDO preguiçosa: exceções, *prepares* nativos, **fuso horário da sessão UTC**. |
| `Config` | — | Lê o `.env`; 503 quando ele não existe. |
| `Security\Csrf` | — | Token vinculado à sessão, verificado em todo POST. |

### 4.4 Apresentação (`app/src/Presentation/`)

`Views` tem um método estático por tela e apenas monta marcação; `Layout` a envolve na moldura da
página; `FindingPresenter` renderiza um achado (observação → impacto → correção → exemplo → painel
técnico); `Html::escape` é a única função de codificação de saída. Todo valor dinâmico passa por
ela, inclusive a evidência copiada do alvo (contrato C6).

O painel traz o formulário *Histórico por período* (um formulário GET: não altera nada).

`public/assets/app.js` acrescenta conveniências sem ser obrigatório: copiar para a área de
transferência o exemplo corrigido, o controle da autorização do modo ativo, os filtros de
severidade e o indicador de "análise em execução", que também trava o botão de envio contra uma
execução duplicada.

## 5. Referência dos módulos — motor Python

| Módulo | Responsabilidade |
|---|---|
| `scanner.py` | CLI: interpreta os argumentos, força stdout em UTF-8, imprime exatamente um documento JSON, código de saída 0/1. |
| `engine/runner.py` | `run_scan()` e `ScanRunner`: rastreamento em largura conduzido por `CrawlFrontier`, dois baselines por página analisada (uma só requisição para uma variação que repete um modelo), leitura dos scripts da própria origem, todos os plugins em cada página, remoção de duplicatas entre páginas, o documento de resultado. Não contém lógica de vulnerabilidade. `PASSIVE_LIMITS` / `ACTIVE_LIMITS` são os orçamentos de requisições e de tempo. |
| `engine/safety.py` | `SafetyController`: escopo (fixação de host/porta, nova verificação de DNS, bloqueio de redes privadas), orçamentos, limite de taxa, cancelamento, mascaramento de cabeçalhos sensíveis no log. Define as exceções `Cancelled`, `BudgetExceeded`, `EndpointBudgetExceeded`, `ScopeViolation`, cujas mensagens (em português) chegam ao usuário. |
| `engine/transport.py` | `HttpTransport`: o único caminho de código que envia HTTP; leituras limitadas; uma nova tentativa em caso de *reset* transitório; valida certificados TLS. |
| `engine/crawler.py` | Descoberta de páginas de mesma origem (links, formulários GET, redirecionamentos, URLs em JavaScript), as regras de navegação somente leitura (sem logout, sem links ou caminhos que alteram estado, sem arquivos estáticos), assinatura e formato de página, estrutura de página para reconhecer modelos e a fila `CrawlFrontier` (formatos novos primeiro, variações de modelo descartadas, cobertura relatada). |
| `engine/discovery.py` | Pontos de entrada: parâmetros de query e campos de formulário. |
| `engine/normalization.py` | Remove conteúdo volátil antes das comparações; monta o contexto da página. |
| `engine/confidence.py` | A fórmula de confiança e o seu mapeamento para um status. |
| `engine/matchers.py` | Predicados de resposta combináveis (usados pelos testes do motor; nenhum plugin os usa hoje). |
| `engine/models.py` | Dataclasses que cruzam fronteiras de módulos; `Finding.to_dict()` é a serialização do §3.2 do contrato, incluindo o ajuste dos campos de texto à largura das colunas. |
| `plugins/base.py` | `ScannerPlugin` e `PluginMetadata`. |
| `plugins/*.py` | 7 famílias passivas, 34 verificações. |
| `plugins/active/*.py` | 13 famílias ativas seguras, 30 verificações. Cada módulo traz o próprio `CATALOG` de textos. |
| `plugins/catalog.py`, `remediation_examples.py` | Textos (em português) das verificações passivas e exemplos de correção de todas as verificações, por id. |
| `plugins/support.py` | `build_finding()`, construção e envio de sondas para entradas de query e de formulário. |

### 5.1 Catálogo de verificações

| Plugin | Modo | Verificações | CWE | WSTG |
|---|---|---:|---|---|
| TransportSecurityPlugin | passivo | 5 | CWE-319, 326, 298 | CRYP-01, CONF-07 |
| SecurityHeadersPlugin | passivo | 12 | CWE-693, 1021, 200, 116 | CONF-12, CLNT-09 |
| CookieSecurityPlugin | passivo | 5 | CWE-614, 1004, 352, 284 | SESS-02 |
| CorsPassivePlugin | passivo | 2 | CWE-942 | CLNT-07 |
| CacheSecurityPlugin | passivo | 1 | CWE-525 | CONF-12 |
| InformationDisclosurePlugin | passivo | 7 | CWE-200, 209, 548, 540, 319 | INFO-02/05/08, ERRH-01, CONF-04 |
| SecretsExposurePlugin | passivo | 2 | CWE-798 | INFO-05 |
| SqlInjectionPlugin | safe_active | 3 | CWE-89 | INPV-05 |
| ReflectedXssPlugin | safe_active | 3 | CWE-79 | INPV-01 |
| PathTraversalPlugin | safe_active | 2 | CWE-22 | ATHZ-01 |
| OpenRedirectPlugin | safe_active | 2 | CWE-601 | CLNT-04 |
| CommandInjectionPlugin | safe_active | 3 | CWE-78 | INPV-12 |
| TemplateInjectionPlugin | safe_active | 1 | CWE-1336 | INPV-18 |
| XxePlugin | safe_active | 2 | CWE-611 | INPV-07 |
| CrlfInjectionPlugin | safe_active | 1 | CWE-93 | INPV-15 |
| HostHeaderInjectionPlugin | safe_active | 2 | CWE-644 | INPV-17 |
| HttpVerbTamperingPlugin | safe_active | 3 | CWE-650 | CONF-06 |
| NoSqlInjectionPlugin | safe_active | 2 | CWE-943 | INPV-05 |
| CorsActivePlugin | safe_active | 4 | CWE-942 | CLNT-07 |
| SsrfPlugin | safe_active | 2 | CWE-918 | INPV-19 |
| **Total** | | **64** (34 + 30) | | |

Números conferidos em 2026-11-24 contra `plugins_for_mode()`: 7 plugins / 34 verificações no modo
passivo e 20 plugins / 64 verificações no modo `safe_active`.

Observações sobre o comportamento real de duas famílias:

- **TransportSecurityPlugin** — como o transporte valida o certificado e exige TLS 1.2+, um alvo
  com certificado expirado ou que só aceita TLS 1.0/1.1 nem chega a ser lido (a análise falha). Na
  prática, `tls.certificate_expiry` só aparece para certificados ainda válidos que expiram em menos
  de 30 dias, e `tls.legacy_protocol` não tem como disparar.
- **HttpVerbTamperingPlugin** — envia OPTIONS, POST, PUT, DELETE, PATCH e TRACE uma vez **a cada
  página visitada** (não uma vez por varredura). Em uma varredura de 20 páginas são até 20 DELETE,
  cada um para uma URL diferente.

## 6. Mudanças comuns

### 6.1 Adicionar uma verificação

1. Escreva o plugin como subclasse de `ScannerPlugin` em `scanner/plugins/` (passivo) ou
   `scanner/plugins/active/` (ativo seguro), declarando o seu `PluginMetadata` e os ids das
   verificações.
2. Escreva os textos de cada id: em `plugins/catalog.py` para um plugin passivo, ou no `CATALOG` do
   próprio módulo (passado a `build_finding(..., catalog=CATALOG)`) para um plugin ativo. Adicione
   o exemplo de correção em `plugins/remediation_examples.py`.
3. Registre o plugin: em `default_passive_plugins()` (passivo) ou em `ACTIVE_PLUGIN_SPECS`
   (ativo), ambos em `engine/runner.py`.
4. Adicione um teste com um fixture **vulnerável** e um **seguro** servidos por
   `tests/support/local_server.py`. A partir daí, `tests/test_remediation_examples.py` verifica
   automaticamente que todo id tem um exemplo e `tests/test_coding_standard.py` verifica que o
   plugin carrega, declara metadados e não repete um id existente. Um texto ausente no catálogo só
   aparece quando o achado é gerado (`KeyError`), por isso o teste do fixture vulnerável é
   obrigatório.
5. Atualize as contagens em [REQUIREMENTS.md](REQUIREMENTS.md) (FR-02) e no §5.1 acima.

Nenhuma mudança no PHP é necessária: os novos achados trafegam pelo contrato existente.

### 6.2 Alterar o contrato

Siga o §6 de [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md): altere os dois lados no mesmo
commit, incremente a versão, acrescente uma linha ao histórico de mudanças, execute
`python tests/test_integration_contract.py --regenerate-fixture` e rode as duas suítes.

### 6.3 Alterar o esquema

Acrescente um comando aditivo ao `database.sql` (`ADD COLUMN IF NOT EXISTS`, nunca uma mudança
destrutiva), para que reimportar sobre um banco existente seja seguro; se a nova coluna guardar um
campo do achado, acrescente sua largura ao contrato (§3.2) e a `FINDING_FIELD_LIMITS` em
`engine/models.py`.

## 7. Testes

| O quê | Comando | Requer |
|---|---|---|
| Suíte PHP | `php tests/php_test.php` | Apenas PHP |
| Suíte Python (inclui os testes de contrato do produtor) | `python -m unittest discover -s tests -v` | Apenas Python |
| Um arquivo de teste Python | `python -m unittest tests.test_integration_contract -v` | Apenas Python |
| Sistema + injeção de falhas | `python tests/e2e/run_system_tests.py [--suite system\|failure] [--only ST-13 …]` | Apache, MariaDB, `.env` com `ALLOW_PRIVATE_TARGETS=true`, porta 8765 livre |
| Casos de navegador (MT-01…03) | `python tests/e2e/run_system_tests.py --suite browser` | o mesmo que acima, mais Chrome ou Edge (controlado sem interface por `tests/e2e/cdp.py`) |
| Apenas o alvo de laboratório | `python tests/e2e/lab_target.py --variant vulnerable --log lab.jsonl` | Apenas Python |
| Preparar a demonstração ao vivo | `python tests/e2e/demo.py --limpar` — cadastra o site de testes e um endereço fora do ar, faz a análise "antes" com o site `vulnerable` e deixa o site no ar como `partial` para a análise "depois" e a comparação | Apache, MariaDB, `.env` com `ALLOW_PRIVATE_TARGETS=true`, portas 8765 e 8799 livres |

O driver de sistema grava `docs/test-evidence/<execução>/results.md` e `results.json`, além das
evidências brutas (`--run-name` define o nome da pasta). Os casos de injeção de falhas alteram o
ambiente (param o MariaDB, revogam um privilégio, ativam o modo SQL estrito, reescrevem o `.env`) e
o restauram em um bloco `finally`; execute-os apenas em uma máquina de desenvolvimento. O plano está
em [TEST_PLAN.md](TEST_PLAN.md) e os resultados em [TEST_REPORT.md](TEST_REPORT.md).

## 8. Depuração

| Sintoma | Onde olhar |
|---|---|
| Página genérica de "erro inesperado" | `logs/error.log` do Apache (a pasta `php/logs/` do XAMPP não existe, então o PHP registra ali): cada linha começa com `SentinelScope:` e traz a exceção completa. |
| Análise falhou com "resposta inválida" | Rode o motor à mão: `python scanner/scanner.py <url> --mode=passive [--allow-private]` e confira se ele imprime um único documento JSON. |
| Análise falhou com "excedeu o tempo máximo" | O motor não terminou dentro do prazo-limite; o alvo é lento ou muito grande. Use `--max-pages` na linha de comando para delimitá-lo. |
| Análise falhou com "Nenhuma página pôde ser acessada no alvo." | A página-semente não respondeu: alvo fora do ar, porta errada, firewall ou falha de TLS (certificado inválido/expirado, TLS < 1.2). |
| Alvo privado bloqueado | Proteção esperada contra SSRF; `ALLOW_PRIVATE_TARGETS=true` apenas em laboratório. |
| Log de requisições do motor | `python scanner/scanner.py <url> --log-file scan.jsonl` (segredos mascarados). |
