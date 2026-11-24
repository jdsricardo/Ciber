# Arquitetura

O SentinelScope usa uma implantação local em camadas. O navegador envia requisições a uma
aplicação PHP pura. O PHP valida a entrada, orquestra as análises, renderiza os resultados e
persiste os dados por meio de *prepared statements* do PDO. Um processo Python, iniciado à parte,
executa as requisições HTTP limitadas e devolve JSON. O MariaDB armazena aplicações, análises e
achados.

## Camadas e direção das dependências

```
                        public/index.php
                               |
       Presentation ---+--- UseCase ---> Domain <--- Infrastructure
       (Views,             (RegisterApplication,  (Model,        (PDO repositories,
        Layout,             RunAnalysis,           Contract,      PythonScannerGateway,
        FindingPresenter,   CompareAnalyses,       Service,       Config, Database, Csrf)
        Html)               ExportAnalysis)        Exception)
```

Toda seta aponta para `app/src/Domain/`, que não depende de nada fora de si — regra garantida por
um teste em `tests/php_test.php` que falha se algum arquivo do domínio referenciar, em código,
`App\Infrastructure`, `App\Presentation`, `App\UseCase` ou `PDO`.

| Camada | Diretório | Responsabilidade | Pode depender de |
|---|---|---|---|
| Domain | `app/src/Domain/` | Entidades (`Application`, `Analysis`, `Finding`), objetos de valor (`TargetUrl`, `Period`, `SecurityScore`, `Severity`, `ScanMode`, `AnalysisStatus`, `RemediationExample`, `ScanResult`), o serviço de comparação, os contratos e a convenção de erros. Valida no construtor, de modo que um objeto inválido não pode existir. | nada |
| UseCase | `app/src/UseCase/` | Uma classe por operação da aplicação: `RegisterApplication`, `RunAnalysis`, `CompareAnalyses`, `ExportAnalysis`. Orquestra o domínio por meio dos contratos e é dona da fronteira transacional. | Domain |
| Infrastructure | `app/src/Infrastructure/` | Implementa os contratos do domínio: `PdoApplicationRepository`, `PdoAnalysisRepository`, `PdoFindingRepository`, `PdoTransactionManager`, `PythonScannerGateway`, além de `Config`, `Database` e `Csrf`. Único lugar onde existem SQL e a invocação do Python. | Domain |
| Presentation | `app/src/Presentation/` | `Views` (um método por tela), `Layout`, `FindingPresenter`, `Html`. Lê entidades, produz marcação e não decide nada. | Domain, UseCase |

`public/index.php` é o *front controller*: constrói os adaptadores, conecta-os aos casos de uso,
despacha uma requisição e converte um `DomainError` no seu status HTTP. Não contém regras.

### Contratos declarados pelo domínio

| Interface | Implementada por (produção) | Implementada por (testes) |
|---|---|---|
| `Domain\Contract\ApplicationRepository` | `PdoApplicationRepository` | `Tests\Php\InMemoryApplicationRepository` |
| `Domain\Contract\AnalysisRepository` | `PdoAnalysisRepository` | `Tests\Php\InMemoryAnalysisRepository` |
| `Domain\Contract\FindingRepository` | `PdoFindingRepository` | `Tests\Php\InMemoryFindingRepository` |
| `Domain\Contract\ScannerGateway` | `PythonScannerGateway` | `Tests\Php\FakeScannerGateway`, `Tests\Php\ThrowingScannerGateway` |
| `Domain\Contract\TransactionManager` | `PdoTransactionManager` | `Tests\Php\ImmediateTransactionManager`, `Tests\Php\FailingTransactionManager` |

### Convenção de erros

O domínio lança apenas subclasses de `DomainError` — `InvalidInput` (400), `NotFound` (404),
`ScannerUnavailable` (502) — com uma mensagem já escrita para o desenvolvedor que usa a aplicação.
Falhas de infraestrutura são encapsuladas pelo adaptador que as produziu. Qualquer coisa que chegue
ao *front controller* como um `Throwable` comum é um defeito: é registrada por completo no log e o
usuário vê uma mensagem genérica. Veja o §6 de [CODING_STANDARD.md](CODING_STANDARD.md).

## Fluxo principal

1. O desenvolvedor registra um alvo autorizado.
2. O PHP cria uma análise `running` e inicia o motor Python (`scanner/scanner.py`) como processo
   filho, a partir de uma lista de argumentos e sem shell, sob um prazo-limite alinhado ao
   orçamento de tempo do próprio motor. Tudo o que atravessa essa fronteira — argumentos, o
   documento JSON, larguras dos campos, respostas de falha e o que o consumidor deve fazer com cada
   uma — está especificado em [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md) e é garantido por
   testes de contrato dos dois lados.
3. O motor Python (`scanner/engine/`) valida a URL e os endereços resolvidos e então rastreia em
   largura a superfície de mesma origem alcançável (`engine/crawler.py`): partindo da URL-semente,
   segue links `<a>`, *actions* de formulários GET e redirecionamentos de mesma origem, até um
   limite de páginas e de profundidade, de modo que a análise cobre páginas que o usuário nunca
   digitou — por exemplo, uma página desprotegida a um clique depois da tela de login. Para cada
   página descoberta, envia duas requisições de baseline independentes por um transporte
   controlado pelo mecanismo de segurança, monta o contexto da página e executa todos os plugins
   registrados (`scanner/plugins/`) — 34 verificações passivas de segurança de transporte,
   cabeçalhos de segurança, cookies, CORS, cache, exposição de informações e exposição de segredos,
   mais os detectores ativos no modo `safe_active` — emitindo achados JSON estruturados com
   severidade, confiança, status, referências CWE/OWASP/WSTG e evidência sanitizada. O rastreamento
   é deliberadamente somente leitura: links de logout/sair e links que alteram estado
   (`?action=delete`, `?remove=`, …) nunca são seguidos, de modo que uma sessão autenticada
   sobrevive ao rastreamento e a navegação não provoca efeito colateral destrutivo. **Atenção:** no
   modo `safe_active`, a verificação de verbos HTTP (`HttpVerbTamperingPlugin`) envia OPTIONS,
   POST, PUT, DELETE, PATCH e TRACE uma vez a cada página visitada; em um alvo vulnerável esses
   métodos podem ser de fato executados, por isso o modo completo deve ser usado apenas em
   ambientes de teste.
4. O PHP valida o documento, grava os achados em uma transação, calcula a pontuação e marca a
   análise como concluída. Qualquer outro desfecho — falha do motor, documento ilegível ou que viola
   o contrato, prazo-limite excedido, banco recusando a gravação — encerra a análise como `failed`
   com o motivo; nenhuma análise sobrevive à sua requisição no estado `running`.
5. A interface apresenta cada problema como observação, impacto para o desenvolvedor, correção, um
   exemplo concreto de código/configuração "vulnerável × corrigido"
   (`scanner/plugins/remediation_examples.py`, indexado pelo id da verificação e incorporado a cada
   achado por `build_finding`), um selo de confiança/status e um painel técnico recolhível com a
   evidência bruta. A identidade dos achados (verificação, endpoint, parâmetro) dá suporte às
   comparações.

## Funcionamento interno do motor de varredura

O motor é deliberadamente organizado em camadas para que adicionar uma verificação nunca exija
mexer no núcleo:

- `engine/models.py` — modelo de dados tipado de requisição/resposta/achado/evidência compartilhado
  por todos os plugins.
- `engine/safety.py` + `engine/transport.py` — controle de escopo (fixação de host/porta, nova
  resolução de DNS a cada requisição, bloqueio de redes privadas), limitação de taxa, orçamentos e o
  único caminho de código autorizado a fazer uma requisição HTTP. O transporte repete uma vez em
  caso de *reset* TCP transitório (cobrando o orçamento de requisições uma única vez). Uma página
  que não pode ser obtida é pulada; se nem a página-semente responde, a varredura termina como
  falha (`ok:false`, "Nenhuma página pôde ser acessada no alvo."), nunca como erro não tratado.
- `engine/normalization.py` — remove conteúdo volátil (horários, UUIDs, tokens CSRF/nonce) antes de
  qualquer comparação e deriva o contexto da página (tem formulários, tem campo de senha, parece
  autenticada) usado para manter a severidade proporcional.
- `engine/confidence.py` — o único lugar que transforma força da evidência, reprodutibilidade e
  ambiguidade em uma confiança de 0 a 100 e em um status do achado, independente da severidade.
- `engine/discovery.py` — transforma uma URL e um documento HTML na lista de `InputPoint` que os
  detectores ativos sondam: parâmetros da query string mais os campos de todos os formulários.
  Cada ponto é identificado por canal e nome: um nome repetido no mesmo canal é testado uma única
  vez, e o mesmo nome na query e em um formulário é testado em cada canal.
- `engine/matchers.py` — um pequeno vocabulário de predicados combináveis sobre uma resposta
  (status, cabeçalho, texto, tamanho, similaridade, tempo, redirecionamento) com `&`, `|` e `~`.
  Está disponível para detectores que prefiram condições declarativas; os plugins atuais expressam
  suas condições diretamente, então ele é exercitado pelos testes do motor e não por um plugin.
- `engine/crawler.py` — descoberta de links/redirecionamentos de mesma origem: interpreta alvos de
  `<a>` e *actions* de formulários GET, mantém apenas URLs HTTP(S) dentro do escopo no host/porta
  fixados e aplica as regras de navegação somente leitura (ignora logout/sair, ignora links que
  alteram estado no estilo `?action=delete`, ignora arquivos estáticos). As páginas são agrupadas
  por *assinatura* (caminho + conjunto de nomes de parâmetros da query, ignorando os valores), de
  modo que `/product?id=1` e `/product?id=2` contam como uma página.
- `engine/runner.py` — orquestra o rastreamento em largura e, para cada página descoberta, a coleta
  de baselines e a execução dos plugins; não contém lógica específica de vulnerabilidade. Remove
  duplicatas de achados entre páginas (condições do servidor inteiro — cabeçalhos, transporte,
  cookies, cache, CORS — uma vez por fingerprint; achados de injeção/exposição por
  fingerprint+endpoint+parâmetro) e compartilha um único orçamento do `SafetyController` entre
  rastreamento e sondagem, de modo que uma varredura nunca excede seu envelope de requisições/tempo,
  qualquer que seja o tamanho do site. O rastreamento é limitado por `max_pages` e `max_depth`
  (ajustáveis por execução com `--max-pages`/`--max-depth`); `max_pages=1` reproduz o comportamento
  original de página única.
- `plugins/*.py` — uma classe por família de vulnerabilidade (subclasses de `ScannerPlugin`), cada
  uma declarando seus metadados CWE/OWASP/WSTG e os ids das verificações que possui;
  `plugins/catalog.py` centraliza os textos de referência para que sejam escritos uma única vez
  (os plugins ativos mantêm o próprio `CATALOG` no mesmo formato).
- `plugins/support.py` `build_probe`/`send_probe` — auxiliar de sondagem independente da origem do
  parâmetro: parâmetros de query são testados na URL (GET), campos de formulário são enviados no
  corpo de um POST (preservando os campos vizinhos). Os plugins ativos percorrem
  `testable_inputs` (query + formulário) em vez de apenas a query. O teste de formulário/POST está
  ligado em todos os detectores de injeção de valor — SQL injection, XSS refletido, path traversal,
  open redirect, command injection, SSTI e SSRF. CRLF (reflexão em cabeçalho) e NoSQL (mutação de
  chave `name[$ne]`) continuam apenas na query porque a construção da sonda depende do canal.
  Limitação conhecida: a sonda de formulário é enviada à URL da página onde o formulário está, não
  ao `action` do formulário.
- Varredura autenticada: `ScanContext.auth_headers` (um cookie de sessão ou um token *bearer*) é
  anexado a toda requisição pelo transporte, cobrindo verificações passivas e ativas sem tocar em
  nenhum plugin. Só é enviado ao host/porta fixados, é mascarado nos logs e é repassado pela
  aplicação web apenas durante a análise (nunca persistido).

Essa estrutura é a que os 13 plugins ativos já usam e a que futuras famílias (por exemplo, IDOR)
devem estender: novos plugins se registram na mesma interface `ScannerPlugin` e reutilizam a mesma
maquinaria de baseline/diferença/confiança, em vez de cada um reimplementar a lógica de comparação.

## Fronteiras de segurança

- Destinos privados, de loopback, link-local e reservados são bloqueados por padrão.
- O motor aceita apenas HTTP(S), rejeita credenciais na URL, nunca segue um redirecionamento
  automaticamente (o destino de um redirecionamento de mesma origem é enfileirado como página e
  revalidado contra o escopo), limita o tamanho das respostas e usa um tempo limite por requisição.
- Em HTTPS, o certificado do alvo é validado e é exigido TLS 1.2 ou superior (contexto padrão do
  Python); um alvo com certificado inválido ou expirado não pode ser analisado.
- O motor é iniciado sem shell, então nenhum valor fornecido pelo usuário consegue estender a linha
  de comando; o cookie de sessão existe apenas nos argumentos desse processo e nunca é persistido
  nem registrado em log.
- `display_errors` é forçado a desligado pelo bootstrap: um erro fatal nunca mostra caminho ou
  *stack trace* no navegador.
- Mutações exigem um token CSRF vinculado à sessão. A codificação da saída mitiga XSS armazenado.
  *Prepared statements* nativos do PDO previnem SQL injection.
- A versão acadêmica atual pressupõe uma instalação local confiável, de usuário único. Autenticação
  e controle de acesso por papéis são recomendados antes de uma implantação compartilhada.

## Modelo de dados

`applications 1—N analyses 1—N findings`. Índices nos caminhos aplicação/data e
análise/fingerprint dão suporte ao histórico e à comparação. Chaves estrangeiras preservam a
consistência, e `findings` é removida em cascata, de modo que uma análise nunca deixa linhas órfãs.
Todo horário é UTC: a conexão define o fuso da sessão como `+00:00`, então os valores padrão das
colunas e as gravações explícitas com `UTC_TIMESTAMP()` compartilham o mesmo relógio.

Duas análises são comparadas pela **identidade do achado** — id da verificação, endpoint sem query
string, localização e nome do parâmetro (`Finding::identity()`, contrato §5) — e não apenas pelo
id da verificação, de modo que a mesma fraqueza corrigida em um endpoint e ainda aberta em outro
aparece como *corrigida* e *persistente*, respectivamente.

| Tabela | Operação predominante | Índice que a atende |
|---|---|---|
| `applications` | listar e buscar pela chave primária | chave primária |
| `analyses` | inserir e depois ler o histórico de uma aplicação por data, opcionalmente dentro de um período | `idx_analysis_application_date (application_id, started_at)` — o período é um intervalo na segunda coluna |
| `findings` | inserção em lote por análise e depois leitura de todos os achados de uma análise | `idx_finding_analysis (analysis_id)`, `idx_finding_fingerprint (analysis_id, fingerprint)` |

## Decisões medidas

Quatro escolhas estruturais desta arquitetura foram feitas porque foram medidas, não porque se
esperava que fossem mais rápidas. Cada uma foi comparada com a alternativa que o enunciado do
problema sugere naturalmente, nos tamanhos de entrada que o sistema realmente atinge e em duas
ordens de grandeza acima.

| Decisão | Alternativa rejeitada | Estrutura adotada | Onde |
|---|---|---|---|
| Fila do rastreamento | lista + `pop(0)` (deslocamento O(n) a cada visita) | `collections.deque` | `scanner/engine/runner.py` |
| Páginas já enfileiradas | busca em lista (O(n)) | `set` (O(1) em média) | `scanner/engine/runner.py` |
| Remoção de achados duplicados | varredura par a par (O(n²)) | `set` de chaves + lista ordenada | `ScanRunner._deduplicate()` |
| Comparação entre análises | varredura par a par (O(n²)) | mapa indexado pela identidade do achado | `app/src/Domain/Service/AnalysisComparison.php` |

A decisão da comparação é a que importa para o NFR-01: com 1.000 achados a versão par a par custa
94,8 ms contra 0,2 ms do mapa indexado, e degrada para cerca de 10 s com 10.000 achados, enquanto o
mapa indexado fica abaixo de 3 ms. A decisão da fila do rastreamento é registrada pelo que é —
nenhum ganho mensurável no tamanho que uma varredura realmente atinge (`max_pages` de 30), adotada
porque elimina o único termo quadrático do laço de rastreamento.

Resultados completos, método e ambiente estão em
[ALGORITHM_MEASUREMENTS.md](ALGORITHM_MEASUREMENTS.md); eles são reproduzidos com
`python evaluation/benchmark_structures.py` e `php evaluation/benchmark_comparison.php`.

---

**Repositório.** O código-fonte, os testes e a documentação de engenharia descritos nas seções
acima estão versionados em https://github.com/jdsricardo/Ciber.git
