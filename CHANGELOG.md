# Changelog

Todas as mudanças relevantes do SentinelScope. Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).

## [Não lançado] — 2026-11-24 · Documentação em português e revisão contra o código

### Alterado
- Toda a documentação de engenharia (`README.md`, `CHANGELOG.md`, `docs/*.md`) traduzida para o
  português e reconferida contra o código. NFR-06 e o §1 do padrão de codificação passam a
  declarar a documentação em português; o código-fonte continua em inglês.
- Mensagens de erro do motor exibidas ao usuário (violação de escopo, orçamento de requisições ou
  de tempo, cancelamento) traduzidas para o português, como exige o §3.3 do contrato
  (`scanner/engine/safety.py`). Quando a análise termina antes de a primeira página responder, o
  motor devolve uma frase em português em vez do código interno (`budget_exceeded`, `cancelled`)
  (`scanner/engine/runner.py`).
- [Contrato de integração](docs/INTEGRATION_CONTRACT.md) 1.2: `stopped_early` também assume
  `scope_violation`; exemplo e causas de falha do §3.3 corrigidos para as mensagens reais.
- Comentários e docstrings desatualizados corrigidos (`Finding.php`, `scanner.py`,
  `http_verb_tampering.py`, `nosql_injection.py`).

### Corrigido na documentação
- O plano de testes citava `tests/e2e/browser_tests.py`, que não existe; os casos de navegador
  rodam com `run_system_tests.py --suite browser`.
- O relatório de testes atribuía ao FI-04 a mensagem "Falha de rede ao acessar o alvo…"; para um
  alvo que não responde, o motor registra "Nenhuma página pôde ser acessada no alvo.".
- `SCANNER_ENGINE.md` descrevia a Fase 1 (`run_passive_scan`, `app/bootstrap.php` persistindo os
  achados, sondas ativas "ainda não habilitadas"); foi reescrito para o motor atual.
- O manual e a arquitetura afirmavam que o modo completo é "não destrutivo" sem mencionar que a
  verificação de verbos HTTP envia PUT, DELETE e PATCH a cada página visitada.

## [1.0.1] — 2026-10-28 · Conferência final contra o Termo de Referência

### Adicionado
- Histórico por período no painel (*Histórico por período*: de / até, ambos inclusivos) — o item 6
  do Termo pedia e não existia (**D-09**). `Domain\Model\Period`;
  `AnalysisRepository::listByApplication()` recebe um período opcional, atendido pelo índice
  existente `(application_id, started_at)`.
- O `summary` da exportação JSON passa a trazer achados por severidade, achados que exigem revisão
  manual e a pontuação — o item 8 do Termo pedia um resumo e a exportação trazia só uma contagem
  (**D-10**).
- Casos de navegador MT-01…MT-03 automatizados em um Chrome/Edge real sem interface
  (`tests/e2e/cdp.py`).
- Casos de teste ST-25 e ST-26.

## [1.0.0] — 2026-10-14 · Fases 4 e 5 (construção, integração e verificação)

### Adicionado
- Indicador de progresso no formulário de execução, com o botão de envio travado após o primeiro
  clique, para que um clique duplo não inicie uma análise duplicada (passo 23 do roteiro).
- [Contrato de integração](docs/INTEGRATION_CONTRACT.md) v1.1 entre a aplicação PHP e o motor
  Python, com testes de conformidade dos dois lados lendo um mesmo payload capturado.
- Driver de testes de sistema e de injeção de falhas (`tests/e2e/run_system_tests.py`) e um alvo
  de laboratório controlável (`tests/e2e/lab_target.py`).
- [Plano de testes](docs/TEST_PLAN.md) 2.0, [relatório de testes](docs/TEST_REPORT.md), evidências
  brutas em `docs/test-evidence/`, [guia do desenvolvedor](docs/DEVELOPER_GUIDE.md) e
  [conformidade com o roteiro](docs/ROADMAP_COMPLIANCE.md).
- A página de comparação mostra a página e o parâmetro de cada achado.

### Corrigido
- **D-01** A comparação fundia a mesma verificação encontrada em dois endpoints; os achados agora
  são comparados pela identidade (verificação, endpoint, parâmetro).
- **D-02** Uma falha ao gravar o resultado deixava a análise `running` para sempre; agora ela é
  encerrada como `failed`.
- **D-03** No Windows, `%`, `!` e `"` na URL do alvo ou no cookie de sessão eram trocados por
  espaços antes de chegar ao motor; o motor agora é iniciado sem shell.
- **D-04** Análises mais longas que o limite de 120 s do PHP morriam com um erro fatal que exibia
  um caminho do servidor e permaneciam `running`; o gateway agora controla o prazo-limite e a
  exibição de erros está desligada.
- **D-05** A duração da análise mostrava o tempo de resposta de uma requisição; agora é a duração
  da varredura inteira.
- **D-06** Valores maiores que a coluna do banco (por exemplo, um nome de campo de formulário com
  300 caracteres) faziam um banco em modo estrito rejeitar a análise; o motor ajusta cada campo à
  largura da sua coluna.
- **D-07** `started_at` era gravado no horário local do servidor e `completed_at` em UTC; todo
  horário agora é UTC.
- **D-08** O contrato v1.0 não listava `cookie` como `parameter_location` (apenas documentação).

### Alterado
- Manual de instalação e de uso reescrito: criação do usuário do banco, referência do `.env`,
  verificações do primeiro acesso, verificação com o laboratório, solução de problemas.

## [0.3.0] — 2026-09-23 · Fase 3 (arquitetura)
- Arquitetura em camadas (Domain, UseCase, Infrastructure, Presentation) com contratos declarados
  pelo domínio e dublês de teste em memória.

## [0.2.0] — 2026-09-16 · Fase 2 (decisões técnicas)
- Padrão de codificação, medições de algoritmos e estruturas de dados, modelo de domínio.

## [0.1.0] — 2026-08-23 · Linha de base
- Motor de varredura com plugins passivos e ativos seguros, aplicação web, esquema do banco.
