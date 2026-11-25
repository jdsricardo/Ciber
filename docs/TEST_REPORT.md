# Relatório de Testes

| | |
|---|---|
| Produto | SentinelScope 1.0.1 — o código após as correções de D-01…D-10 (execução 3) |
| Plano | [TEST_PLAN.md](TEST_PLAN.md) 2.0, redigido **antes** da primeira execução; a 2.1 acrescenta as revisões datadas do seu §8 |
| Executado | 2026-10-14 (execuções 1, 1b, 2) e 2026-10-28 (execuções 3a, 3), com o driver de teste automatizado; MT-04 pendente (§6). Reverificação parcial em 2026-11-24 (§8). Execução 4 completa em 2026-11-25, após o rastreamento inteligente (§9). |
| Ambiente | Conforme o §2 do plano: Windows 11 Pro 10.0.26200, XAMPP Apache 2.4 + PHP 8.2.12, MariaDB 10.4.32, Python 3.12.2 |
| Evidência bruta | `docs/test-evidence/2026-10-14_run1`, `…_run1-failure`, `…_run1b-confirm`, `…_run2`, `2026-10-28_run3a-before`, `…_run3`, `2026-11-25_run4`, `…_run4b-rerun` (`results.md`/`results.json` por caso, logs de requisições do laboratório, exportações JSON, respostas HTML, saídas das suítes) |

## 1. Resumo

| Execução | Código · início (UTC) | AT-01 Python | AT-02 PHP | Sistema (ST) | Injeção de falhas (FI) |
|---|---|---|---|---|---|
| 1 | antes das correções · 2026-10-14 23:00 | 108 / 113 | 129 / 133 | 20 / 23 | 6 / 10 ¹ |
| 1b — confirmação | antes das correções · 2026-10-14 23:05 | — | — | ST-24: 0 / 1 | FI-02, 03: aprovados; FI-08, 09: reprovados |
| 2 — reexecução | após as correções D-01…D-08 · 2026-10-14 23:13 | 113 / 113 | 140 / 140 | 24 / 24 | 10 / 10 |
| 3a — novos casos, antes de D-09/D-10 | antes de D-09/D-10 · 2026-10-28 22:32 | — | — | ST-25, ST-26: 0 / 2; navegador 2 / 3 ² | — |
| 3 — reexecução final (até 2026-11-24) | código de 2026-10-28 · 22:36 | 113 / 113 | 153 / 153 | 26 / 26 + navegador 3 / 3 | 10 / 10 |
| 4 — rastreamento inteligente | após D-11 · 2026-11-25 14:30 | 124 / 124 ³ | 168 / 168 | 27 / 27 + navegador 2 / 3 ⁴ | 9 / 10 ⁴ |
| **4b — reexecução final** | **código final · 2026-11-25 14:55** | **125 / 125** ³ | **168 / 168** | **navegador 3 / 3** | **FI-02: aprovado** |

¹ Das quatro reprovações da execução 1, duas (FI-02, FI-03) foram falsos positivos do driver de
teste e uma (FI-09) não provocou a falha que deveria provocar; ver §4. Elas foram reexecutadas na
1b antes de qualquer mudança no código do produto.

² O MT-01 reprovou na execução 3a por causa do driver de teste, não do produto (TW-04, §4).

³ 113 testes anteriores + 12 novos do rastreador (11 na execução 4; o 12º, sobre variações não
visitadas por falta de orçamento, foi escrito junto com a correção feita durante a execução — §9).

⁴ As duas reprovações da execução 4 foram do ambiente de teste, não do produto (TW-05, TW-06, §4);
os casos foram reexecutados na 4b sem nenhuma mudança no código do produto.

**Resultado:** 11 defeitos encontrados (1 bloqueante, 7 altos, 2 médios, 1 baixo); **todos os 11
corrigidos e verificados pela reexecução dos casos que os revelaram** (§3). Nenhum defeito
permanece aberto. Todos os casos planejados foram executados, exceto o **MT-04** — instalação por
uma pessoa de fora da equipe —, do qual depende o CA-07.

A execução 4/4b é o resultado de referência: a bateria inteira executada sobre o código final em
2026-11-25. A execução 3 é a referência para o código anterior ao rastreamento inteligente.

### 1.1 Critérios de aceite

| Critério | Veredito | Evidência (execução 2) |
|---|---|---|
| CA-01 — o catálogo é executado e a conclusão é registrada | **Atendido** | ST-06 (34 verificações, passivo), ST-08 (64 verificações, modo completo), AT-01 |
| CA-02 — todo achado tem severidade, confiança, status, taxonomia, evidência e correção | **Atendido** | ST-09 (todos os 14 achados do ST-08 completos), ST-11, ST-19 |
| CA-03 — pontuação 0–100 pela regra 30/15/7/2 | **Atendido** | ST-10: página e exportação iguais ao cálculo manual nas duas análises |
| CA-04 — a comparação mostra novos, persistentes e corrigidos | **Atendido após D-01** | ST-13, ST-14 (reprovados na execução 1) |
| CA-05 — 1.000 achados em menos de 3 s | **Atendido** | ST-22: pior das 20 respostas cronometradas 129,1 ms na execução 3 (89,5 ms na execução 2; limite 3.000 ms) |
| CA-06 — exportação JSON completa e igual ao gravado e ao exibido | **Atendido após D-10** | ST-16, ST-24, ST-26 |
| CA-07 — instalação por alguém de fora usando apenas o manual | **Ainda não verificado** | MT-04 pendente (§6) |
| CA-08 — requisitos de alta prioridade rastreados até o Termo | **Atendido** | Inspeção TR-01 (§5) |

## 2. Resultados por caso (execução 2)

### 2.1 Testes de sistema

Os valores observados são os da execução 2; a execução 3 repetiu todos os casos com o mesmo
veredito e acrescentou ST-25 e ST-26.

| Caso | Cobre | Veredito | Observado |
|---|---|---|---|
| ST-01 | FR-01 | APROVADO | 302 → painel, aviso exibido, linha com `authorization_confirmed_at`. |
| ST-02 | FR-01 *(inv)* | APROVADO | 400, mensagem de autorização, nenhuma linha. |
| ST-03 | FR-01 *(inv)* | APROVADO | 400 com a mensagem específica para cada uma das 5 URLs inválidas; nenhuma linha. |
| ST-04 | FR-01 *(inv)* | APROVADO | 400 para nomes vazio, em branco e com 121 caracteres; nenhuma linha. |
| ST-05 | NFR-02 *(inv)* | APROVADO | 400 "token de sessão expirou" para token ausente e errado, em create e run; nada criado. |
| ST-06 | FR-02, FR-13, NFR-03 | APROVADO | Concluída, 34 verificações; `/`, `/search`, `/profile`, `/about` receberam exatamente 2 GET cada; **0 requisições a `/logout` e `/item`**; nenhum XSS no modo passivo. |
| ST-07 | FR-02 *(inv)* | APROVADO | 400, nenhuma análise criada. |
| ST-08 | FR-02, FR-10 | APROVADO | Concluída em 14,8 s, 64 verificações; XSS em `/search` (q) e `/profile` (name). |
| ST-09 | FR-03/05/09 | APROVADO | Todos os 14 achados completos e exibidos. |
| ST-10 | FR-04 | APROVADO | Pontuações iguais ao cálculo manual. |
| ST-11 | NFR-02 *(inv)* | APROVADO | Nome `<script>` escapado no painel; nenhuma tag crua de sonda na página de resultado. |
| ST-12 | FR-06 | APROVADO | As duas análises listadas, a mais nova primeiro, com modo, status e pontuação. |
| ST-13 | FR-07, CA-04 | APROVADO | *Corrigidos*: XSS em `/search · parâmetro q`; *Ainda presentes*: XSS em `/profile · parâmetro name`; nenhum achado novo. |
| ST-14 | FR-07, CA-04 | APROVADO | Os dois XSS e os quatro achados de cabeçalho em *Corrigidos*; nenhum achado novo; pontuação melhorou. |
| ST-15 | FR-07 *(inv)* | APROVADO | 400 "Escolha duas análises da mesma aplicação." |
| ST-16 | FR-12, CA-06 | APROVADO | Anexo JSON; contagens e fingerprints iguais na exportação, no banco e na página. |
| ST-17 | FR-08 | APROVADO | Relatório com nome, pontuação, métricas, todos os títulos e remediações, botão de impressão, sem link de exportação. |
| ST-18 | FR-12 | APROVADO | Contagens dos chips iguais às da exportação por severidade. |
| ST-19 | FR-11, NFR-07 | APROVADO | `/account/notes` alcançado com o cookie; o segredo não está num dump completo do banco, no log de acesso do Apache nem no log de erros. |
| ST-20 | Contrato R1 | APROVADO | Cookie `lab_session=s3cr%3D!x` recebido byte a byte; primeira requisição `GET /search?q=a%20b`. |
| ST-21 | erros *(inv)* | APROVADO | 404 com a mensagem correta nas quatro rotas. |
| ST-22 | NFR-01, CA-05 | APROVADO | Página de resultado 60–76 ms, relatório 46–90 ms, exportação 41–85 ms, comparação de 1.000 × 1.000 59–80 ms; 1.000 achados renderizados. |
| ST-23 | passo 23 | APROVADO | `data-busy`, `role="status"` e o handler de submit presentes. |
| ST-24 | FR-06, CA-06 | APROVADO | Data do histórico dentro da janela UTC da execução; `started_at ≤ completed_at`, 2 s de diferença. |
| ST-25 | FR-06, Termo item 6 | APROVADO (execução 3; reprovado na 3a — D-09) | Sem período: 3 análises; fevereiro: 1; 15/02–20/03: 2 (extremos inclusivos); extremo aberto: 2; intervalo invertido e `31/02/2026`: 400 com suas mensagens; o formulário mostra o período aplicado. |
| ST-26 | FR-12, Termo item 8 | APROVADO (execução 3; reprovado na 3a — D-10) | `summary` = 14 achados, `by_severity` {critical 0, high 3, medium 5, low 6}, `manual_review_required` 0, `security_score` 8 — cada um igual aos achados e à análise. |

### 2.2 Injeção de falhas (passo 28 do roteiro) — comportamento observado

| Caso | Falha provocada | Comportamento observado (execução 2) | Veredito |
|---|---|---|---|
| FI-01 | `.env` ausente | 503 com a orientação de configuração. | APROVADO |
| FI-02 | MariaDB parado | 500 com a mensagem genérica; nenhum SQLSTATE, caminho ou stack trace na resposta; exceção completa no `error.log` do Apache; a senha não aparece em lugar nenhum (o PHP 8.2 a registra como `Object(SensitiveParameterValue)`). | APROVADO |
| FI-03 | Senha do banco errada | Igual ao FI-02; a senha errada não é exibida nem registrada. | APROVADO |
| FI-04 | Alvo inacessível | `failed` com o motivo "Nenhuma página pôde ser acessada no alvo." exibido; nenhum achado. ³ | APROVADO |
| FI-05 | Loopback com alvos privados negados | `failed` com "Private, loopback, link-local, and reserved targets are blocked"; **0 requisições** chegaram ao alvo. ⁴ | APROVADO |
| FI-06 | Binário Python ausente | `failed` com "O scanner retornou uma resposta inválida…"; não deixada em running. | APROVADO |
| FI-07 | Motor responde `severity: "info"` | `failed` com "Severidade desconhecida: info."; nenhum achado gravado. | APROVADO |
| FI-08 | `INSERT` em `findings` revogado | Página genérica 500; análise `failed` com "Falha ao gravar o resultado da análise…"; nenhum achado parcial. | APROVADO (reprovado na execução 1 — D-02) |
| FI-09 | Varredura mais longa que os 120 s do PHP | Varredura em modo completo de 228,6 s concluída; 302 para o resultado; análise `completed`, pontuação 8, 64 verificações. | APROVADO (reprovado na execução 1b — D-04) |
| FI-10 | Nome de campo de 300 caracteres, modo SQL estrito | `completed`; o achado do formulário gravado com um parâmetro de 180 caracteres. | APROVADO (reprovado na execução 1 — D-06, D-02) |

³ *Correção de 2026-11-24.* A versão anterior deste relatório citava, para o FI-04, a mensagem
"Falha de rede ao acessar o alvo…". A evidência da execução (`results.md`) registra apenas que um
motivo foi gravado e exibido, não o seu texto; e o código (`scanner/engine/runner.py`) produz
"Nenhuma página pôde ser acessada no alvo." quando a conexão é recusada (conferido em 2026-11-24
executando a CLI contra uma porta fechada). "Falha de rede ao acessar o alvo: …" só aparece quando a
resolução DNS do alvo falha. O veredito não muda.

⁴ Mensagem observada na época, em inglês. Desde 2026-11-24 a mensagem do motor está em
português: "Alvos em rede privada, loopback, link-local ou endereços reservados são bloqueados por
padrão."

### 2.3 Suítes automatizadas

| Suíte | Execução 2 | Duração |
|---|---|---|
| AT-01 `python -m unittest discover -s tests -v` | 113 testes, OK (execuções 2 e 3) | 266,3 s |
| AT-02 `php tests/php_test.php` | 140 verificações (execução 2); 153 verificações, 0 falhas (execução 3: + período e resumo da exportação) | < 2 s |

## 3. Registro de defeitos

Severidade conforme o §3.1 do plano. "Verificado" significa que o caso que revelou o defeito foi
reexecutado sobre o código corrigido e passou (execução 2) — não apenas que o código foi alterado.

| ID | Severidade | Título | Encontrado por | Causa raiz | Correção | Verificado |
|---|---|---|---|---|---|---|
| D-01 | Alta | A comparação funde a mesma verificação encontrada em dois endpoints; corrigir um endpoint não aparece | ST-13, ST-14, AT-02 (§5 identidade) | O `fingerprint` do motor é o id da verificação; `AnalysisComparison` usava-o como chave. A URL completa também não serve: carrega o marcador aleatório da sonda. | `Finding::identity()` = verificação + endpoint sem query + localização e nome do parâmetro; comparação indexada pela identidade; a página de comparação mostra página e parâmetro. Contrato §5. | ST-13, ST-14, AT-02 ✔ |
| D-02 | **Bloqueante** | Uma falha ao gravar o resultado deixa a análise em `running` para sempre | FI-08, FI-10, AT-02 (C2) | `RunAnalysis` fechava a análise em falhas do scanner, mas não quando a transação dos achados lançava exceção. | Captura em volta da transação: fecha como `failed` com um motivo e relança para o log. | FI-08, FI-10, AT-02 ✔ |
| D-03 | Alta | `%`, `!` e `"` na URL do alvo ou no cookie de sessão viram espaços antes de chegar ao motor (Windows) | ST-20 | `escapeshellarg()` no Windows substitui esses caracteres; uma URL com percent-encoding falhava e um cookie chegava alterado. | Motor iniciado com `proc_open` a partir de uma lista de argumentos, sem shell (contrato R1/R2). Verificações unitárias da lista de argumentos adicionadas ao AT-02. | ST-20, AT-02 ✔ |
| D-04 | Alta | Uma varredura com mais de 120 s morre com *Fatal error: Maximum execution time … in C:\xampp\…\PythonScannerGateway.php*, HTTP 200, análise deixada em `running` | FI-09 (execução 1b) | No Windows o `max_execution_time` conta tempo de relógio, incluindo a espera pelo motor; `display_errors=On` no XAMPP exibia o caminho. | O gateway eleva o limite da requisição ao seu próprio prazo-limite (210 s / 630 s, alinhados ao orçamento do motor), encerra o motor no prazo-limite com um motivo, ignora a desconexão do cliente; o bootstrap força `display_errors=0`. | FI-09 ✔ |
| D-05 | Média | A *Duração* da análise mostra ~0 ms para uma varredura de 14 s | AT-01 (contrato) | `duration_ms` carregava o tempo de resposta da página-semente. | Duração de relógio da varredura inteira. | AT-01 ✔ |
| D-06 | Alta | Um valor maior que sua coluna (nome de campo de formulário com 300 caracteres) é rejeitado por um banco em modo estrito, perdendo a análise; truncado silenciosamente por um permissivo | AT-01 (contrato), FI-10 | O motor copia nomes e URLs controlados pelo alvo para os achados sem limite. | `FINDING_FIELD_LIMITS` aplicado em `Finding.to_dict()` (contrato §3.2). | AT-01, FI-10 ✔ |
| D-07 | Média | O histórico rotulado "UTC" mostra o horário local do servidor; uma análise parece durar 3 h | Observado na execução 1 (banco), depois ST-24 escrito antes da correção | `started_at` vindo de um default de coluna no fuso local da sessão (America/Sao_Paulo), `completed_at` de `UTC_TIMESTAMP()`. | A conexão define `time_zone = '+00:00'`. | ST-24 ✔ |
| D-09 | Alta | O histórico não pode ser consultado por período, como exige o item 6 do Termo ("consultar o histórico … por período") | Conferência cruzada do Termo com o produto; ST-25 (execução 3a) | Não implementado: o painel sempre listava o histórico inteiro. | `Domain\Model\Period`; `AnalysisRepository::listByApplication()` recebe um período opcional, um intervalo sobre o índice `(application_id, started_at)`; formulário *Histórico por período* no painel. | ST-25, AT-02 ✔ |
| D-10 | Alta | A exportação JSON não tem um resumo de fato, como exige o item 8 do Termo ("resumo, Pontuação de Segurança, metadados e relação dos achados") | Conferência cruzada do Termo com o produto; ST-26 (execução 3a) | `summary` trazia apenas o número de achados. | `summary` com `by_severity`, `manual_review_required` e `security_score`. | ST-26, AT-02 ✔ |
| D-11 | Alta | Telas de aplicações roteadas por parâmetro (`index.php?p=12`, `?p=14`) eram tratadas como uma única página: só a primeira tela do menu era analisada, sem aviso | Uso da ferramenta contra o desenho do Portal de Clientes e do PIM (2026-11-25); reproduzido em `tests/test_crawler.py` (`PortalLike`) | `page_signature` agrupava páginas pelos *nomes* dos parâmetros, ignorando os valores, para não visitar `/produto?id=1..N` muitas vezes; o mesmo critério juntava telas diferentes. Além disso, endpoints chamados por JavaScript não eram descobertos e a cobertura não era informada. | Assinatura com valores; `page_shape` + reconhecimento de modelo de página (`CrawlFrontier`, `page_structure`); URLs lidas no JavaScript; cobertura relatada, gravada e exibida (contrato 1.3). | AT-01 (`SmartCrawlTests`: antes 1 página e 0 de 2 XSS; depois 6 páginas e 2 de 2), ST-27, AT-02 ✔ |
| D-08 | Baixa | A versão 1.0 do contrato não listava `cookie` como `parameter_location` | AT-01 (contrato) | Omissão de documentação; o produtor sempre o emitiu. | Contrato v1.1; teste do produtor atualizado. | AT-01 ✔ |

### 3.1 Passos de reprodução (no código anterior às correções)

- **D-01** Registrar `http://127.0.0.1:8765/`; executar uma análise completa com `lab_target.py --variant vulnerable`; reiniciar o laboratório com `--variant partial`; executar de novo; comparar. *Corrigidos* fica vazio embora `/search` tenha sido corrigido.
- **D-02** `REVOKE` de `INSERT` em `sentinelscope.findings` para o usuário da aplicação; executar qualquer análise. HTTP 500, e o painel mostra a análise em `running` indefinidamente.
- **D-03** Executar com o cookie `lab_session=s3cr%3D!x`; o log do laboratório mostra `Cookie: lab_session=s3cr 3D x`. Registrar `http://127.0.0.1:8765/search?q=a%20b`; a análise falha.
- **D-04** Iniciar o laboratório com `--delay 2`; executar uma análise completa. Após 120 s o navegador mostra o erro fatal com o caminho do servidor; a análise fica em `running`.
- **D-05** `python scanner/scanner.py http://127.0.0.1:8765/ --mode=safe_active --allow-private` → `"duration_ms": 0` após ~14 s.
- **D-06** `SET GLOBAL sql_mode='STRICT_TRANS_TABLES'`; análise completa de `lab_target.py --variant edge`. Log do Apache: `Data too long for column 'parameter'`; análise em `running`.
- **D-07** Executar qualquer análise num servidor cujo fuso horário não seja UTC; `SELECT TIMESTAMPDIFF(SECOND, started_at, completed_at)` retorna 10.800 para uma execução de 2 segundos.
- **D-09** Abrir o painel: nada restringe o histórico a um período; `index.php?from=2026-02-01&to=2026-02-28` lista todas as análises.
- **D-10** Exportar qualquer análise: `"summary": {"findings": N}` e nada mais.
- **D-08** Executar `tests/test_integration_contract.py` com o contrato v1.0: `cookies.missing_httponly.parameter_location must be query, form or null`.

### 3.2 Observações residuais (não são defeitos)

- **Linhas deixadas pelo código antigo.** As análises 15, 17, 19 e 20 do banco de teste ficaram
  em `running` nas execuções 1 e 1b, antes da correção de D-02/D-04. A correção impede novas
  ocorrências; não reescreve o histórico. Uma instalação que rodou a versão antiga pode fechar
  essas linhas com
  `UPDATE analyses SET status='failed', error_message='Interrompida antes da correção D-02/D-04', completed_at=UTC_TIMESTAMP() WHERE status='running';`
  enquanto nenhuma análise estiver em andamento.
- **Encerramento por prazo-limite não exercitado de ponta a ponta.** O FI-09 prova que uma
  varredura mais longa que os 120 s do PHP agora termina. O ramo que encerra o motor no
  prazo-limite do próprio gateway (630 s no modo completo) não foi provocado, porque o orçamento
  de 600 s do próprio motor encerra a varredura antes; esse ramo é verificado apenas por revisão
  de código.
- **Timestamps preexistentes.** As linhas gravadas antes de D-07 mantêm seu `started_at` em
  horário local.

## 4. Problemas do testware

Problemas dos próprios testes, mantidos separados dos defeitos do produto para que os números do
produto não sejam inflados nem escondidos.

| ID | Problema | Efeito | Resolução |
|---|---|---|---|
| TW-01 | A verificação "nenhum detalhe técnico" tratava `.php` como vazamento, mas toda página tem link para `index.php`. | Falsa REPROVAÇÃO em FI-02, FI-03, FI-08 (execução 1). | As respostas foram inspecionadas manualmente (apenas a mensagem genérica); lista de marcadores corrigida; reexecutado na 1b. |
| TW-02 | O driver de teste lia `php/logs/php_error_log`, que o XAMPP não cria; o PHP grava no `error.log` do Apache. | Falsa REPROVAÇÃO "detalhe registrado" no FI-02. | Caminho corrigido; o manual e o guia do desenvolvedor apontam para o log correto. |
| TW-03 | O FI-09 com 1 s por resposta terminou em 115,8 s, abaixo dos 120 s que deveria ultrapassar. | Uma **falsa APROVAÇÃO** na execução 1: a falha não foi provocada. Registrada como nula. | Atraso elevado para 2 s (revisão do plano §8); a execução 1b então reproduziu o D-04. |
| TW-04 | O MT-01 lia o botão pelo DevTools após o clique; depois que um formulário é enviado, o navegador só responde ao DevTools quando a página seguinte termina de carregar. | Falsa REPROVAÇÃO na execução 3a: o driver leu a página de resultado em vez do botão. | Conferido manualmente com o envio bloqueado (o botão é travado e mostra "Analisando…"); o estado agora é registrado dentro da página (MutationObserver → `sessionStorage`) e lido após a navegação. |
| TW-05 | O FI-02 procura o detalhe do erro no log do Apache (`--php-log` padrão), mas nesta máquina o `php.ini` define `error_log = C:\xampp\php\logs\php_error_log`. | Falsa REPROVAÇÃO do item "detalhe registrado" na execução 4; os demais itens do FI-02 (HTTP 500, mensagem genérica, nenhum detalhe na resposta) aprovados. O detalhe estava gravado (`SentinelScope: PDOException … [2002]`, 14:42:10 UTC). | Execução 4b com `--php-log C:\xampp\php\logs\php_error_log`: FI-02 aprovado, inclusive "senha não registrada" conferida no arquivo certo. |
| TW-06 | O MT-03 lê o PDF gerado com `pypdf`, que não estava instalado no Python desta máquina. | REPROVAÇÃO do item "pypdf disponível"; o PDF foi gerado (`%PDF-1.4`). | Execução 4b com um ambiente virtual isolado contendo `pypdf` (MT-01…03 reexecutados juntos, porque o MT-03 usa a análise preparada pelo MT-01): aprovados. |

Os resultados esperados desses casos não mudaram; o §8 do plano registra cada revisão e sua data.

## 5. Inspeção

| ID | Item | Resultado |
|---|---|---|
| TR-01 | CA-08: todo requisito de alta prioridade do [REQUIREMENTS.md](REQUIREMENTS.md) aponta para um item do escopo incluído do Termo (§3.2). | 14 de 14 requisitos de alta prioridade têm um item de origem (1, 2, 3, 4, 5, 6, 7, 9 ou 10). Atendido. |
| TR-02 | Todo requisito de alta prioridade tem pelo menos um caso de teste. | Plano §7: todos os 14 cobertos. Atendido. |
| TR-03 | A bateria inclui casos de entrada inválida. | ST-02, 03, 04, 05, 07, 11, 15, 21 e todos os casos FI. Atendido. |

## 6. Casos de navegador e manuais

MT-01…MT-03 precisam de um motor de navegador real, não de uma pessoa: desde a execução 3 eles são
executados pela suíte `browser` do driver de teste, num Chrome headless conduzido pelo protocolo
DevTools (`tests/e2e/cdp.py`). O MT-04 precisa de uma pessoa de fora da equipe e é o único caso
não executado.

| ID | Resultado (execução 3) | Veredito |
|---|---|---|
| MT-01 | Após um clique duplo real, o botão ficou desabilitado com o texto "Analisando…", `aria-busy=true`, a mensagem de progresso visível; a página de resultado abriu e **exatamente uma** análise foi criada. | APROVADO |
| MT-02 | Resultado com 12 achados (1 high, 5 medium, 6 low): cada chip deixou visíveis apenas os achados da sua severidade, na quantidade correta; *Todos* mostrou os 12 de novo. | APROVADO |
| MT-03 | Relatório impresso em PDF (`2026-10-28_run3/MT-03-report.pdf`): nome da aplicação, pontuação, métricas e todos os títulos de achados presentes; navegação e botões ausentes. | APROVADO |
| MT-04 | Pessoa de fora instala usando apenas o manual e executa uma análise; registrar cada pergunta. | **Pendente — a ser executado pela equipe** |

## 7. Como reproduzir

```bash
php tests/php_test.php
python -m unittest discover -s tests -v
python tests/e2e/run_system_tests.py --run-name <name>   # Apache + MariaDB em execução, ALLOW_PRIVATE_TARGETS=true; Chrome ou Edge para MT-01…03
```

## 8. Reverificação de 2026-11-24 (tradução da documentação)

Ao traduzir a documentação para o português, o código foi reverificado nesta máquina. Fatos
observados:

| Item | Resultado |
|---|---|
| AT-01 `python -m unittest discover -s tests` | 113 testes, OK, em 264 s; novamente 113 OK (269 s) depois das alterações de código do item (e) abaixo. |
| AT-02 `php tests/php_test.php` | 153 verificações, 0 falhas, antes e depois das alterações de código. |
| `php -l` | Sem erros nos 50 arquivos PHP versionados. |
| `python -m compileall` | Sem erros nos 67 arquivos Python. |
| Benchmarks | `evaluation/benchmark_structures.py` e `evaluation/benchmark_comparison.php` reexecutados, com as mesmas conclusões do [ALGORITHM_MEASUREMENTS.md](ALGORITHM_MEASUREMENTS.md). |
| Varredura via CLI do alvo de laboratório (`lab_target.py --variant vulnerable`) | Modo passivo: 34 verificações, 5 páginas, 12 achados, nenhum `xss.*`. Modo completo: 64 verificações, 137 requisições, 14 achados, incluindo `xss.reflected_html_text` em `/search` (q) e `/profile` (name). |
| FI-01 | Reproduzido com o servidor embutido do PHP sem `.env`: HTTP 503 com a mensagem de configuração. |

**Não reexecutado:** as suítes de sistema, injeção de falhas e navegador (ST/FI/MT) — Apache e
MariaDB não estavam em execução e não há `.env` nesta máquina. A execução 3 continua sendo a
referência.

**Observações sobre o produto encontradas nesta revisão** (não registradas como defeitos D-xx;
pendentes de decisão da equipe):

- (a) O `HttpVerbTamperingPlugin` envia PUT, DELETE, PATCH e TRACE uma vez **por página
  visitada** (5 de cada na varredura de 5 páginas do laboratório; até 20 numa varredura em modo
  completo), enquanto sua docstring prometia uma vez por varredura. Num alvo vulnerável, isso pode
  alterar estado.
- (b) O motor valida certificados TLS e o Python 3.12 exige TLS ≥ 1.2; por isso
  `tls.certificate_expiry` só dispara para certificados ainda válidos que expiram em menos de 30
  dias, `tls.legacy_protocol` não tem como disparar, e um alvo HTTPS com certificado inválido ou
  expirado falha com "Nenhuma página pôde ser acessada no alvo."
- (c) O falso positivo de NoSQL em páginas 404 estáveis, descrito no
  [EVALUATION_RESULTS.md](EVALUATION_RESULTS.md), continua presente (`_looks_rejected` trata 404
  como rejeição).
- (d) As sondas de formulário são enviadas por POST à URL da página, não ao `action` do
  formulário (limitação conhecida, ainda presente).
- (e) As mensagens de erro do motor (escopo, orçamento, cancelamento) estavam em inglês e foram
  traduzidas em 2026-11-24 — alteração de código em `scanner/engine/safety.py` e
  `scanner/engine/runner.py`.

## 9. Execução 4 — rastreamento inteligente (2026-11-25)

Motivo: o defeito D-11 (telas `?p=` agrupadas numa só página) e a falta de informação sobre a
cobertura da análise. Mudanças: `scanner/engine/crawler.py` (assinatura com valores, formato de
página, estrutura e reconhecimento de modelo, `CrawlFrontier`, URLs em JavaScript, filtro de
caminhos destrutivos), `scanner/engine/runner.py`, `scanner/engine/models.py`, contrato 1.3,
`App\Domain\Model\CrawlCoverage`, gravação em `analyses.pages_scanned`/`crawl_coverage`,
seção *Cobertura da análise* no resultado e `coverage` na exportação. O ST-27 foi acrescentado ao
plano **antes** da execução (plano §8).

| Item | Resultado |
|---|---|
| AT-01 `python -m unittest discover -s tests` | Execução 4: 124 testes, OK (289 s). Durante a execução do sistema, a revisão do código encontrou que variações descartadas por falta de orçamento eram contadas como "variações de modelo" e não apareciam como não analisadas; corrigido (`CrawlFrontier.out_of_budget`) com um teste novo — o caminho não é exercitado pelo laboratório da suíte de sistema. Execução 4b: 125 testes, OK (290 s). |
| AT-02 `php tests/php_test.php` | 168 verificações, 0 falhas (153 anteriores + 15 de cobertura). |
| Sistema (ST-01…ST-27) | 27 / 27 aprovados. No laboratório, cada página continua recebendo exatamente 2 GET (ST-06), as mesmas 5 páginas são visitadas e a amostra do contrato mantém 137 requisições e 14 achados no modo completo: o rastreamento novo não alterou o resultado de referência. |
| Injeção de falhas (FI-01…FI-10) | Execução 4: 9 / 10 (FI-02, TW-05). Execução 4b: FI-02 aprovado. |
| Navegador (MT-01…MT-03) | Execução 4: 2 / 3 (MT-03, TW-06). Execução 4b: 3 / 3. |
| Verificação manual pela interface | Laboratório `PortalLike` cadastrado e analisado pelo Apache: a seção *Cobertura da análise* mostra "6 páginas analisadas; 1 arquivo JavaScript lido em busca de endpoints" e lista as 5 telas `?p=` e o endpoint AJAX. |

Medição antes/depois (motor anterior extraído do `master` e motor atual, mesmos sites de
laboratório de `tests/test_crawler.py`, limites padrão):

| Site | Versão | Páginas | Requisições | XSS encontrados |
|---|---|---:|---:|---:|
| `PortalLike`, modo completo | anterior | 1 | 48 | 0 de 2 |
| | atual | 6 | 188 | 2 de 2 |
| `PortalLike`, passivo | anterior | 1 | 2 | — |
| | atual | 6 | 13 | — |
| `Catalog` (40 produtos), passivo | anterior | 2 | 4 | — |
| | atual | 2 | 7 | — |

Os registros criados no banco pela suíte e pela verificação manual foram apagados depois da
execução (com backup local), para devolver a instalação ao estado vazio usado na apresentação.
