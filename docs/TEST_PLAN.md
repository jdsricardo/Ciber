# Plano de Testes

| | |
|---|---|
| Produto | SentinelScope 1.0 |
| Versão do plano | 2.1 (a 2.0 de 2026-10-14 mais as revisões datadas do §8; substitui o plano 1.x, cujos casos TC-01…TC-18 permanecem como testes automatizados no §5) |
| Redigido em | 2026-10-14, **antes** da execução de qualquer caso abaixo — o resultado esperado de cada caso é fixado aqui primeiro (passo 29 do roteiro, "regra de ouro"). Os resultados de execução vão para o [TEST_REPORT.md](TEST_REPORT.md), nunca para este arquivo. |
| Base | Critérios de aceite CA-01…CA-08 do Termo de Referência (§5), requisitos em [REQUIREMENTS.md](REQUIREMENTS.md), regras de integração em [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md). |

## 1. Escopo e abordagem

| Nível | O que verifica | Como | Onde |
|---|---|---|---|
| Unidade / componente | Invariantes do domínio, casos de uso, apresentação, pontuação, comparação, cada plugin do scanner contra fixtures vulneráveis e seguras | Automatizado, sem banco de dados, sem rede além de 127.0.0.1 | `tests/php_test.php`, `tests/test_*.py` |
| Contrato | Os dois lados da fronteira PHP ⇄ Python obedecem ao [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md) | Automatizado; os dois lados leem o mesmo payload capturado | `tests/test_integration_contract.py`, grupo *Integration contract* de `tests/php_test.php` |
| Sistema (ponta a ponta) | O fluxo completo, da requisição do navegador ao banco de dados e de volta, passando por Apache + PHP + MariaDB + o motor Python, contra um alvo de laboratório controlável | Driver de teste HTTP automatizado, caixa-preta pela interface web; banco de dados lido apenas para confirmar o que a interface mostra | `tests/e2e/run_system_tests.py`, `tests/e2e/lab_target.py` |
| Injeção de falhas | Comportamento diante de cada falha previsível (passo 28 do roteiro) | Mesmo driver de teste, com o ambiente deliberadamente quebrado e depois restaurado | `tests/e2e/run_system_tests.py --suite failure` |
| Manual | O que precisa de uma pessoa, de um navegador real ou de alguém de fora | Protocolo no §6, executado e assinado por um testador | [TEST_REPORT.md](TEST_REPORT.md) §6 |

Todo requisito de alta prioridade tem pelo menos um caso, e toda área funcional tem casos com
**entrada inválida**, não apenas o caminho de sucesso (roteiro §9, checklist antes da E4).

## 2. Ambiente de teste

| Item | Valor |
|---|---|
| Máquina | Windows 11 Pro 10.0.26200, estação de trabalho de um único desenvolvedor |
| Servidor web | XAMPP Apache 2.4 com mod_php, PHP 8.2.12 (`max_execution_time=120`) |
| Banco de dados | MariaDB 10.4.32 (XAMPP), esquema de `database.sql`, usuário da aplicação `sentinelscope_app` apenas com `SELECT, INSERT, UPDATE, DELETE` |
| Motor | Python 3.12, somente biblioteca padrão |
| URL da aplicação | `http://localhost/www/Ciber/public/` |
| Alvo de laboratório | `tests/e2e/lab_target.py` em `http://127.0.0.1:8765/`; o `.env` tem `ALLOW_PRIVATE_TARGETS=true` porque o alvo está em loopback |
| Dados de teste | Criados pelos próprios casos; todo nome de aplicação carrega a tag da execução, para que execuções nunca colidam. O CA-05 semeia 1.000 achados com um script (ST-22). |

### 2.1 Alvo de laboratório

O alvo é uma aplicação deliberadamente vulnerável cujo estado é escolhido na inicialização, de
modo que um caso possa analisá-la, "implantar uma correção" reiniciando-a com outra variante e
analisá-la de novo. Ele registra toda requisição recebida, o que permite a um caso provar o que o
scanner **não** fez.

| Variante | `/search?q=` | `/profile?name=` | Cabeçalhos de segurança | Extra |
|---|---|---|---|---|
| `vulnerable` | reflete sem escape (XSS) | reflete sem escape (XSS) | nenhum | cookie sem flags; links para `/logout` e `/item?id=7&action=delete` |
| `partial` | **com escape** | reflete sem escape | nenhum | — |
| `fixed` | com escape | com escape | CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy | — |
| `edge` | como `vulnerable` | como `vulnerable` | nenhum | formulário `/feedback` com um campo de nome com 300 caracteres |

`/account` e `/account/notes?n=` só respondem ao cookie `lab_session=<secret>`; caso contrário,
redirecionam para `/`.

## 3. Critérios de entrada e de saída

- **Entrada:** as duas suítes automatizadas passam; Apache e MariaDB em execução; esquema importado.
- **Saída:** todos os casos executados; todo defeito *bloqueante* e *alto* corrigido **e verificado
  pela reexecução do caso que o revelou** (passo 31 do roteiro); todo defeito aberto de severidade
  menor registrado com sua justificativa.

### 3.1 Severidade de defeitos

| Severidade | Significado |
|---|---|
| Bloqueante | Impede um fluxo principal ou corrompe/perde dados; sem contorno. |
| Alta | Um requisito ou critério de aceite não é atendido, ou uma regra de segurança é violada. |
| Média | Informação errada ou enganosa para o usuário; existe contorno. |
| Baixa | Divergência cosmética ou de documentação. |

## 4. Casos de teste

Notação: **Pré** = pré-condição, **Passos** = o que o driver de teste faz, **Esperado** = o
resultado que faz o caso passar. *(inv)* marca um caso construído sobre entrada inválida ou
ambiente quebrado.

### 4.1 Testes de sistema — registro e validação de entrada

| ID | Cobre | Pré | Passos | Esperado |
|---|---|---|---|---|
| ST-01 | FR-01, CA-01 | Painel acessível | POST `create` com um nome, `http://127.0.0.1:8765/` e a caixa de autorização marcada | HTTP 302 para `index.php`; o painel mostra o aviso "Aplicação registrada." e um card com o nome e a URL; a linha de `applications` tem `authorization_confirmed_at` não nulo. |
| ST-02 *(inv)* | FR-01 | — | POST `create` sem a caixa de autorização | HTTP 400; a página mostra "Confirme que você possui autorização para analisar este alvo."; nenhuma linha criada. |
| ST-03 *(inv)* | FR-01 | — | POST `create` com cada URL: vazia, `ftp://example.com/`, `javascript:alert(1)`, `http://user:pw@example.com/`, `nota-uma-url` | HTTP 400 para cada uma, com a mensagem correspondente (`Informe a URL da aplicação.`, `A URL deve usar o esquema HTTP ou HTTPS.` ou `Informe uma URL válida.`, `A URL não pode conter credenciais embutidas.`); nenhuma linha criada. |
| ST-04 *(inv)* | FR-01 | — | POST `create` com nome vazio, só com espaços e com 121 caracteres | HTTP 400 para cada um; nenhuma linha criada. |
| ST-05 *(inv)* | NFR-02 | Existe uma aplicação | POST `create` e POST `run` sem o campo `csrf`, e com um valor errado | HTTP 400 com "Seu token de sessão expirou. Atualize a página e tente novamente."; nenhuma aplicação e nenhuma análise criadas. |

### 4.2 Testes de sistema — análise

| ID | Cobre | Pré | Passos | Esperado |
|---|---|---|---|---|
| ST-06 | FR-02, FR-13, NFR-03, CA-01 | Laboratório `vulnerable`; aplicação registrada (ST-01) | POST `run` em modo passivo | 302 para `page=result&id=N`; análise `completed`; *Verificações executadas* = **34**; o log do laboratório mostra `/`, `/search`, `/profile`, `/about` requisitados, **cada página com exatamente 2 GET** (duas baselines), **zero requisições a `/logout` e `/item`**; os achados incluem `headers.csp_missing`; **nenhum achado `xss.*`** (o modo passivo não envia sondas). |
| ST-07 *(inv)* | FR-02 | Aplicação registrada | POST `run` em modo ativo, mas sem a autorização ativa | HTTP 400 "Autorize o envio de payloads de teste ativos para usar a análise completa."; o número de análises da aplicação não muda. |
| ST-08 | FR-02, FR-10, CA-01 | Laboratório `vulnerable` | POST `run` em modo ativo e com autorização ativa | Análise `completed`; *Verificações executadas* = **64**; os achados incluem `xss.reflected_html_text` com o parâmetro `q` em `/search` **e** com o parâmetro `name` em `/profile`; continuam zero requisições a `/logout` e `/item`. |
| ST-09 | FR-03, FR-05, FR-09, CA-02 | ST-08 concluído | Ler a exportação JSON e a página de resultado do ST-08 | **Todo** achado tem severidade não vazia, confiança em 0–100, status, categoria, CWE, OWASP, WSTG, evidência com um `reason`, impacto para o desenvolvedor e remediação; a página de resultado mostra o título e o rótulo de severidade de cada achado. |
| ST-10 | FR-04, CA-03 | ST-06 e ST-08 concluídos | Para cada um, calcular `max(0, min(100, 100 − 30·critical − 15·high − 7·medium − 2·low))` a partir dos achados exportados | O valor calculado é igual à pontuação da página de resultado e ao `security_score` da exportação. |
| ST-11 *(inv)* | NFR-02 | — | Registrar uma aplicação chamada `<script>alert("st11")</script>`; abrir o painel; abrir a página de resultado do ST-08 (sua evidência contém a tag HTML que a sonda injetou) | O painel contém `&lt;script&gt;alert(&quot;st11&quot;)&lt;/script&gt;` e **não** a tag crua; a página de resultado não contém a tag crua da sonda `<sszz`. |
| ST-12 | FR-06 | ST-06 e ST-08 concluídos | Abrir o painel | O card da aplicação lista as duas análises, a mais recente primeiro, cada uma com modo, status `completed` e pontuação. |
| ST-19 | FR-11, NFR-07, R3 | Laboratório `vulnerable` com o segredo `st19-<tag>` | POST `run` (passivo) com o cookie de sessão `lab_session=st19-<tag>` | Análise concluída; o log do laboratório mostra `/account/notes` requisitado **com** esse cookie (a área autenticada foi alcançada; sem o cookie, `/account` apenas redireciona); o segredo **não aparece em lugar nenhum** do banco de dados (dump completo de `sentinelscope`), do log de acesso do Apache ou do log de erros do PHP. |
| ST-20 | Contrato R1 | Laboratório `vulnerable` com o segredo `s3cr%3D!x` | (a) POST `run` com o cookie `lab_session=s3cr%3D!x`; (b) registrar `http://127.0.0.1:8765/search?q=a%20b` e executá-la | (a) o cabeçalho Cookie recebido pelo laboratório é exatamente `lab_session=s3cr%3D!x` e `/account/notes` é alcançado; (b) a primeira requisição recebida pelo laboratório é `GET /search?q=a%20b`. |

### 4.3 Testes de sistema — comparação, histórico, exportação, relatório

| ID | Cobre | Pré | Passos | Esperado |
|---|---|---|---|---|
| ST-13 | FR-07, CA-04 | Nova aplicação; análise ativa **A** do laboratório `vulnerable`; depois o laboratório reiniciado como `partial`; análise ativa **B** | Abrir `compare&old=A&new=B` | *Corrigidos* contém o XSS de `/search`; *Ainda presentes* contém o XSS de `/profile`; *Novos problemas* está vazio. |
| ST-14 | FR-07, CA-04 | A do ST-13; laboratório reiniciado como `fixed`; análise ativa **C** | Abrir `compare&old=A&new=C` | *Corrigidos* contém os dois achados de XSS e os quatro achados de cabeçalho que a variante corrigida agora envia (`csp`, `frame_options`, `nosniff`, `referrer_policy`); *Novos problemas* está vazio; a pontuação de C é maior que a de A. |
| ST-15 *(inv)* | FR-07 | Análises de duas aplicações diferentes | Abrir `compare` com uma de cada | HTTP 400 "Escolha duas análises da mesma aplicação." |
| ST-16 | FR-12, CA-06 | ST-08 concluído | GET `export&id=<ST-08>` | HTTP 200, `Content-Type: application/json`, `Content-Disposition: attachment`; o documento tem o nome da aplicação, `started_at`, `security_score`; o número de achados é igual ao do banco de dados **e** ao mostrado na página de resultado; o multiconjunto de fingerprints é igual ao do banco. |
| ST-17 | FR-08 | ST-08 concluído | GET `report&id=<ST-08>` | HTTP 200; contém o nome da aplicação, a pontuação, as quatro métricas da execução, o título de cada achado e sua remediação, o botão de impressão; **não** contém o link *Exportar JSON*. |
| ST-18 | FR-12 | ST-08 concluído | Ler os chips de severidade da página de resultado | Um chip por severidade presente, cada contagem igual ao número de achados exportados daquela severidade; *Todos* é igual ao total. |
| ST-21 *(inv)* | Convenção de erros | — | GET `result&id=999999`, `export&id=999999`, `compare&old=999999&new=999999`; POST `run` com `application_id=999999` | HTTP 404 para cada um, com "Análise não encontrada." ou "Aplicação não encontrada." |
| ST-22 | NFR-01, CA-05 | Uma análise semeada com **1.000** achados (severidades mistas) e uma segunda com 1.000 para comparação | GET da página de resultado, do relatório, da exportação e da comparação, 5 vezes cada, cronometrando a resposta HTTP completa | Cada uma das 20 respostas termina em **< 3.000 ms**; a página de resultado renderiza os 1.000 achados. |
| ST-23 | Passo 23 do roteiro | Aplicação registrada | GET do painel e de `assets/app.js` | O formulário de execução tem `data-busy` e um elemento `role="status"`; o script contém o handler de submit que o exibe e trava o botão. (Comportamento interativo: MT-01.) |
| ST-24 | FR-06, CA-06 | Laboratório `vulnerable`; horário UTC anotado antes e depois de uma execução passiva | Ler a linha do painel e a exportação JSON dessa análise | A data mostrada na coluna *Data (UTC)* do histórico está entre os dois instantes UTC anotados (± 5 s); na exportação `started_at ≤ completed_at` e a diferença é menor que 60 s. *(Adicionado em 2026-10-14 após a execução 1 — ver §8.)* |
| ST-25 | FR-06, Termo 3.2 item 6 | Nova aplicação com três análises concluídas cujo `started_at` é 2026-01-10, 2026-02-15 e 2026-03-20 (definido pelo driver de teste no banco) | GET do painel (a) sem período; (b) `from=2026-02-01&to=2026-02-28`; (c) `from=2026-02-15&to=2026-03-20`; (d) apenas `from=2026-02-01`; *(inv)* (e) `from=2026-03-01&to=2026-02-01`; *(inv)* (f) `from=31/02/2026` | (a) o card lista as 3 análises; (b) apenas a de fevereiro; (c) fevereiro e março — os dois extremos inclusivos; (d) fevereiro e março; (e) HTTP 400 "A data inicial deve ser anterior ou igual à data final."; (f) HTTP 400 "Informe as datas no formato AAAA-MM-DD.". O formulário de filtro mostra o período aplicado. *(Adicionado em 2026-10-28 — ver §8.)* |
| ST-26 | FR-12, Termo 3.2 item 8 | ST-08 concluído | GET `export&id=<ST-08>` e ler `summary` | `summary.findings` = número de achados; `summary.by_severity` tem as quatro severidades e cada contagem é igual aos achados daquela severidade; `summary.security_score` = `analysis.security_score`; `summary.manual_review_required` = número de achados marcados para revisão manual. *(Adicionado em 2026-10-28 — ver §8.)* |

### 4.4 Injeção de falhas (passo 28 do roteiro)

Cada caso quebra uma coisa, registra o comportamento observado e restaura o ambiente. O
comportamento esperado é o que o contrato e a convenção de erros exigem.

| ID | Falha provocada | Comportamento esperado |
|---|---|---|
| FI-01 | `.env` ausente | HTTP 503 com "Configuração necessária: copie .env.example para .env e importe database.sql." |
| FI-02 | MariaDB parado | HTTP 500 com a mensagem genérica "Ocorreu um erro inesperado. Consulte o log do servidor."; a resposta não contém `SQLSTATE`, stack trace, caminho de arquivo nem credencial; o detalhe é gravado no log de erros do PHP, sem a senha do banco. |
| FI-03 | Senha do banco errada no `.env` | Igual ao FI-02; a senha errada não aparece nem na resposta nem no log. |
| FI-04 | Alvo inacessível (laboratório fora do ar) | Análise `failed`; a página de resultado mostra o motivo; nenhum achado; linha do painel `failed`. |
| FI-05 | Alvo em loopback com `ALLOW_PRIVATE_TARGETS=false` | Análise `failed` com o motivo de escopo; **o laboratório recebe zero requisições**. |
| FI-06 | `PYTHON_BINARY` aponta para um programa que não existe | Análise `failed` com "O scanner retornou uma resposta inválida. Verifique a configuração do Python."; nunca deixada em `running`. |
| FI-07 | O motor responde um documento que viola o contrato (`severity: "info"`) | Análise `failed` com "Severidade desconhecida: info."; nenhum achado gravado. |
| FI-08 | O banco recusa a gravação dos achados (`INSERT` em `findings` revogado) | O usuário recebe uma página de erro; a análise fica `failed` com um motivo, **não** deixada em `running`; nenhum achado gravado (contrato C2, C3). |
| FI-09 | A varredura ultrapassa o `max_execution_time` do PHP (laboratório respondendo cada requisição após 2 s, modo ativo ≈ 140 requisições ⇒ ≈ 280 s; 1 s no plano 2.0, ver §8) | A requisição termina com uma página para o usuário e a análise fica `completed` ou `failed` com um motivo — **nunca deixada em `running`** (contrato C2, C5). |
| FI-10 | Um valor maior que sua coluna (laboratório `edge`: um nome de campo com 300 caracteres) com o MariaDB em modo estrito (`STRICT_TRANS_TABLES`, o padrão do MariaDB fora do XAMPP) | A análise fica `completed`; o achado do formulário é gravado com `parameter` de no máximo 180 caracteres (contrato §3.2). |

## 5. Suítes automatizadas (regressão)

| ID | Suíte | Esperado |
|---|---|---|
| AT-01 | `python -m unittest discover -s tests -v` — 106 testes preexistentes (motor, cada plugin contra fixtures vulneráveis/seguras, rastreador, transporte, exemplos de remediação, padrão de codificação, harness de avaliação) mais os 7 testes de contrato do lado produtor | Todos passam. |
| AT-02 | `php tests/php_test.php` — 115 verificações preexistentes (camadas, padrão de codificação, invariantes do domínio, pontuação, apresentação, comparação, casos de uso, exportação, renderização de 1.000 achados) mais as verificações de contrato do lado consumidor | Todas passam. |

Os casos 1.x continuam cobertos por essas suítes: TC-03/04/09/10/11/15/16/17 pelo AT-01 e
TC-12/13/14/18 pelo AT-02; TC-01/02/05/06/07/08 foram substituídos por ST-01/02-04/13/17/22/FI-05.

## 6. Testes manuais

Estes precisam de um navegador real. MT-01, MT-02 e MT-03 são executados pela suíte `browser` do
driver de teste (`python tests/e2e/run_system_tests.py --suite browser`), que conduz um Chrome/Edge
headless real pelo protocolo DevTools por meio de `tests/e2e/cdp.py` (clique, clique duplo, leitura
do estado visível, impressão em PDF); seus resultados esperados abaixo não mudaram. O MT-04 precisa
de uma pessoa de fora da equipe e não pode ser automatizado.

| ID | Cobre | Passos | Esperado |
|---|---|---|---|
| MT-01 | Passo 23 | Em um navegador, iniciar uma análise e dar clique duplo em *Executar análise* | O botão passa a "Analisando…" e fica desabilitado, a mensagem de progresso aparece e apenas **uma** análise é criada. |
| MT-02 | FR-12 | Em uma página de resultado com várias severidades, clicar em cada chip | Só os achados daquela severidade permanecem visíveis; *Todos* mostra todos de novo. |
| MT-03 | FR-08 | Abrir o relatório para impressão e usar *Imprimir / Salvar como PDF* | O PDF contém o cabeçalho, as métricas e todos os achados; navegação e botões não são impressos. |
| MT-04 | CA-07, NFR-05 | Uma pessoa que não participou do desenvolvimento instala o sistema em uma máquina sem o projeto, usando apenas o [INSTALLATION_AND_USER_MANUAL.md](INSTALLATION_AND_USER_MANUAL.md), e executa uma análise | Instalação e primeira análise bem-sucedidas; toda pergunta que a pessoa fizer é registrada como lacuna do manual e corrigida. |

## 7. Rastreabilidade — critérios de aceite para casos

| Critério | Casos |
|---|---|
| CA-01 — o catálogo é executado e a conclusão é registrada | ST-01, ST-06, ST-08, AT-01 |
| CA-02 — todo achado tem severidade, confiança, status, taxonomia, evidência, remediação | ST-09, ST-11, ST-19, AT-01, AT-02 |
| CA-03 — pontuação 0–100 pela regra 30/15/7/2 | ST-10, AT-02 |
| CA-04 — a comparação mostra novos, persistentes e corrigidos | ST-13, ST-14, ST-15, AT-02 |
| CA-05 — 1.000 achados em menos de 3 s | ST-22, AT-02 |
| CA-06 — exportação JSON completa e igual ao que está gravado e é exibido | ST-16, ST-24, ST-26 |
| CA-07 — instalação por alguém de fora usando apenas o manual | MT-04 |
| CA-08 — todo requisito de alta prioridade rastreado até o Termo | Inspeção do [REQUIREMENTS.md](REQUIREMENTS.md) (TR-01 no relatório) |

| Requisito de alta prioridade | Casos |
|---|---|
| FR-01 | ST-01, ST-02, ST-03, ST-04 |
| FR-02 | ST-06, ST-07, ST-08 |
| FR-03 | ST-09 |
| FR-05 | ST-09 |
| FR-06 | ST-12, ST-25 |
| FR-07 | ST-13, ST-14, ST-15 |
| FR-09 | ST-09 |
| FR-10 | ST-08, AT-01 |
| FR-13 | ST-06 |
| NFR-01 | ST-22 |
| NFR-02 | ST-05, ST-11 |
| NFR-03 | ST-06 |
| NFR-04 | FI-05, AT-01 |
| NFR-07 | ST-19 |

## 8. Revisões do plano

| Data | Alteração | Motivo |
|---|---|---|
| 2026-10-14 | Plano 2.0 redigido antes de qualquer execução (a execução 1 começou às 23:00 UTC). | Regra de ouro do passo 29. |
| 2026-10-14 | ST-24 adicionado, **antes** da correção do defeito que ele cobre. | Durante a execução 1, o banco mostrou análises com 10.800 s de duração: `started_at` é gravado no horário local do servidor e `completed_at` em UTC. Nenhum caso planejado olhava timestamps, então o defeito foi registrado (D-07) e um caso com seu resultado esperado foi escrito antes da correção. |
| 2026-10-14 | Atraso do FI-09 elevado de 1 s para 2 s. | Na execução 1, a varredura terminou em 115,8 s, abaixo do limite de 120 s; portanto a falha **não foi provocada** e o veredito da execução 1 é nulo (registrado como *inconclusivo*, não como aprovação). O comportamento esperado não mudou. |
| 2026-10-14 | Driver de teste: a verificação "nenhum detalhe técnico" deixou de tratar `.php` como vazamento; o log do PHP passou a ser lido do `error.log` do Apache. | Falsos positivos da execução 1: toda página tem link para `index.php`, e, sem `C:\xampp\php\logs\`, o PHP grava no log de erros do Apache. Os dois foram conferidos manualmente (evidência da execução 1) antes da mudança no driver; os resultados esperados não mudaram. |
| 2026-10-28 | ST-25 e ST-26 adicionados, **antes** de o código que eles verificam ser escrito. | Uma conferência cruzada do Termo de Referência com o produto encontrou dois itens do escopo incluído não totalmente realizados: o item 6 pede consultar o histórico *por período* (não havia filtro de período), e o item 8 pede que a exportação JSON contenha um *resumo* (ela trazia apenas o número de achados). |
| 2026-10-28 | MT-01, MT-02 e MT-03 automatizados com um navegador headless (suíte `browser` de `tests/e2e/run_system_tests.py`, com `tests/e2e/cdp.py`). | Eles precisam de um motor de navegador real, não de uma pessoa; automatizá-los os torna repetíveis. Resultados esperados inalterados. O MT-04 continua manual. |
| 2026-10-28 | Driver de teste do MT-01: o estado do botão passa a ser registrado dentro da página (MutationObserver → `sessionStorage`) em vez de lido pelo DevTools após o clique. | Primeira execução automatizada (execução 3a): depois que o formulário é enviado, o navegador só responde ao DevTools quando a página seguinte termina de carregar, então o driver leu a página de resultado em vez do botão. Conferido manualmente com o envio bloqueado: o botão de fato passa a "Analisando…" e fica desabilitado. Resultado esperado inalterado. |
| 2026-11-24 | Documento traduzido para o português; as referências a `tests/e2e/browser_tests.py` (arquivo inexistente) foram corrigidas para a suíte `browser` de `tests/e2e/run_system_tests.py`. | Revisão da documentação contra o código. Nenhum caso nem resultado esperado mudou. |
