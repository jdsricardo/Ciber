# Contrato de Integração — Aplicação Web ⇄ Motor do Scanner

| | |
|---|---|
| Versão do contrato | **1.2** |
| Situação | Normativo. Uma mudança em qualquer regra abaixo exige uma nova versão e uma entrada no histórico de alterações no fim deste documento. |
| Produtor | Motor do scanner — `scanner/scanner.py` (Python 3.10+, somente biblioteca padrão) |
| Consumidor | `App\Infrastructure\Scanner\PythonScannerGateway` → `App\Domain\Model\ScanResult` (PHP 8.2+) |
| Testes de conformidade | `tests/test_integration_contract.py` (lado do produtor) e o grupo *Integration contract* em `tests/php_test.php` (lado do consumidor). Ambos leem o mesmo payload capturado, `tests/fixtures/scan_result.sample.json`. |

Este documento é o acordo único entre as duas metades do SentinelScope. A aplicação PHP nunca
importa código Python e o motor nunca lê o banco de dados; tudo o que cruza a fronteira está
descrito aqui: como o motor é iniciado, o que recebe, o que imprime e o que o consumidor deve
fazer com cada resposta possível.

---

## 1. Transporte

| Aspecto | Regra |
|---|---|
| Mecanismo | Um processo filho por análise. O consumidor o inicia, espera que termine e lê sua saída padrão. Não há socket, fila nem arquivo compartilhado. |
| Direção | Requisição: argumentos de linha de comando. Resposta: **um documento JSON** na saída padrão. |
| Codificação | A saída padrão é UTF-8, independentemente da plataforma ou da página de código do console. O motor garante isso com `stream.reconfigure(encoding="utf-8")`. |
| Delimitação | Toda a saída padrão é o documento. O consumidor remove espaços em branco nas extremidades e o decodifica com `json_decode`. Não há delimitador nem prefixo de tamanho: **qualquer outra coisa impressa na saída padrão — um aviso, uma linha de depuração, um traceback — é uma violação do contrato**. |
| Saída de erro | Não faz parte da resposta. O consumidor não deve misturá-la ao documento que decodifica. |
| Código de saída | `0` quando o documento tem `"ok": true`; `1` quando tem `"ok": false`. Qualquer outro código, ou nenhum documento, significa que o motor não chegou ao fim. |

## 2. Requisição

### 2.1 Linha de comando

```
<PYTHON_BINARY> <ROOT>/scanner/scanner.py <target-url> --mode=<mode> [--allow-private] [--cookie=<value>]
```

| Argumento | Tipo | Obrigatório | Regra |
|---|---|---|---|
| `<target-url>` | string | sim | A URL base da aplicação, já validada por `Domain\Model\TargetUrl` (HTTP/HTTPS, ≤ 2.048 caracteres, sem credenciais embutidas). |
| `--mode` | `passive` \| `safe_active` | sim | `safe_active` só é enviado quando o usuário pediu a análise completa **e** confirmou a autorização ativa separada (`RunAnalysis`). |
| `--allow-private` | flag | não | Enviado somente quando `ALLOW_PRIVATE_TARGETS=true` no `.env`. Sem ela o motor recusa destinos privados, de loopback, link-local e reservados. |
| `--cookie` | string | não | Credencial de sessão para áreas autenticadas (FR-11). Enviada somente quando o usuário informou uma para esta análise. |

Outras opções que o motor aceita (`--header`, `--max-pages`, `--max-depth`, `--log-file`,
`--cancel-file`) servem ao uso pela linha de comando e à avaliação, e não são enviadas pela
aplicação web.

### 2.2 Regras sobre a requisição

- **R1 — Os argumentos chegam intactos.** A URL do alvo e o cookie de sessão devem chegar ao
  motor byte a byte como o usuário os digitou. Caracteres como `%`, `!`, `"`, `&` e espaços são
  legítimos em ambos (URLs codificadas com porcentagem; valores de cookie) e não podem ser
  alterados, descartados nem interpretados por um shell.
- **R2 — Sem injeção de shell.** Nenhum valor fornecido pelo usuário pode estender a linha de
  comando.
- **R3 — A credencial é transitória.** O cookie de sessão existe apenas nos argumentos do
  processo filho, durante aquela análise. Ele nunca é gravado no banco de dados, em arquivo ou em
  log (NFR-07). O motor mascara os cabeçalhos `Cookie`, `Authorization` e de chave de API em seu
  próprio log de requisições (`SENSITIVE_HEADERS` em `scanner/engine/safety.py`).

## 3. Resposta

### 3.1 Documento de sucesso (`"ok": true`)

| Campo | Tipo | Significado |
|---|---|---|
| `ok` | `true` | A varredura foi executada e os achados abaixo são seu resultado completo. |
| `status_code` | int | Status HTTP da primeira resposta de baseline da página-semente. |
| `duration_ms` | int ≥ 0 | **Duração real (relógio de parede) de toda a varredura**, da primeira à última requisição, em milissegundos. Exibida ao usuário como a duração da análise. |
| `plugins_run` | int | Número de famílias de plugins executadas (7 no modo passivo; 20 em `safe_active`). |
| `checks_run` | int | Número de identificadores de verificação declarados por esses plugins (34 no modo passivo; 64 em `safe_active`). |
| `baseline_stability` | float 0–1 | Similaridade entre as duas respostas de baseline da página-semente. |
| `requests_made` | int | Requisições enviadas, somando rastreamento e sondagem. |
| `pages_scanned` | int | Páginas distintas visitadas pelo rastreador. |
| `crawled_urls` | lista de string | Essas páginas, na ordem de visita. |
| `findings` | lista de *Finding* | Todos os achados, já deduplicados entre páginas. Pode estar vazia. |
| `scanned_at` | string | Data e hora ISO-8601 em UTC. |
| `stopped_early` | string, opcional | `budget_exceeded`, `cancelled` ou `scope_violation` quando a varredura terminou antes de esgotar o rastreamento. Os achados reunidos até ali continuam válidos. |
| `plugin_warnings` | lista de string, opcional | Plugins que não puderam ser carregados. |

Atualmente o consumidor lê `ok`, `findings`, `checks_run`, `duration_ms` e `status_code`; os
demais campos são informativos e podem ser ignorados.

### 3.2 Achado (*Finding*)

Todo elemento de `findings` tem os campos abaixo. A coluna **limite** é a largura da coluna que
armazena o campo (`database.sql`); o produtor não pode excedê-la, porque um valor que não cabe é
rejeitado (modo SQL estrito) ou truncado silenciosamente (modo permissivo), e nenhuma das duas
coisas é aceitável.

| Campo | Tipo | Obrigatório | Limite | Regra |
|---|---|---|---|---|
| `fingerprint` | string | sim | 120 | Identificador da verificação, `<família>.<verificação>` (por exemplo `xss.reflected_html_text`). O prefixo antes do primeiro ponto é a família de vulnerabilidade. |
| `title` | string | sim | 180 | Título curto em português, de `plugins/catalog.py`. |
| `category` | string | sim | 80 | Nome da categoria. |
| `cwe` / `owasp` / `wstg` | string | sim | 120 cada | Identificadores de taxonomia na forma padrão em inglês (NFR-06). |
| `severity` | string | sim | enum | Um de `critical`, `high`, `medium`, `low`. **Nenhum outro valor é válido.** |
| `confidence` | int | sim | 0–100 | Independente da severidade (FR-09). |
| `status` | string | sim | 30 | Um de `confirmed`, `high_confidence`, `probable`, `possible`, `informational`, `manual_review_required`. |
| `affected_url` | string | sim | 2.048 | URL onde o achado foi observado. Para um achado ativo é a URL da sonda e, portanto, inclui o valor da sonda. |
| `endpoint` | string | sim | — | Mesmo valor de `affected_url` (nome interno do motor, não armazenado). |
| `method` | string | sim | 10 | Método HTTP usado para chegar ao achado (`POST` para campos de formulário). |
| `parameter` | string \| null | sim | 180 | Nome da entrada testada, ou `null` para achados de nível de página. |
| `parameter_location` | string \| null | sim | 40 | `query`, `form`, `cookie` (achado sobre um cookie que a página define) ou `null`. |
| `description` | string | sim | text | O que a verificação procura. |
| `evidence_summary` | string | sim | 500 | Uma frase descrevendo o que foi observado. |
| `evidence` | object | sim | 64 KiB serializado | Evidência estruturada: `reason`, `baseline`, `probe_request`, `probe_response`, `differences`, `verification_count`. Segredos já vêm mascarados. |
| `developer_impact` | string | sim | text | Por que isso importa para o desenvolvedor. |
| `remediation` | string | sim | text | Como corrigir. |
| `manual_review_required` | bool | sim | — | O detector pede confirmação humana. |
| `remediation_example_vulnerable` / `_fixed` | string | sim (pode ser vazio) | text | O exemplo "vulnerável vs. corrigido" (FR-05). |
| `remediation_example_language` | string | sim (pode ser vazio) | 60 | Linguagem do exemplo. |
| `remediation_example_note` | string | sim (pode ser vazio) | 500 | Nota curta sobre o exemplo. |

### 3.3 Documento de falha (`"ok": false`)

```json
{"ok": false, "error": "Nenhuma página pôde ser acessada no alvo."}
```

| Campo | Tipo | Regra |
|---|---|---|
| `ok` | `false` | A varredura não produziu um resultado utilizável. |
| `error` | string, não vazia | Motivo legível em português, exibido ao usuário como a razão da falha da análise. |

Causas típicas e a mensagem que cada uma produz:

| Causa | `error` |
|---|---|
| O endereço não responde, ou a conexão (inclusive TLS) falha na página-semente | "Nenhuma página pôde ser acessada no alvo." |
| O nome do alvo não é resolvido (DNS) | "Falha de rede ao acessar o alvo: <detalhe do sistema operacional>" — o detalhe vem do sistema operacional e pode não estar em português. |
| Violação de escopo (por exemplo, destino privado sem `--allow-private`) | por exemplo "Alvos em rede privada, loopback, link-local ou endereços reservados são bloqueados por padrão." |
| Orçamento global de requisições ou de tempo esgotado antes de a página-semente responder | "O limite de requisições ou de tempo foi atingido antes de a primeira página responder." |
| Cancelamento antes de a página-semente responder | "A análise foi cancelada antes de a primeira página responder." |

## 4. Obrigações do consumidor

| Regra | Obrigação |
|---|---|
| **C1 — Registrar antes de chamar.** | A linha da análise existe com status `running` antes de o motor ser iniciado, para que uma execução interrompida deixe rastro. |
| **C2 — Toda análise é encerrada.** | Aconteça o que acontecer depois de C1 — sucesso, `ok:false`, saída ilegível, queda do motor, limite de tempo ou falha ao gravar o resultado — a análise termina como `completed` ou `failed`, com um motivo. **Uma análise nunca pode permanecer `running` depois que a requisição que a iniciou terminou.** |
| **C3 — Tudo ou nada.** | Os achados e o status `completed` são gravados em uma única transação. Uma falha ao gravá-los não deixa achados parciais. |
| **C4 — Validar, não confiar.** | O documento é validado na leitura (`ScanResult::fromEnginePayload`, `Finding::fromRow`, `Severity::fromString`). Um documento inválido — não JSON, severidade desconhecida, fingerprint/título/URL ausentes, confiança fora de 0–100 — faz a análise falhar com um motivo claro; nunca é armazenado parcialmente nem relatado como uma varredura vazia. |
| **C5 — Prazo-limite.** | O consumidor concede ao motor todo o seu orçamento de tempo (180 s no modo passivo, 600 s em safe-active, `global_timeout_seconds` em `scanner/engine/runner.py`) mais uma margem, e ainda deve cumprir C2 se esse prazo-limite for excedido. |
| **C6 — Escapar é tarefa do consumidor.** | Toda string do documento — inclusive a evidência copiada do alvo, que é controlável por um atacante — é escapada na saída (`Presentation\Html::escape`). |

## 5. Identidade de um achado entre análises

Comparar duas análises (FR-07, CA-04) exige saber quando um achado da análise mais antiga é "o
mesmo" que um achado da análise mais nova. A identidade de um achado é a tupla:

```
( fingerprint,  scheme://host:port/path de affected_url (sem a query string),  parameter_location,  parameter )
```

- A **query string é removida** porque, nos achados ativos, `affected_url` contém o marcador
  aleatório da sonda que revelou o problema, diferente a cada execução.
- O **caminho e o parâmetro são mantidos** porque a mesma verificação pode falhar de forma
  independente em dois endpoints ou dois parâmetros, e corrigir um deles deve aparecer como
  *corrigido* enquanto o outro continua *persistente*.
- Achados de nível de site (cabeçalhos, transporte, cookies, cache, CORS) são relatados uma única
  vez pelo motor, na primeira página onde foram observados, que é a página-semente sempre que a
  condição vale ali; sua identidade é, portanto, estável entre execuções da mesma aplicação.

## 6. Política de versionamento

- Acrescentar um campo opcional à resposta é uma mudança **minor** (1.x): consumidores ignoram
  campos que não leem.
- Remover ou renomear um campo, mudar um tipo, acrescentar uma severidade ou mudar o significado
  de um campo é uma mudança **major** (2.0) e exige que o consumidor seja alterado no mesmo
  commit.
- Toda mudança é registrada abaixo, e o payload de exemplo compartilhado é regenerado com
  `python tests/test_integration_contract.py --regenerate-fixture`.

## 7. Histórico de alterações

| Versão | Data | Alteração |
|---|---|---|
| 1.2 | 2026-11-24 | Documento traduzido para o português. `stopped_early` também assume `scope_violation`, que o produtor sempre emitiu (omissão de documentação). Exemplo e causas do §3.3 corrigidos para as mensagens reais. As mensagens de escopo, orçamento e cancelamento do motor, que eram em inglês contrariando o §3.3, passaram a ser em português (`scanner/engine/safety.py`, `scanner/engine/runner.py`). Nenhum campo mudou: alteração *minor*. |
| 1.1 | 2026-10-14 | `parameter_location` também assume `cookie`, que o plugin de cookies sempre emitiu (`cookies.missing_httponly`, `cookies.missing_samesite`, …). A versão 1.0 o omitia; o teste de conformidade do produtor revelou a omissão (defeito D-08). Correção de documentação — nenhum código mudou em nenhum dos lados. |
| 1.0 | 2026-10-14 | Primeira versão escrita do contrato que estava implícito em `ScanResult::fromEnginePayload` e `ScanRunner.run()` desde a Fase 1. Acrescenta as regras explícitas R1–R3, C1–C6, os limites de coluna do §3.2, o significado de `duration_ms` e a regra de identidade do §5. |
