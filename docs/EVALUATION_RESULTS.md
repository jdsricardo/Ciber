# Resultados de varredura — alvos públicos de teste autorizados

_Gerado em 2026-09-09 pelo SentinelScope. Alvos deliberadamente vulneráveis e de uso público para teste de ferramentas de segurança (Altoro Mutual / IBM e Micro Focus). Nenhum dado foi persistido em banco._

> **Observação metodológica.** Estes números são de alvos reais e não controlados, sem *ground-truth* completo. Servem para demonstrar a cobertura do rastreamento e do modo ativo, não como medida de *precision/recall* — que exige os alvos controlados da Seção 5.3.


## Altoro Mutual — varredura ativa (não autenticada)

- **URL-semente:** `http://demo.testfire.net/`
- **Páginas rastreadas:** 14  ·  **Requisições:** 909  ·  **Verificações declaradas:** 64  ·  **Interrompido:** não
- **Achados:** 38 — 11 critical, 16 high, 4 medium, 7 low
- Destaque: XSS refletido descoberto **em uma página que não era a semente** (`content` em index.jsp, via link) e **em um campo de formulário via POST** (`query` em search.jsp). Travessia de diretório suspeita no mesmo parâmetro `content`. Os dois achados NoSQL são candidatos a **falso positivo** (a aplicação é Java/SQL) e devem ser verificados manualmente.

**Páginas descobertas pelo rastreador:**

- `http://demo.testfire.net/`
- `http://demo.testfire.net/index.jsp`
- `http://demo.testfire.net/login.jsp`
- `http://demo.testfire.net/index.jsp?content=inside_contact.htm`
- `http://demo.testfire.net/feedback.jsp`
- `http://demo.testfire.net/cgi.exe`
- `http://demo.testfire.net/subscribe.jsp`
- `http://demo.testfire.net/default.jsp?content=security.htm`
- `http://demo.testfire.net/survey_questions.jsp`
- `http://demo.testfire.net/status_check.jsp`
- `http://demo.testfire.net/swagger/index.html`
- `http://demo.testfire.net/search.jsp`
- `http://demo.testfire.net/disclaimer.htm?url=http://www.netscape.com`
- `http://demo.testfire.net/survey_questions.jsp?step=a`

**Achados por identificador (após consolidação entre páginas):**

| Qtd | Identificador | Família | Severidade máx. |
|---:|---|---|---|
| 12 | `http_verb_tampering.method_bypass_suspected` | http_verb_tampering | high |
| 9 | `http_verb_tampering.destructive_method_accepted` | http_verb_tampering | critical |
| 2 | `xss.reflected_html_text` | xss | high |
| 1 | `transport.https` | transport | critical |
| 1 | `headers.csp_missing` | headers | high |
| 1 | `headers.frame_options_missing` | headers | high |
| 1 | `headers.nosniff_missing` | headers | low |
| 1 | `headers.referrer_policy_missing` | headers | low |
| 1 | `headers.permissions_policy_missing` | headers | low |
| 1 | `headers.coop_missing` | headers | low |
| 1 | `headers.corp_missing` | headers | low |
| 1 | `cookies.missing_samesite` | cookies | medium |
| 1 | `cache.sensitive_no_store_missing` | cache | medium |
| 1 | `disclosure.server_header` | disclosure | low |
| 1 | `disclosure.password_over_http` | disclosure | critical |
| 1 | `path_traversal.suspicious_behavior` | path_traversal | medium |
| 1 | `nosql_injection.operator_bypass_confirmed` | nosql_injection | high |
| 1 | `nosql_injection.array_type_confusion_suspected` | nosql_injection | medium |

## zero.webappsecurity.com — varredura ativa (não autenticada)

- **URL-semente:** `http://zero.webappsecurity.com/`
- **Páginas rastreadas:** 3  ·  **Requisições:** 103  ·  **Verificações declaradas:** 64  ·  **Interrompido:** não
- **Achados:** 13 — 2 critical, 3 high, 1 medium, 7 low
- Apenas 3 páginas rastreadas: o site é majoritariamente uma SPA cujos *links* são construídos por JavaScript, que o rastreador (sem execução de JS) não segue — limitação registrada na Seção 7.

**Páginas descobertas pelo rastreador:**

- `http://zero.webappsecurity.com/`
- `http://zero.webappsecurity.com/index.html`
- `http://zero.webappsecurity.com/search.html`

**Achados por identificador (após consolidação entre páginas):**

| Qtd | Identificador | Família | Severidade máx. |
|---:|---|---|---|
| 2 | `http_verb_tampering.destructive_method_accepted` | http_verb_tampering | critical |
| 1 | `transport.https` | transport | high |
| 1 | `headers.csp_missing` | headers | high |
| 1 | `headers.frame_options_missing` | headers | high |
| 1 | `headers.nosniff_missing` | headers | low |
| 1 | `headers.referrer_policy_missing` | headers | low |
| 1 | `headers.permissions_policy_missing` | headers | low |
| 1 | `headers.coop_missing` | headers | low |
| 1 | `headers.corp_missing` | headers | low |
| 1 | `cors.wildcard_origin` | cors | medium |
| 1 | `disclosure.server_header` | disclosure | low |
| 1 | `http_verb_tampering.method_bypass_suspected` | http_verb_tampering | low |

## Altoro Mutual — varredura autenticada (passiva, com cookie de sessão)

- **URL-semente:** `http://demo.testfire.net/bank/main.jsp`
- **Páginas rastreadas:** 15  ·  **Requisições:** 30  ·  **Verificações declaradas:** 34  ·  **Interrompido:** não
- **Achados:** 10 — 1 critical, 3 high, 6 low
- Login `jsmith`/`Demo1234`; apenas o `JSESSIONID` foi anexado. O rastreador alcançou a **área bancária autenticada** (`/bank/transfer.jsp`, `/bank/transaction.jsp`, `/bank/queryxpath.jsp`, `/bank/showAccount`, ...), acessível somente após o *login*, e **não seguiu** o *link* de encerramento de sessão. Modo passivo por responsabilidade em host compartilhado.

**Páginas descobertas pelo rastreador:**

- `http://demo.testfire.net/bank/main.jsp`
- `http://demo.testfire.net/index.jsp`
- `http://demo.testfire.net/index.jsp?content=inside_contact.htm`
- `http://demo.testfire.net/feedback.jsp`
- `http://demo.testfire.net/bank/transaction.jsp`
- `http://demo.testfire.net/bank/transfer.jsp`
- `http://demo.testfire.net/bank/queryxpath.jsp`
- `http://demo.testfire.net/bank/customize.jsp`
- `http://demo.testfire.net/bank/apply.jsp`
- `http://demo.testfire.net/status_check.jsp`
- `http://demo.testfire.net/swagger/index.html`
- `http://demo.testfire.net/search.jsp`
- `http://demo.testfire.net/bank/showAccount`
- `http://demo.testfire.net/cgi.exe`
- `http://demo.testfire.net/subscribe.jsp`

**Achados por identificador (após consolidação entre páginas):**

| Qtd | Identificador | Família | Severidade máx. |
|---:|---|---|---|
| 1 | `transport.https` | transport | high |
| 1 | `headers.csp_missing` | headers | high |
| 1 | `headers.frame_options_missing` | headers | high |
| 1 | `headers.nosniff_missing` | headers | low |
| 1 | `headers.referrer_policy_missing` | headers | low |
| 1 | `headers.permissions_policy_missing` | headers | low |
| 1 | `headers.coop_missing` | headers | low |
| 1 | `headers.corp_missing` | headers | low |
| 1 | `disclosure.server_header` | disclosure | low |
| 1 | `disclosure.password_over_http` | disclosure | critical |
---

## Métricas formais (precision/recall/F1) — Altoro Mutual

Avaliação rigorosa de alvo único, com **ground-truth por verificação manual** (reprodução de cada requisição) e apuração automatizada pelo arcabouço `evaluation/evaluate.py`. Ground-truth em [`evaluation/ground_truth.altoro.json`](../evaluation/ground_truth.altoro.json); relatório do harness em [`evaluation/report.altoro.md`](../evaluation/report.altoro.md). Reproduzir com:

```
python evaluation/evaluate.py evaluation/ground_truth.altoro.json --out evaluation/report.altoro.md
```

| Classe (CWE) | Presente | VP | FP | FN | Precisão | Recall | F1 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| XSS refletido (CWE-79) | sim | 1 | 0 | 0 | 1,00 | 1,00 | 1,00 |
| Travessia de diretório (CWE-22) | sim | 1 | 0 | 0 | 1,00 | 1,00 | 1,00 |
| Injeção de SQL (CWE-89) | sim | 0 | 0 | 1 | — | 0,00 | 0,00 |
| Injeção NoSQL (CWE-943) | não | 0 | 1 | 0 | 0,00 | — | 0,00 |
| **Total** | — | **2** | **1** | **1** | **0,67** | **0,67** | **0,67** |

**Verificação manual das duas falhas:**

- **FN — SQLi no login:** `uid=' OR '1'='1` → HTTP 500 (a injeção alcança o banco), mas o form tem `action="doLogin"` (caminho ≠ página) e o *probe* de formulário é enviado à própria URL da página → nunca atinge o handler vulnerável. Limitação conhecida (Seção 4.3 do artigo).
- **FP — NoSQL em `default.jsp`:** a página devolve HTTP 404 estável e idêntico para `[$ne]`, `[$eq]` e baseline; o detector leu a estabilidade do 404 como "contorno de operador". Correção: exigir que a resposta de controle seja distinta de uma página de erro genérica antes de confirmar.

> Escopo restrito às famílias com ground-truth verificável na superfície não autenticada. A avaliação comparativa completa (DVWA/Juice Shop/WebGoat + baseline ZAP) permanece como trabalho de continuidade — bloqueada nesta máquina por ausência de Docker, Node, Java 11+ e ZAP.
