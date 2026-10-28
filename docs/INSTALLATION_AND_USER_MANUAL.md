# Installation and User Manual

SentinelScope 1.0 · for the person installing the system and for the developer using it.
Follow the steps in order; each one ends with a check that tells you it worked.

> **Authorization.** SentinelScope sends HTTP requests to the address you register — in the
> complete mode, requests carrying test payloads. Only analyse applications you own or are
> explicitly authorized in writing to assess.

---

## Part A — Installation

### A.1 Requirements

| Component | Version | Notes |
|---|---|---|
| Operating system | Windows 10/11 (tested on Windows 11 Pro) | Linux works with the same steps and the equivalent paths. |
| XAMPP | 8.2.x | Provides Apache 2.4, PHP 8.2 and MariaDB 10.4. Download from apachefriends.org. |
| PHP extensions | `pdo_mysql`, `mbstring` | Enabled by default in XAMPP. Check with `php -m`. `proc_open` must not be listed in `disable_functions`. |
| Python | 3.10 or newer | Standard library only — no `pip install` is needed. During installation tick **Add python.exe to PATH**. |
| Browser | any current browser | |

**Check:** in a new terminal, `python --version` prints 3.10 or newer and
`C:\xampp\php\php.exe -m` lists `pdo_mysql` and `mbstring`.

### A.2 Place the files

Copy (or `git clone https://github.com/jdsricardo/Ciber.git`) the project into the XAMPP web
folder. This manual assumes `C:\xampp\htdocs\www\Ciber`; if you choose another folder, adjust the
URL in A.6 accordingly (the URL is the folder path below `htdocs`, followed by `/public/`).

**Check:** `C:\xampp\htdocs\www\Ciber\public\index.php` exists.

### A.3 Start Apache and MySQL

Open the **XAMPP Control Panel** and click **Start** next to **Apache** and **MySQL**.

**Check:** both modules turn green. If port 80 or 3306 is taken, stop the program using it or
change the port in XAMPP (`Config` button) and use that port in A.5 and A.6.

### A.4 Create the database and its user

1. Open `http://localhost/phpmyadmin/`.
2. **Import** → choose `database.sql` from the project folder → **Import** (bottom of the page).
   This creates the `sentinelscope` database with the tables `applications`, `analyses` and
   `findings`. Importing it again later is safe: it only adds what is missing.
3. Open the **SQL** tab and run the statements below, replacing `CHOOSE_A_PASSWORD` with a strong
   password of your own. They create a user that can read and write the application's data and
   nothing else:

```sql
CREATE USER 'sentinelscope_app'@'localhost' IDENTIFIED BY 'CHOOSE_A_PASSWORD';
CREATE USER 'sentinelscope_app'@'127.0.0.1' IDENTIFIED BY 'CHOOSE_A_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE ON sentinelscope.* TO 'sentinelscope_app'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON sentinelscope.* TO 'sentinelscope_app'@'127.0.0.1';
FLUSH PRIVILEGES;
```

**Check:** the left panel of phpMyAdmin shows `sentinelscope` with three tables.

### A.5 Configure `.env`

In the project folder, copy `.env.example` to a new file named `.env` (exactly that name, with the
leading dot) and edit it:

| Key | What to write |
|---|---|
| `DB_HOST` | `127.0.0.1` |
| `DB_PORT` | `3306` (or the port chosen in A.3) |
| `DB_NAME` | `sentinelscope` |
| `DB_USER` | `sentinelscope_app` |
| `DB_PASSWORD` | the password chosen in A.4 |
| `PYTHON_BINARY` | `python`. If the analysis later fails with *"O scanner retornou uma resposta inválida"*, write the full path instead, e.g. `C:\Users\you\AppData\Local\Programs\Python\Python312\python.exe` (find it with `where python`). |
| `ALLOW_PRIVATE_TARGETS` | `false`. Write `true` **only** to analyse an application running on your own machine or a laboratory network (A.7). |

`.env` holds a password: never send it to anyone and never commit it (Git already ignores it).

### A.6 First access

Open `http://localhost/www/Ciber/public/`.

**Check:** the **Painel** page appears with the heading *"Encontre o risco. Entregue a correção."*
and the text *"Nenhuma aplicação registrada ainda."*

| What you see instead | Cause and fix |
|---|---|
| *"Configuração necessária: copie .env.example para .env…"* | `.env` is missing or has another name (Windows may have saved it as `.env.txt`). Redo A.5. |
| *"Ocorreu um erro inesperado. Consulte o log do servidor."* | Usually the database: MySQL not started (A.3), `database.sql` not imported (A.4), or wrong user/password in `.env`. The exact reason is in `C:\xampp\apache\logs\error.log`, on the last line starting with `SentinelScope:`. |
| *Object not found* (404) | The URL does not match the folder of A.2. |

### A.7 Verify the scanner (recommended)

The project ships a deliberately vulnerable laboratory application, so the installation can be
verified without touching any real system.

1. In a terminal, in the project folder: `python tests/e2e/lab_target.py --port 8765`
   (leave it running).
2. In `.env`, set `ALLOW_PRIVATE_TARGETS=true`.
3. In the browser, follow B.1 and B.2 with the URL `http://127.0.0.1:8765/`.

**Check:** the analysis finishes with status *completed*, **34** checks executed and a list of
findings (missing security headers, cookie without HttpOnly, …). Stop the laboratory with
`Ctrl+C` and set `ALLOW_PRIVATE_TARGETS=false` again afterwards.

### A.8 Recommendations for a shared or production-like installation

- Point Apache's `DocumentRoot` at the `public` folder, so no other project file is reachable.
- Serve over HTTPS and put the application behind authentication: this version assumes a trusted,
  single-user local installation and has no login of its own.
- Keep `ALLOW_PRIVATE_TARGETS=false`.
- Keep `display_errors=Off` in `php.ini` (the application also forces it off).
- A complete-mode analysis may take up to ~10 minutes on a large target. The application raises
  PHP's time limit for that request itself; if a proxy sits in front of Apache, give it a read
  timeout of at least 11 minutes.

---

## Part B — Use

### B.1 Register an application

**Adicionar aplicação** → enter a **name** and the **base URL** of a test or staging environment
(`https://staging.example.com/`) → tick the authorization statement → **Registrar aplicação**.

The URL must start with `http://` or `https://` and must not contain a user or password. Without
the authorization tick the application is not registered.

### B.2 Run an analysis

On the **Painel**, each application has a card with the **Executar análise** button.

| Option | Effect |
|---|---|
| *(default)* **Passive** | Observes the responses only: transport, security headers, cookies, CORS, cache, information disclosure, exposed secrets — 34 checks. Sends two ordinary GET requests per page. Usually seconds. |
| **Análise completa (ativa)** | Also sends safe test payloads to every parameter and form field found (SQL injection, XSS, path traversal, open redirect, command injection, SSTI, XXE, CRLF, Host header, HTTP verbs, NoSQL, CORS, SSRF) — 64 checks. Requires the second authorization tick. Can take several minutes. |
| **Área autenticada (opcional)** | Paste a session cookie (e.g. `PHPSESSID=…`) of a test user to analyse pages behind login. It is sent only to the registered address, during this analysis, and is never stored. |

The scanner starts at the registered URL and follows same-site links (up to 30 pages in passive
mode, 20 in complete mode). It never follows logout links or links that change data (such as
`?action=delete`).

While the analysis runs, the button shows **Analisando…** and a progress message; do not close
the page. When it ends, the result page opens.

### B.3 Read the result

The header shows the **Pontuação de Segurança** (0–100) and four metrics: checks executed,
findings, HTTP status of the first page, and duration.

Each finding reads top-down: **what was observed**, **why it matters**, **how to fix it**, and a
**vulnerable vs. fixed** code example you can copy with one click. Two badges are independent:

- **Severity** — how bad it would be if real (crítico, alto, médio, baixo).
- **Confidence / status** — how sure the scanner is. *Revisão manual* means a person should
  confirm the finding before acting.

The chips above the list filter the findings by severity. The **technical context** panel of each
finding shows the raw evidence.

How the score is calculated: it starts at 100 and loses 30 / 15 / 7 / 2 points per critical / high
/ medium / low finding, never going below 0. It is meant to compare successive analyses of the
same application, not to certify security.

If the analysis could not be completed, the page says why — for example, the address did not
answer, or it points to a private network while that is not allowed.

### B.4 Compare before and after a fix

After deploying fixes, run a new analysis. On the application's card, choose the older and the
newer analysis and click **Comparar**. The page lists **Novos problemas**, **Ainda presentes** and
**Corrigidos**, each with the page and parameter where the finding is, plus the score change.

### B.5 Report and export

- **Relatório para impressão** → **Imprimir / Salvar como PDF** produces a PDF with the header,
  the metrics and every finding with its explanation and fix.
- **Exportar JSON** downloads the analysis for CI pipelines or issue trackers: the application and
  date, a summary (findings per severity, findings needing manual review, score) and every finding
  with its taxonomy, evidence and fix example.

### B.6 History

Each card lists every analysis of that application, most recent first, with date (UTC), mode,
status, score and number of checks. Click an analysis number to open it.

To consult a period, fill **De** and/or **Até** in *Histórico por período* above the cards and
click **Filtrar**: every card then lists only the analyses started in that period (both days
included; leave one field empty for an open end). **Limpar** shows the whole history again.

---

## Part C — Troubleshooting

| Problem | What to do |
|---|---|
| *"O scanner retornou uma resposta inválida. Verifique a configuração do Python."* | Python is not found by Apache. Put the full path to `python.exe` in `PYTHON_BINARY` (A.5). Test it: `"<that path>" scanner\scanner.py https://example.com` must print one line of JSON. |
| *"Private, loopback, link-local, and reserved targets are blocked"* | Expected protection: the address is on your machine or a private network. Set `ALLOW_PRIVATE_TARGETS=true` only for an authorized laboratory. |
| *"Falha de rede ao acessar o alvo"* / *"Nenhuma página pôde ser acessada no alvo"* | The address did not answer: check it in the browser, the VPN, or a firewall. |
| *"A análise excedeu o tempo máximo de … segundos e foi interrompida."* | The target is too slow or too large for one analysis. Run the passive mode, or analyse a more specific URL. |
| *"Falha ao gravar o resultado da análise."* | The database refused the write (disk full, permissions). See the last `SentinelScope:` line of `C:\xampp\apache\logs\error.log`. |
| *"Seu token de sessão expirou."* | The page was open for too long or cookies are blocked; reload it and repeat. |
| *"Informe as datas no formato AAAA-MM-DD."* / *"A data inicial deve ser anterior ou igual à data final."* | Correct the period in *Histórico por período*, or click **Limpar**. |
| An analysis listed as *running* | Only while it is in progress. An analysis is always closed as *completed* or *failed* when its request ends. |
