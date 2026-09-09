# Installation and User Manual

## Prerequisites

Windows with XAMPP (Apache, PHP 8.2+, MariaDB) and Python 3.10+ available as `python`. Enable PHP extensions `pdo_mysql` and `mbstring`.

## Installation

1. Place the repository in the XAMPP `htdocs` directory.
2. Start Apache and MySQL.
3. Open phpMyAdmin, choose **Import**, and import `database.sql`.
4. Copy `.env.example` to `.env` if it is absent and set the MariaDB credentials and Python executable. Never commit `.env`.
5. Open the project's `/public/` URL. A dashboard confirms database connectivity.

For production-like use, point the web server document root directly to `public`, use a dedicated least-privilege database user, enable HTTPS, keep `allow_private_targets` disabled, and restrict access to authenticated users.

## Use

Select **Add application**, enter a test or staging URL, confirm authorization, and register it. Select **Run analysis** and wait up to the network timeout. Read findings in this order: what was observed, why it matters, and how to fix it — each finding also shows a concrete "vulnerable vs. fixed" code example. After deploying fixes, run another analysis and compare the two. Open **Printable report** and use the browser's **Save as PDF** option. On the results page you can also filter findings by severity, copy a fix example to the clipboard, and use **Exportar JSON** to download the analysis as machine-readable JSON for CI or ticketing.

To scan an authenticated area, expand **Área autenticada (opcional)** on the run form and paste a valid session cookie (e.g. `PHPSESSID=...`). It is sent only to the authorized target for that single analysis and is never stored. From the command line the same is available with `python scanner/scanner.py <url> --mode safe_active --cookie "PHPSESSID=..."` (or the repeatable `--header "Name: value"`).

## Troubleshooting

- Database error: verify MySQL is running, the schema was imported, and `.env` credentials are correct.
- Invalid scanner response: run `python scanner/scanner.py https://example.com` and verify the Python path.
- Private target blocked: this is expected SSRF protection. Enable the laboratory option only in an isolated, explicitly authorized environment.
- Permission error: allow the Apache service account to execute Python and read the project files.
