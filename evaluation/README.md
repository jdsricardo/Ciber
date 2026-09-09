# Avaliação empírica

Este diretório contém o arcabouço reproduzível para a **avaliação empírica comparativa**
proposta no artigo (Seção 5.3). Ele mede, contra alvos deliberadamente vulneráveis, a
capacidade de detecção do SentinelScope em termos de verdadeiros positivos (VP), falsos
positivos (FP), falsos negativos (FN), **precisão**, **recall** e **F1** por classe de
vulnerabilidade.

> ⚠️ **Uso ético.** Só execute contra aplicações que você mesmo hospeda em laboratório
> isolado (ex.: DVWA, OWASP Juice Shop, OWASP WebGoat) ou para as quais possua autorização
> explícita. O arcabouço se recusa a rodar enquanto o arquivo de ground-truth não declarar
> `"authorized": true`.

## Como executar

1. Suba um alvo vulnerável em laboratório isolado. Exemplos:
   - **DVWA** (Damn Vulnerable Web Application) via Docker: `docker run --rm -p 8080:80 vulnerables/web-dvwa`
   - **OWASP Juice Shop**: `docker run --rm -p 3000:3000 bkimminich/juice-shop`
2. Copie `ground_truth.example.json` para `ground_truth.json`, ajuste as URLs para o seu
   laboratório e marque `"authorized": true`.
3. Rode o arcabouço (a partir da raiz do projeto):

   ```bash
   python evaluation/evaluate.py evaluation/ground_truth.json --out evaluation/report.md --allow-private
   ```

   `--allow-private` é necessário porque os alvos de laboratório costumam ficar em
   `127.0.0.1`, normalmente bloqueado pela proteção contra SSRF.

4. O relatório (`report.md`) traz a tabela por família e o detalhe por alvo — pronto para
   colar na seção de resultados do TCC.

## Baseline de comparação (OWASP ZAP)

Para posicionar o SentinelScope frente a uma ferramenta de mercado, execute o **OWASP ZAP
baseline** sobre exatamente os mesmos alvos e preencha a coluna comparativa na tabela do
artigo:

```bash
docker run --rm -t --network host ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py -t http://127.0.0.1:8080/ -r zap_report.html
```

Registre, para cada classe, VP/FP/FN de cada ferramenta e compare precisão/recall/F1. Como
os dois usam critérios de detecção diferentes, documente no texto como você mapeou os
alertas do ZAP para as mesmas classes (CWE) usadas aqui.

## O que conta como acerto

Cada achado tem uma *família*, o prefixo do seu `fingerprint` antes do primeiro ponto
(`sqli.boolean_differential` → `sqli`). Para cada alvo, `expected_families` lista as
famílias realmente presentes; o arcabouço compara com as famílias detectadas, restritas a
`scope_families`. Detecções fora do escopo (ex.: cabeçalhos ausentes) não contam como
falso positivo — elas simplesmente não fazem parte do experimento de detecção de classe.
Um alvo endurecido com `expected_families: []` funciona como **controle negativo**: qualquer
detecção no escopo ali é, por definição, um falso positivo.
