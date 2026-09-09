# Resultado da avaliação empírica — SentinelScope

**Ambiente:** Altoro Mutual (demo.testfire.net) — aplicação bancária deliberadamente vulnerável mantida pela IBM para teste público de ferramentas de segurança. Superfície NÃO autenticada, alcançada por rastreamento a partir da raiz. Ground-truth estabelecido por verificação manual (reprodução de cada requisição) em 2026-09-09.

**Famílias avaliadas (escopo):** nosql_injection, path_traversal, sqli, xss


## Métricas por família

| Família | VP | FP | FN | Precisão | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| nosql_injection | 0 | 1 | 0 | 0.00 | 0.00 | 0.00 |
| path_traversal | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| sqli | 0 | 0 | 1 | 0.00 | 0.00 | 0.00 |
| xss | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **Total** | **2** | **1** | **1** | **0.67** | **0.67** | **0.67** |

## Detalhe por alvo

### Altoro Mutual — superfície não autenticada (rastreada)
- URL: `http://demo.testfire.net/`
- Modo: safe_active · requisições: 909 · duração: 531 ms
- Esperado: ['path_traversal', 'sqli', 'xss']
- Detectado (no escopo): ['nosql_injection', 'path_traversal', 'xss']
- VP: ['path_traversal', 'xss'] · FP: ['nosql_injection'] · FN: ['sqli']


> Gerado por `evaluation/evaluate.py`. Preencha a coluna comparativa com a baseline de mercado (ex.: OWASP ZAP baseline) executada sobre os mesmos alvos.
