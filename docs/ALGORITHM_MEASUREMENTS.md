# Medições de Algoritmos e Estruturas de Dados

Cada escolha estrutural abaixo foi feita porque foi medida, não porque se esperava que fosse mais
rápida. Cada decisão indica a alternativa rejeitada e os tamanhos de entrada em que as duas foram
comparadas.

## Ambiente de medição

| Item | Valor |
|---|---|
| CPU | Intel64 Family 6 Model 140 (11ª geração, mobile), AMD64 |
| SO | Windows 11 Pro 10.0.26200 |
| Python | 3.12.2 (CPython, 64 bits) |
| PHP | 8.2.12, ZTS, 64 bits |
| Método | Mediana de 5 execuções por caso, tempo de relógio, no mesmo processo |
| Data | 2026-09-16 |

Reporta-se a mediana — não a média —, para que um único soluço de escalonamento na máquina de
medição não possa mover um resultado. Os tempos absolutos dependem da máquina; a razão entre as
duas implementações não, e é na razão que a decisão se apoia.

## Como reproduzir

```
python evaluation/benchmark_structures.py     # motor do scanner (Python)
php   evaluation/benchmark_comparison.php     # comparação de análises (PHP)
```

Ambos aceitam `--json` para um resultado legível por máquina.

## Decisão 1 — Fronteira do rastreamento: `deque`, não lista

`ScanRunner.run` percorre a superfície de mesma origem alcançável em largura, retirando a próxima
página do início da fronteira. Remover do início de uma lista Python desloca todos os elementos
restantes; `collections.deque.popleft()` tem tempo constante.

| n (páginas na fronteira) | lista + `pop(0)` | deque + `popleft()` | Ganho |
|---|---|---|---|
| 30 | 0.0102 ms | 0.0107 ms | 1.0× |
| 1 000 | 0.4311 ms | 0.3390 ms | 1.3× |
| 10 000 | 228.0680 ms | 4.0594 ms | 56.2× |

**Decisão: `deque`.** No tamanho que uma varredura realmente atinge — `max_pages` é 30 (passivo)
e 20 (ativo) — as duas são indistinguíveis, e a leitura honesta da medição é que esta mudança não
traz ganho hoje. Ela foi adotada mesmo assim porque custa um import e remove o único termo
quadrático do laço de rastreamento, de modo que aumentar `max_pages` no futuro seja uma mudança
de configuração e não uma investigação de desempenho. Implementada em `scanner/engine/runner.py`;
desde 2026-11-25 a fronteira é `CrawlFrontier` (`scanner/engine/crawler.py`), com **duas** deques —
formatos de página novos e variações de formatos conhecidos —, ambas consumidas com `popleft()`.

## Decisão 2 — Páginas já enfileiradas: conjunto hash, não lista

Antes de enfileirar um link, o rastreador pergunta se aquela assinatura de página já foi vista. A
pergunta é feita uma vez por link descoberto, então seu custo se multiplica pelo número de links
do site, não pelo número de páginas varridas.

| n (assinaturas distintas) | lista + `in` | set + `in` | Ganho |
|---|---|---|---|
| 30 | 0.0194 ms | 0.0114 ms | 1.7× |
| 1 000 | 13.5200 ms | 0.3538 ms | 38.2× |
| 10 000 | 618.4438 ms | 2.1607 ms | 286.2× |

**Decisão: `set`.** Pertinência é a única operação feita nessa coleção, e ela é feita para cada
link de cada página, então o O(1) médio é a propriedade que importa; a ordem é irrelevante porque
a fronteira já preserva a ordem de visita. Implementado como `enqueued` em
`scanner/engine/runner.py`, hoje em `CrawlFrontier` (`scanner/engine/crawler.py`).

**Reavaliação (2026-11-25).** A assinatura passou a incluir os *valores* dos parâmetros
(`index.php?p=12` ≠ `?p=14`). Com isso, um catálogo que lista mil produtos gera mil assinaturas
distintas — exatamente a faixa da tabela em que o `set` é 38× mais rápido que a lista. A decisão
deixou de ser preventiva e passou a ser necessária. Os formatos já vistos (`queued_shapes`) e o
estado de cada formato (`shapes`) usam a mesma estrutura pelo mesmo motivo.

## Decisão 3 — Deduplicação de achados: conjunto de chaves, não varredura par a par

Um rastreamento de muitas páginas relata a mesma condição de nível de site (um cabeçalho ausente,
um cookie inseguro) uma vez por página. `ScanRunner._deduplicate` os consolida, mantendo a ordem
em que foram vistos pela primeira vez.

| n (achados antes da deduplicação) | varredura par a par | conjunto de chaves | Ganho |
|---|---|---|---|
| 30 | 0.0151 ms | 0.0114 ms | 1.3× |
| 1 000 | 3.4437 ms | 0.4951 ms | 7.0× |
| 10 000 | 474.9044 ms | 6.3865 ms | 74.4× |

**Decisão: conjunto de chaves.** Uma varredura ativa de 20 páginas com 64 verificações produz
achados na casa das centenas antes da deduplicação, onde a varredura par a par já é mensuravelmente
pior e piora quadraticamente. A lista de achados únicos é mantida ao lado do conjunto, porque a
ordem do relatório faz parte da saída e um conjunto não tem ordem.

## Decisão 4 — Comparação de duas análises: mapa indexado por fingerprint, não varredura par a par

`AnalysisComparison::diff` classifica cada achado de duas análises como novo, persistente ou
corrigido. A formulação natural — "para cada achado, procure-o na outra análise" — é O(n²).
Indexar os dois lados por fingerprint primeiro transforma cada classificação em uma consulta hash,
e deixa `array_diff_key` / `array_intersect_key` do PHP fazerem o trabalho em C.

| n (achados por análise) | varredura par a par | indexado por fingerprint | Ganho |
|---|---|---|---|
| 100 | 0.4590 ms | 0.0141 ms | 32.6× |
| 1 000 | 94.8329 ms | 0.2000 ms | 474.2× |
| 10 000 | 9 950.7170 ms | 2.8598 ms | 3 479.5× |

**Decisão: mapa indexado por fingerprint.** Este é o único caso em que a medição muda o
atendimento de um critério de aceite. CA-05 / NFR-01 exige que um histórico de 1 000 achados seja
utilizável em até três segundos; a versão par a par gasta 95 ms desse orçamento só na comparação
e degrada para cerca de 10 s com 10 000 achados, enquanto a versão indexada fica abaixo de 3 ms.
Implementado em `app/src/Domain/Service/AnalysisComparison.php`.

*Atualização de 2026-10-14 (defeito D-01, Fase 5).* A chave do mapa mudou do fingerprint puro
para a identidade do achado (`Finding::identity()`: id da verificação, endpoint sem query string,
localização e nome do parâmetro), porque o fingerprint sozinho fundia a mesma verificação em dois
endpoints. A estrutura — um mapa hash por lado, uma consulta por achado — não mudou, então a
medição acima continua válida; a verificação de ponta a ponta com 1 000 achados é o ST-22 em
[TEST_REPORT.md](TEST_REPORT.md).

## Decisão 5 — Persistência: índices B-tree, não estruturas em memória

As três coleções que crescem — `applications`, `analyses`, `findings` — não ficam em memória entre
requisições, então a estrutura que decide seu custo de acesso é o índice que o InnoDB constrói,
não um array PHP. Os índices existem para os dois caminhos de acesso que a aplicação realmente
usa:

| Índice | Atende |
|---|---|
| `idx_analysis_application_date (application_id, started_at)` | o histórico de uma aplicação, já ordenado, sem filesort |
| `idx_finding_analysis (analysis_id)` | carregar os achados de uma análise |
| `idx_finding_fingerprint (analysis_id, fingerprint)` | localizar um achado por identidade ao comparar análises |

B-tree, não índice hash: a consulta de histórico é uma varredura de intervalo ordenada por data,
que um índice hash não consegue atender. Cada consulta é O(log n) em vez do O(1) médio de um mapa
hash em memória, e essa é a troca correta — durabilidade e acesso ordenado são requisitos aqui; a
velocidade de uma consulta isolada não é a restrição determinante.

O carregamento e a renderização de 1 000 achados são medidos diretamente pela suíte PHP
(`tests/php_test.php`, CA-05): a renderização termina bem abaixo do orçamento de três segundos.

## Reexecução de 2026-11-24

Os dois benchmarks foram executados novamente para confirmar que continuam funcionando e que as
conclusões se mantêm. Ambiente: Windows 11 Pro 10.0.26300, Python 3.12.10, PHP 8.2.12 (mesma
família de máquina; não é uma remedição controlada).

| Decisão | n | Alternativa | Estrutura adotada | Ganho |
|---|---|---|---|---|
| 1 — Fronteira do rastreamento | 10 000 | lista: 92.66 ms | deque: 1.86 ms | 49.8× |
| 2 — Páginas já enfileiradas | 10 000 | lista: 451.71 ms | set: 2.15 ms | 209.7× |
| 3 — Deduplicação de achados | 10 000 | par a par: 352.84 ms | conjunto de chaves: 4.37 ms | 80.8× |
| 4 — Comparação de análises | 1 000 | par a par: 70.57 ms | mapa: 0.31 ms | 228.4× |
| 4 — Comparação de análises | 10 000 | par a par: 8 248.0 ms | mapa: 4.09 ms | 2 018.1× |

Os tempos absolutos diferem da medição original, mas as razões mantêm a mesma ordem de grandeza;
todas as decisões continuam válidas.

Observações:

- O benchmark PHP ainda rotula a estrutura adotada como "mapa por fingerprint", enquanto a
  produção indexa o mapa por `Finding::identity()` — a estrutura é a mesma (ver a atualização da
  Decisão 4).
- `benchmark_structures.py` imprime os rótulos acentuados de forma corrompida em um console do
  Windows que não esteja configurado para UTF-8. É apenas cosmético e não afeta os números.
