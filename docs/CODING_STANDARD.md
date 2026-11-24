# Padrão de Codificação

As regras que este código segue. Cada uma está escrita para que um revisor possa decidir, sem
discussão, se uma mudança está em conformidade — e as regras marcadas como **verificada** são
checadas automaticamente pela suíte de testes, para que não se deteriorem em silêncio. Quando a
verificação automática cobre só parte da regra, isso está dito ao lado.

A Etapa 9 do roteiro do projeto pede um repositório com histórico e um documento de padrão de
codificação. Este é esse documento; ele descreve o código como ele é, não como poderia ser.

## 1. Idioma e público

| Artefato | Idioma | Motivo |
|---|---|---|
| Código-fonte, identificadores, comentários, docstrings | Inglês | O código é lido por engenheiros e por ferramentas; um único idioma evita identificadores misturados. |
| Títulos, descrições, impacto para o desenvolvedor, remediação e notas dos exemplos dos achados | Português do Brasil | O público é uma equipe de desenvolvimento brasileira (NFR-06). |
| Textos da interface e mensagens de erro exibidas no navegador, inclusive as mensagens de falha geradas pelo motor | Português do Brasil | Mesmo público. |
| Identificadores CWE / OWASP / WSTG | Forma padrão em inglês | São identificadores externos, não prosa. |
| Documentação de engenharia (`README.md`, `CHANGELOG.md`, `docs/`, `evaluation/`) | Português do Brasil | Mesmo público; traduzida em 2026-11-24. Os nomes dos arquivos continuam em inglês porque são referenciados pelo código e pelos testes. Os documentos da disciplina em `docs/docsAula/` também estão em português. |

Exceção conhecida: a evidência bruta gerada pelo driver de testes (`docs/test-evidence/*/results.md`)
continua em inglês, pois é saída de ferramenta preservada como registro.

## 2. Comentários

Um comentário explica o **porquê**, nunca o **o quê**. Um comentário que repete a linha abaixo
indica que o problema é a linha.

```python
# Bad — restates the code
# increment the counter
self.total += 1

# Good — states the reason the code cannot be simpler
# Re-resolving on every request is what closes the DNS-rebinding window: a name that
# pointed at the authorized address when the scan started must still point there now.
if self._resolve(parsed.hostname) != self.pinned_addresses:
```

Todo módulo, classe e função não óbvia traz uma docstring ou docblock declarando sua
responsabilidade em uma frase. Uma exceção engolida nunca é escrita sem um comentário dizendo qual
falha está sendo tolerada e por que continuar é seguro.

Exceção conhecida: `scanner/engine/matchers.py` está escrito em estilo compacto (várias instruções
por linha, sem docstrings) e não segue esta seção nem o §4.

## 3. PHP

- `declare(strict_types=1);` como primeira instrução depois de `<?php`. **Verificada.**
- Uma classe, interface ou enum por arquivo, em um namespace que espelha seu diretório dentro de
  `app/src/`, carregada por `app/autoload.php`. **Verificada** a regra de um tipo por arquivo; o
  espelhamento do namespace é garantido na prática pelo autoloader (um tipo fora do lugar não
  carrega).
- Classes são `final`, a menos que algo as estenda. O único tipo não final é a abstrata
  `DomainError`. **Verificada.**
- Todo método declara tipo de retorno, e todo parâmetro e propriedade declara seu tipo. `mixed` é
  usado apenas onde o valor é de fato irrestrito (`Html::escape`, `Config::get`,
  `Finding::nullableString`, `TransactionManager::transactional` e suas implementações).
  **Verificada** para o tipo de retorno; os tipos de parâmetros e propriedades são conferidos na
  revisão.
- Propriedades são `readonly` quando o valor não muda depois da construção.
- 4 espaços, chaves em linha própria para classes e métodos, tipos em `UpperCamelCase`, métodos e
  variáveis em `lowerCamelCase`, constantes em `UPPER_SNAKE`.
- SQL existe apenas dentro de `app/src/Infrastructure/Persistence/`, sempre por *prepared
  statements* do PDO com parâmetros vinculados — nunca concatenação de strings. **Verificada.**
  (O único SQL fora dali é o comando de inicialização da conexão, `SET time_zone = '+00:00'`, em
  `Infrastructure\Database`.)
- `public/index.php` conecta os adaptadores, despacha uma requisição e converte erros em
  respostas. Não contém regra de negócio.
- Toda saída que chega ao navegador passa por `App\Presentation\Html::escape` (ou `e()`).

## 4. Python

- O motor depende apenas da biblioteca padrão do Python. Nenhum pacote de terceiros é importado
  em tempo de execução. **Verificada.**
- `from __future__ import annotations` primeiro, depois as importações da biblioteca padrão e, por
  fim, as importações locais.
- Anotações de tipo em toda assinatura de função pública e em todo campo de dataclass.
- Dados que atravessam a fronteira entre módulos são dataclasses de `engine/models.py`, nunca um
  dicionário solto. (O documento de resultado da varredura é um dicionário por definição: é o JSON
  do contrato.)
- Funções em `snake_case`, classes em `UpperCamelCase`, 4 espaços.
- Uma linha é quebrada quando deixa de ser legível, não em uma coluna fixa. Duas coisas ficam
  deliberadamente em uma linha mesmo quando longas: os textos dos achados em português
  (`description`, `developer_impact`, `remediation`), porque são revisados como prosa e um literal
  concatenado torna o diff ilegível; e as tabelas de assinaturas regex, porque quebrar um padrão
  esconde o que ele reconhece.

## 5. Estrutura e direção das dependências

```
Presentation ─┐
              ├─► UseCase ─► Domain ◄─ Infrastructure
              └──────────────────┘
```

- `app/src/Domain/` não depende de nada fora de si. **Verificada:** um teste em
  `tests/php_test.php` remove os comentários com `token_get_all` e falha se algum arquivo do
  domínio referenciar, em código, `App\Infrastructure`, `App\Presentation`, `App\UseCase` ou `PDO`.
- As interfaces entre camadas ficam em `app/src/Domain/Contract/`, declaradas pelo domínio e
  implementadas fora dele, de modo que a seta de dependência sempre aponta para dentro.
  **Verificada** (todo arquivo de `Domain/Contract` é uma interface).
- Uma classe tem uma responsabilidade. Quando um tratador de requisição começa a tomar decisões, a
  decisão vai para um caso de uso ou para o domínio.
- No motor, uma nova verificação é uma nova subclasse de `ScannerPlugin`. O orquestrador não
  contém lógica específica de vulnerabilidade. **Verificada** (todo plugin registrado é um
  `ScannerPlugin` com metadados e ids únicos).

## 6. Erros

- O domínio lança apenas subclasses de `App\Domain\Exception\DomainError` — `InvalidInput` (400),
  `NotFound` (404), `ScannerUnavailable` (502). Nunca devolve `null` ou `false` para sinalizar uma
  regra violada. **Verificada** em parte: a suíte confere a hierarquia e o status HTTP de
  `InvalidInput` e `NotFound`; a ausência de retornos `null`/`false` é conferida na revisão.
- A mensagem é escrita para o desenvolvedor que usa a aplicação: em português, sem *stack trace*,
  sem SQL, sem identificador interno.
- Falhas de infraestrutura são encapsuladas, pelo adaptador que as produziu, no `DomainError`
  correspondente. Qualquer coisa que chegue ao *front controller* como um `Throwable` comum é um
  defeito: é registrada por completo no log e o usuário recebe uma mensagem genérica.
- Um caso de uso que já criou um registro o encerra antes de desistir, para que uma falha nunca
  deixe uma linha presa em um estado intermediário. **Verificada** para `RunAnalysis`.
- No Python, `engine/safety.py` define o vocabulário de falhas do motor (`Cancelled`,
  `BudgetExceeded`, `EndpointBudgetExceeded`, `ScopeViolation`). Um detector nunca inventa um novo
  tipo de exceção para uma situação que o runner já trata. As mensagens dessas exceções chegam ao
  usuário e por isso são escritas em português.
- Uma falha de rede é uma condição operacional esperada, não uma quebra: `run_scan` a reporta como
  `{"ok": false, "error": ...}`.

## 7. Testes

- Toda mudança de comportamento vem com um teste. Python: `tests/test_*.py`, `unittest` padrão.
  PHP: `tests/php_test.php`, um harness sem dependências.
- Os testes PHP carregam `app/autoload.php`, nunca `app/bootstrap.php`, então a suíte não precisa
  de `.env` nem de banco; a persistência e o motor são substituídos pelas implementações em memória
  de `tests/php/`. **Verificada** — a suíte roda em uma máquina sem MariaDB.
- Os testes verificam comportamento, não estrutura interna.
- A suíte completa passa antes de um commit: `python -m unittest discover -s tests` e
  `php tests/php_test.php`.

## 8. Commits e repositório

- Um commit por mudança coerente; um commit que mistura refatoração com mudança de comportamento é
  dividido.
- Mensagem: um assunto curto, no imperativo, descrevendo o efeito, e depois o motivo quando ele não
  é óbvio pelo diff.
- `master` sempre tem a suíte passando.
- Segredos nunca entram no repositório: `.env` é ignorado, `.env.example` traz valores
  substitutos e `ALLOW_PRIVATE_TARGETS` vem como `false`. **Verificada.**

## 9. Decisões de desempenho

Uma escolha de estrutura de dados ou de algoritmo feita por desempenho é medida, não afirmada. Os
harnesses são `evaluation/benchmark_structures.py` e `evaluation/benchmark_comparison.php`; os
resultados e as decisões que eles sustentam estão em
[ALGORITHM_MEASUREMENTS.md](ALGORITHM_MEASUREMENTS.md). Uma medição que não confirma a expectativa
é registrada como tal.
