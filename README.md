# SentinelScope

O SentinelScope é uma plataforma de avaliação de segurança de aplicações web feita para
desenvolvedores, criada como projeto de conclusão de curso de Engenharia de Software. Ele rastreia
um alvo autorizado, executa um catálogo fixo de 34 verificações passivas — mais 30 sondas ativas
seguras no modo completo — e transforma o que observou em impacto compreensível e orientação de
correção.

## Tecnologia

- PHP 8.2+ sem framework
- Python 3.10+ sem pacotes externos (apenas a biblioteca padrão)
- MariaDB 10.4+
- HTML e CSS sem framework de frontend

## Início rápido com XAMPP

1. Inicie o Apache e o MySQL no XAMPP.
2. Importe `database.sql` pelo phpMyAdmin e crie o usuário de banco da aplicação
   (comandos no manual, passo A.4).
3. Copie `.env.example` para `.env` e informe as credenciais desse usuário. O `.env` é ignorado pelo Git.
4. Abra `http://localhost/<pasta dentro de htdocs>/public/` — para este repositório em
   `C:\xampp\htdocs\www\Ciber`, o endereço é `http://localhost/www/Ciber/public/`.
5. Para um alvo de laboratório local e isolado, defina `ALLOW_PRIVATE_TARGETS=true`. Mantenha `false` no uso normal.

A conta do servidor web precisa ter permissão para executar o binário Python configurado. Nunca
envie um alvo sem autorização explícita. O modo completo envia payloads de teste e também os
métodos PUT, DELETE e PATCH a cada página visitada: use-o apenas em ambientes de teste.
O procedimento completo, passo a passo, está no [manual de instalação e de uso](docs/INSTALLATION_AND_USER_MANUAL.md).

## Testes

| Suíte | Comando | Requer |
|---|---|---|
| Python (motor, plugins, lado produtor do contrato) | `python -m unittest discover -s tests -v` | Apenas Python (~4–5 min: usa sockets reais) |
| PHP (domínio, casos de uso, apresentação, lado consumidor do contrato) | `php tests/php_test.php` | Apenas PHP — repositórios em memória, sem `.env` |
| Sistema e injeção de falhas (ponta a ponta: Apache + MariaDB + motor) | `python tests/e2e/run_system_tests.py` | A instalação em funcionamento, `ALLOW_PRIVATE_TARGETS=true` |

O plano está em [docs/TEST_PLAN.md](docs/TEST_PLAN.md); os resultados, os defeitos e a
verificação de cada um estão em [docs/TEST_REPORT.md](docs/TEST_REPORT.md); as evidências brutas
ficam em `docs/test-evidence/`.

## Documentos de engenharia

- [Padrão de codificação](docs/CODING_STANDARD.md) — as regras que este código segue.
- [Guia do desenvolvedor](docs/DEVELOPER_GUIDE.md) — estrutura, ciclo de uma requisição, referência dos módulos, como adicionar uma verificação.
- [Arquitetura](docs/ARCHITECTURE.md) — camadas, contratos, o motor de varredura e o modelo de dados.
- [Contrato de integração](docs/INTEGRATION_CONTRACT.md) — o acordo versionado entre a aplicação
  PHP e o motor Python.
- [Medições de algoritmos](docs/ALGORITHM_MEASUREMENTS.md) — a base medida de cada decisão de
  estrutura de dados, reproduzível com `evaluation/benchmark_structures.py` e
  `evaluation/benchmark_comparison.php`.
- [Requisitos](docs/REQUIREMENTS.md), [plano de testes](docs/TEST_PLAN.md),
  [relatório de testes](docs/TEST_REPORT.md), [motor de varredura](docs/SCANNER_ENGINE.md).
- [Conformidade com o roteiro](docs/ROADMAP_COMPLIANCE.md) — situação de cada passo das Fases 4 e 5,
  as regras de precedência e os checklists pré-entrega, cada um com sua evidência.
- [Changelog](CHANGELOG.md).

Os nomes dos arquivos foram mantidos em inglês porque são referenciados pelo código, pelos testes
e pelos documentos de entrega; o conteúdo está em português.

## Avaliação empírica

`evaluation/` contém um arcabouço reproduzível que mede precisão, recall e F1 de detecção contra
alvos deliberadamente vulneráveis (DVWA, OWASP Juice Shop, WebGoat) em um laboratório autorizado.
Veja [evaluation/README.md](evaluation/README.md) e os resultados já obtidos em
[docs/EVALUATION_RESULTS.md](docs/EVALUATION_RESULTS.md).

## Documentos da disciplina

`docs/docsAula/` reúne os documentos entregues na disciplina: o roteiro seguido
(`Roteiro_de_Execucao_do_Projeto.pdf`), o Termo de Referência, a entrevista de requisitos, a
atividade de estruturas de dados e os documentos das Fases 2 e 3, que consolidam as decisões
técnicas e a arquitetura. `docs/entrega-final/` contém o documento da entrega final e suas
evidências, e `docs/apresentacao/` a apresentação da defesa.

Consulte o [manual de instalação e de uso](docs/INSTALLATION_AND_USER_MANUAL.md) para as instruções completas.
