# Conformidade com o Roteiro — Fases 4 e 5

Situação de cada passo da Fase 4 (Construção, passos 20–25) e da Fase 5 (Integração e verificação,
passos 26–32) do *Roteiro de Execução do Projeto* (`docs/docsAula/Roteiro_de_Execucao_do_Projeto.pdf`),
seguida das regras de precedência da sua seção 8 e dos checklists pré-entrega da sua seção 9. Cada
afirmação aponta para uma evidência que pode ser conferida no repositório; quando um passo não foi
atendido, ou foi atendido apenas por adaptação, este documento diz isso.

Avaliado em 2026-10-14 após a execução 2, e reavaliado em 2026-10-28 após uma conferência cruzada
do produto com o Termo de Referência (defeitos D-09 e D-10, execução 3).

Em 2026-11-24 a documentação de engenharia foi traduzida para o português e reconferida contra o
código (NFR-06 e o §1 do [CODING_STANDARD.md](CODING_STANDARD.md) foram atualizados de acordo; ver
também o §8 do [TEST_REPORT.md](TEST_REPORT.md)).

**Legenda:** ✅ atendido · 🔄 atendido por adaptação documentada · ⏳ pendente (precisa de uma pessoa) · ⚠️ não atendido na ordem que o roteiro pede (histórico)

## 1. Por que alguns passos são adaptados

O roteiro foi escrito para um aplicativo móvel que pode conversar com um módulo físico (emulador,
modo avião, fila de sincronização offline, circuito embarcado). O SentinelScope é uma **aplicação
web do lado do servidor** cujo propósito é enviar requisições HTTP a um alvo: não tem cliente
offline, nem armazenamento local a sincronizar, nem hardware. Os passos 23, 24 e 25 são, portanto,
atendidos pela sua **intenção** — a interface não congela, a perda de conectividade é tratada sem
corromper nem duplicar dados, e o artefato externo de que o produto depende (uma base de validação)
existe e está registrado — com o raciocínio abaixo. Esta é uma leitura do roteiro, não um corte de
escopo: nenhuma funcionalidade do Termo de Referência foi removida.

## 2. Fase 4 — Construção

| Passo | Saída esperada | Situação | Evidência |
|---|---|---|---|
| 20 — Ambiente e projeto com pacotes por camada | Projeto compilando, estrutura refletindo a arquitetura | ✅ | `app/src/{Domain,UseCase,Infrastructure,Presentation}` = as quatro camadas do [ARCHITECTURE.md](ARCHITECTURE.md). Em 2026-10-14, todos os 49 arquivos PHP passavam no `php -l` e todos os 67 arquivos Python compilavam (`python -m compileall`). Em 2026-11-24, os 50 arquivos PHP versionados (o 50º é `docs/entrega-final/evidencias/medir_comparacao.php`, adicionado na entrega final) passam no `php -l` e os 67 arquivos Python compilam. A regra de camadas é executável (AT-02, "domain references no outer layer"). Ambiente reproduzido a partir do manual em XAMPP 8.2 / MariaDB 10.4 / Python 3.12. |
| 21 — Telas e navegação, sem regras de negócio | Telas de alta prioridade navegáveis | ✅ | Rotas no §3 do [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md). `Presentation\Views` só monta markup; toda decisão fica num caso de uso ou no domínio. Navegação exercitada por ST-01…ST-26 e MT-01…MT-03 num navegador real. |
| 22 — Repositório local, telas com dados reais | Persistência funcionando pelo contrato declarado na E2 | ✅ | Os `Pdo*Repository` implementam os contratos do domínio. **A Fase 3 registrou que os adaptadores PDO nunca tinham rodado contra o MariaDB; este ciclo fecha essa lacuna:** todo teste de sistema roda sobre um MariaDB real com um usuário de privilégio mínimo (TEST_REPORT §2). |
| 23 — Operações de dados e de rede fora do caminho da UI, com indicador de carregamento | Interface sem congelar, indicação de carregamento | 🔄 ✅ | O trabalho de rede (a varredura) roda num processo Python separado, iniciado pelo servidor; o navegador nunca o executa, então a página não tem como congelar. Faltava antes deste ciclo: qualquer indicação de trabalho em andamento e proteção contra um segundo clique. Adicionados em 2026-10-14 (mensagem de progresso com `role="status"`, botão travado → nenhuma análise duplicada). Verificado: ST-23 (markup e script); MT-01 num navegador headless real — após um clique duplo o botão fica travado, a mensagem de progresso é exibida e exatamente uma análise é criada. |
| 24 — Fila de sincronização, testada sem conexão (modo avião, sem duplicação na reconexão) | Operação offline verificada | 🔄 | Não existe modo offline a enfileirar: uma análise *é* acesso de rede ao alvo. A intenção do passo — perder a conectividade não deve corromper nem duplicar dados — é verificada assim: alvo inacessível → análise `failed` com motivo, nenhum achado (FI-04); reset TCP transitório repetido uma vez sem cobrar o orçamento em dobro (AT-01, `test_transport.py`); banco de dados inacessível → erro genérico, nada gravado pela metade (FI-02, FI-08, contrato C3); nenhuma análise duplicada no reenvio (trava do passo 23; MT-01). |
| 25 — Módulo externo / base de validação | Artefato pronto e documentado | 🔄 ✅ | Não há hardware. O artefato de que o produto depende é a sua **base de validação**, e ela existe e está registrada: o alvo de laboratório controlável `tests/e2e/lab_target.py` (4 variantes, log de requisições), as fixtures vulneráveis/seguras por plugin em `tests/`, e o harness de avaliação empírica com ground truth em `evaluation/` (resultados em [EVALUATION_RESULTS.md](EVALUATION_RESULTS.md)). |

## 3. Fase 5 — Integração e verificação

| Passo | Saída esperada | Situação | Evidência |
|---|---|---|---|
| 26 — Escrever e versionar o contrato de integração | Formato, campos, delimitadores, regras de validação | ✅ | [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md) v1.0 escrito em 2026-10-14, antes da bateria ponta a ponta, e v1.1 no mesmo dia, depois dela: transporte e enquadramento, argumentos, cada campo da resposta com tipo e limite de coluna, documento de falha, obrigações do consumidor C1–C6, regra de identidade, política de versionamento e histórico de mudanças. Garantido por testes de conformidade nos dois lados lendo um payload compartilhado. |
| 27 — Integrar de ponta a ponta sem atravessar camadas | Fluxo completo da origem dos dados até a tela | ✅ | O driver de teste do sistema age apenas por HTTP sobre a interface real (Apache → front controller → caso de uso → domínio → PDO / gateway → motor → alvo de laboratório) e lê o banco apenas para confirmar o que a tela mostra. ST-06/08 (varredura até a tela), ST-13/14 (comparação), ST-16/17 (exportação, relatório). |
| 28 — Provocar e tratar falhas previsíveis | Comportamento observado em cada falha | ✅ | FI-01…FI-10, com o comportamento observado em cada uma registrado no §2.2 do [TEST_REPORT.md](TEST_REPORT.md). Três delas revelaram defeitos (D-02, D-04, D-06), todos corrigidos. |
| 29 — Um caso de teste por critério de aceite, resultado esperado escrito antes da execução | Casos com pré-condição e resultado esperado | ✅ | [TEST_PLAN.md](TEST_PLAN.md) 2.0 redigido **antes** da primeira execução (execução 1, 2026-10-14 23:00 UTC, evidência em `docs/test-evidence/2026-10-14_run1`). Casos adicionados depois foram escritos antes do código que verificam: ST-24 antes da correção de D-07, ST-25 e ST-26 antes da implementação de D-09 e D-10 (plano §8, revisões datadas). Casos de entrada inválida incluídos. Rastreabilidade CA → casos no §7 do plano. |
| 30 — Executar e registrar defeitos | Resultado por caso; defeitos com passos de reprodução | ✅ | Evidência da execução 1 em `docs/test-evidence/2026-10-14_run1*`, da execução 3a em `2026-10-28_run3a-before`; registro de defeitos com causa raiz e reprodução no §3 do TEST_REPORT. Erros do testware mantidos à parte (§4), incluindo uma falsa APROVAÇÃO que foi anulada. |
| 31 — Corrigir bloqueantes e altos, reexecutar | Defeitos verificados por reexecução, não apenas corrigidos | ✅ | Todos os 10 defeitos corrigidos, inclusive os médios e o baixo. A execução 2 reexecutou a bateria inteira após D-01…D-08 (113/113, 140/140, 24/24, 10/10); a execução 3 a reexecutou de novo sobre o código final, após D-09/D-10: 113/113, 153/153, 26/26 de sistema, 10/10 de injeção de falhas, 3/3 de navegador. O caso revelador de cada defeito é citado na coluna *Verificado* do registro. |
| 32 — Consolidar os cinco documentos técnicos | Documentação completa e coerente com o produto | ✅ | Ver §3.1. |

### 3.1 Os cinco documentos técnicos (passo 32)

O passo 32 recebe como entrada os passos 6 (Termo), 19 (arquitetura), 25 (módulo) e 31 (testes).
Os cinco documentos são, portanto, lidos como:

| # | Documento | Atualizado neste ciclo para corresponder ao produto |
|---|---|---|
| 1 | Especificação de requisitos — [REQUIREMENTS.md](REQUIREMENTS.md) (com o Termo de Referência) | FR-06 e FR-12 reescritos para dizer o que os itens 6 e 8 do Termo exigem (período, resumo da exportação); rastreabilidade verificada pelas inspeções TR-01/TR-02. |
| 2 | Arquitetura — [ARCHITECTURE.md](ARCHITECTURE.md) | Gateway sem shell e com prazo-limite, a regra "nenhuma análise fica em running", identidade do achado, UTC, link para o contrato. |
| 3 | Contrato de integração — [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md) (o documento do módulo/integração) | Novo, v1.1. |
| 4 | Plano e resultados de teste — [TEST_PLAN.md](TEST_PLAN.md), [TEST_REPORT.md](TEST_REPORT.md) | Novo plano 2.0 e relatório. |
| 5 | Manual de instalação e de uso — [INSTALLATION_AND_USER_MANUAL.md](INSTALLATION_AND_USER_MANUAL.md) | Reescrito: a versão anterior apontava para uma URL errada e não explicava como criar o usuário do banco. |

Documentação de apoio ao código: [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) (novo),
[CODING_STANDARD.md](CODING_STANDARD.md), [SCANNER_ENGINE.md](SCANNER_ENGINE.md),
[ALGORITHM_MEASUREMENTS.md](ALGORITHM_MEASUREMENTS.md), [README](../README.md),
[CHANGELOG](../CHANGELOG.md).

## 4. Regras de precedência (roteiro §8)

Para as Fases 1–3, a evidência é o histórico do git (`git log --reverse --stat`). O projeto partiu
de um artefato que já existia (primeiros commits em 2026-08-23); o roteiro foi adotado com o
trabalho em andamento e as Fases 1–3 foram consolidadas **retroativamente**. As Fases 4 e 5 foram
executadas na ordem do roteiro; para elas a evidência é a tabela de revisões datadas do plano de
testes (seu §8) e os resultados com horário de cada execução em `docs/test-evidence/`.

| Não … | … antes de | Situação | Evidência |
|---|---|---|---|
| Escrever requisitos | ter uma fonte de elicitação | ⚠️ parcialmente | O Termo v1.0 (19/08/2026) cita a observação da rotina da equipe como fonte; o primeiro `REQUIREMENTS.md` está no commit de base de 23/08; a entrevista é de 09/09 (simulada). Em 23/09 a origem de cada requisito foi reapontada para um item do Termo e para a resposta da entrevista (inspeção TR-01). A fonte existe agora; ela não precedeu a primeira versão. |
| Escolher a tecnologia | fechar o Termo | ⚠️ parcialmente | O Termo v1.0 é de 19/08, anterior ao primeiro código (23/08); a tecnologia, porém, foi herdada do artefato preexistente, e não escolhida depois do Termo. |
| Escolher a estrutura de dados | estimar o volume | ⚠️ parcialmente | Volumes estimados e estruturas medidas na Fase 2 (16/09, `docs/ALGORITHM_MEASUREMENTS.md`); algumas estruturas já existiam no código e foram confirmadas — ou, no caso da fila do rastreamento, registradas como sem ganho mensurável — por essa medição. |
| Desenhar a arquitetura | ter o modelo de domínio | ⚠️ parcialmente | O `ARCHITECTURE.md` existia desde 23/08 descrevendo a estrutura anterior; o modelo de domínio e a arquitetura em camadas chegaram juntos em `1aa5598` (16/09) e foram consolidados em `2dcbc8f` (23/09). |
| Abrir o editor de telas | ter os contratos de repositório declarados | ⚠️ não atendido historicamente | `public/index.php` (telas) está na base de 23/08; `app/src/Domain/Contract/` aparece em 16/09. O custo de que o roteiro avisa (regras dentro das telas) de fato ocorreu e foi **pago na Fase 3**: as regras foram movidas para casos de uso e para o domínio, e `Views` hoje não decide nada. |
| Implementar a integração | escrever o contrato de mensagens | ⚠️ não atendido historicamente · ✅ remediado | A integração PHP ⇄ Python existe desde 23/08; o contrato ficou apenas implícito no código até ser escrito em 14/10. Escrevê-lo expôs imediatamente quatro defeitos de integração (D-03, D-05, D-06, D-08) — exatamente a "tentativa e erro entre as duas pontas" que o roteiro prevê. |
| Executar o teste | escrever o resultado esperado | ✅ | Plano 2.0 redigido antes da execução 1 (2026-10-14 23:00 UTC); ST-24, ST-25 e ST-26 escritos antes do código que verificam; revisões do plano datadas (plano §8). |
| Fechar um defeito | reexecutar o caso que o revelou | ✅ | D-01…D-08 fechados apenas após a execução 2 (2026-10-14 23:13 UTC), D-09 e D-10 apenas após a execução 3 (2026-10-28 22:36 UTC); coluna *Verificado* do §3 do TEST_REPORT. |
| Escrever a documentação | — (documentar ao longo do caminho) | ✅ | A documentação foi atualizada em todas as fases; nas Fases 4–5 o contrato e o plano foram escritos antes da execução, a evidência registrada após cada execução, e os documentos consolidados junto com as correções. |

## 5. Checklists antes de cada entrega (roteiro §9)

### Antes da E3 — Aplicação e módulo

| Condição | Situação | Evidência |
|---|---|---|
| A aplicação compila e roda em emulador ou dispositivo físico | 🔄 ✅ | Aplicação web: roda no ambiente-alvo (XAMPP no Windows 11) e foi exercitada de ponta a ponta pelos 39 casos de sistema, injeção de falhas e navegador da execução 3. |
| A estrutura de pacotes reflete as camadas declaradas na E2 | ✅ | Passo 20. |
| Operação offline testada em modo avião, com sincronização verificada | 🔄 | Adaptação do passo 24: FI-02, FI-04, FI-08, `test_transport.py`. |
| O artefato físico ou a base de validação, se houver, está pronto e registrado | ✅ | Passo 25: `tests/e2e/lab_target.py`, fixtures, `evaluation/`. |

### Antes da E4 — Testes e documentação

| Condição | Situação | Evidência |
|---|---|---|
| Pelo menos um caso de teste por critério de aceite de alta prioridade | ✅ | TEST_PLAN §7; TR-02. |
| A bateria inclui casos de entrada inválida, não apenas de sucesso | ✅ | TR-03: 8 casos ST e todos os 10 casos FI. |
| Todo defeito bloqueante e alto corrigido e reverificado por reexecução | ✅ | Bloqueante D-02 e altos D-01, D-03, D-04, D-06, D-09, D-10 (e D-05, D-07, D-08) verificados por reexecução. |
| Os cinco documentos técnicos coerentes com o produto entregue | ✅ | §3.1. |

### Antes da defesa (Fase 6 — para planejamento)

| Condição | Situação | O que falta |
|---|---|---|
| Alguém de fora da equipe instalou o sistema usando apenas o manual | ⏳ | MT-04 / CA-07. O manual foi reescrito para isso; registrar cada pergunta que a pessoa fizer e corrigir o manual. |
| A apresentação foi ensaiada com cronômetro e cabe em 12 minutos | ⏳ | Fase 6, passo 34. |
| A demonstração foi testada no local e no equipamento da defesa | ⏳ | Fase 6. `tests/e2e/lab_target.py` oferece um alvo de demonstração reproduzível e seguro offline. |
| Todo integrante consegue responder sobre qualquer parte do trabalho | ⏳ | Equipe. |

## 6. Itens em aberto

1. **MT-04 / CA-07** — uma pessoa de fora da equipe instala o sistema usando apenas o
   [INSTALLATION_AND_USER_MANUAL.md](INSTALLATION_AND_USER_MANUAL.md) e executa uma análise;
   registrar no §6 do [TEST_REPORT.md](TEST_REPORT.md) e corrigir o manual a cada pergunta feita. É o
   único caso planejado não executado, e não pode ser automatizado.
2. **Fase 6** — apresentação, ensaio e demonstração no equipamento da defesa.

## 7. Notas sobre os documentos da disciplina (`docs/docsAula/`)

Os documentos da disciplina são a referência que este ciclo seguiu; eles **não** foram editados. A
conferência cruzada de 2026-10-28 encontrou os pontos abaixo, registrados aqui para a equipe:

| Documento | Observação | Efeito no produto |
|---|---|---|
| Termo de Referência, §3.2 itens 6 e 8 | Histórico "por período" e um "resumo" na exportação estavam no escopo acordado, mas não totalmente implementados. | Implementados (D-09, D-10); FR-06 e FR-12 alinhados. |
| Termo de Referência, §4 | O contrato de integração e o guia do desenvolvedor produzidos na Fase 5 não estão listados entre os entregáveis; a adaptação dos passos 23–25 do roteiro (§1 acima) não está na tabela de controle de mudanças. | Nenhum — documentado aqui e no repositório. |
| Entrevista de Requisitos, §6.2 | O checklist de encerramento ficou sem marcação, embora cada item tenha seu registro no documento (A2, B1, D2, E1, F1, G1, G2, H1, §5). | Nenhum. |
| Fase 2 (§5, §6) e Estruturas de Dados (§3) | Descrevem o mapa da comparação como indexado por *fingerprint*. Desde o D-01 a chave é a identidade do achado (fingerprint + endpoint + parâmetro); a estrutura — um mapa hash por lado — e sua medição não mudaram. | Registrado no [ALGORITHM_MEASUREMENTS.md](ALGORITHM_MEASUREMENTS.md), Decisão 4. |
| Fase 3, §5.2 e §6.1 | As contagens de testes (106 / 115) e a observação de que os adaptadores PDO nunca rodaram contra o MariaDB são de 23/09; ambas foram superadas pelos resultados da Fase 5. | Nenhum — os documentos são datados. |
