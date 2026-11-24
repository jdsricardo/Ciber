# Requisitos de Software e Rastreabilidade

Cada requisito traz uma prioridade, o **item do Termo de Referência (seção 3.2) de onde ele se
origina**, a resposta da entrevista que produziu esse item e o critério de aceite que o verifica. A
coluna de origem é a que o checklist da E1 exige: nenhum requisito é justificado por "a equipe
decidiu"; todos apontam para um item do Termo.

Os requisitos não funcionais trazem, além disso, a condição mensurável sob a qual são considerados
atendidos.

## Requisitos funcionais

| ID | Requisito | Prioridade | Origem (TR 3.2) | Fonte na entrevista | Critério de aceite |
|---|---|---|---|---|---|
| FR-01 | Registrar o nome de uma aplicação e sua URL base HTTP(S), com confirmação de autorização. | Alta | 1 | RF-001 (B1, G1) | CA-01 |
| FR-02 | Executar sob demanda o catálogo de verificações habilitado: 34 ids de verificação passivos em 7 famílias de plugins, mais 30 ids de verificação ativos em 13 famílias ativas seguras (64 no modo completo), cada um implementado como um plugin independente e orientado a objetos. | Alta | 2 | RF-002 (B2, C1, G1) | CA-01 |
| FR-03 | Armazenar alvo, categoria, CWE, OWASP Top 10:2025, referência WSTG, evidência estruturada, severidade, confiança, status e remediação. | Alta | 3 | RF-005 (F1, D3) | CA-02 |
| FR-04 | Calcular uma pontuação de 0 a 100 a partir dos achados ponderados. | Média | 4 | RF-007 (E2, F3) | CA-03 |
| FR-05 | Explicar o impacto para o desenvolvedor e uma correção acionável para cada achado, incluindo um exemplo concreto de código (ou de configuração do servidor) "vulnerável × corrigido". | Alta | 5 | RF-006 (D1, F1, F2) | CA-02 |
| FR-06 | Exibir o histórico de análises de cada aplicação, opcionalmente restrito a um período (datas inicial e final, ambas inclusivas). | Alta | 6 | RF-008 (E2, F3) | CA-05 |
| FR-07 | Comparar duas análises como novos, persistentes e corrigidos. | Alta | 7 | RF-008 (E2, F3) | CA-04 |
| FR-08 | Gerar um relatório completo para impressão de uma análise. | Média | 12 | RF-009 (F3, H1) | CA-06 |
| FR-09 | Informar uma confiança separada da severidade para cada achado e sinalizar os achados que exigem revisão manual. | Alta | 4 | RF-005 (F1, D3) | CA-02 |
| FR-10 | Testar os campos de formulário descobertos via POST (não apenas parâmetros da query string) nos detectores ativos de injeção de valor (SQLi, XSS, path traversal, open redirect, command injection, SSTI, SSRF). | Alta | 2 | RF-003 (H1) | CA-01 |
| FR-11 | Opcionalmente anexar uma credencial de sessão (cookie/cabeçalho *bearer*) a toda requisição para avaliar áreas autenticadas, enviada apenas ao alvo autorizado e nunca persistida. | Média | 10 | RF-004 (G2, H1) | CA-01 |
| FR-12 | Exportar uma análise concluída em JSON legível por máquina — resumo (achados por severidade, achados que exigem revisão manual, pontuação), metadados da análise e todos os achados — e permitir que o desenvolvedor filtre os achados por severidade na página de resultados. | Média | 8, 11 | RF-009 (F3, H1) | CA-06 |
| FR-13 | Expandir a URL informada para a superfície de mesma origem alcançável e analisar cada página descoberta, seguindo apenas navegação somente leitura: links de logout e links que alteram estado nunca são seguidos. | Alta | 9 | RF-010 (C1, G1) | CA-01 |

Observação sobre o FR-10 (conferida no código em 2026-11-24): a sonda de um campo de formulário é
enviada à URL da página em que o formulário aparece, não ao `action` do formulário; formulários que
enviam para outro caminho não têm o seu tratador testado.

## Requisitos não funcionais

| ID | Requisito | Condição mensurável | Prioridade | Origem (TR 3.2) | Fonte na entrevista | Critério de aceite |
|---|---|---|---|---|---|---|
| NFR-01 | Um histórico de 1.000 achados é apresentado em até três segundos no ambiente de teste definido. | Tempo decorrido < 3.000 ms para 1.000 achados. | Alta | 6, 7 | RNF-004 (E2) | CA-05 |
| NFR-02 | Conteúdo fornecido pelo usuário é escapado; gravações usam SQL com *prepared statements*; ações POST usam tokens CSRF. | Zero saídas sem escape, zero comandos SQL concatenados e toda rota POST rejeitando uma requisição sem token válido. | Alta | 1, 2 | RNF-002 (G1) | CA-02 |
| NFR-03 | O motor envia duas requisições GET de baseline independentes e limitadas por página, lê no máximo 256 KiB por resposta, encerra após dez segundos por requisição e não explora os achados. | `BASELINE_REQUESTS = 2`; `max_response_bytes = 262144`; `request_timeout_seconds = 10.0`. | Alta | 2 | RNF-001 (G1) | CA-01 |
| NFR-04 | Alvos privados, de loopback, link-local e reservados são negados por padrão. | Uma análise de endereço não global falha com `ScopeViolation` enquanto `ALLOW_PRIVATE_TARGETS=false`. | Alta | 2 | RNF-001 (G1) | CA-01 |
| NFR-05 | A instalação é reproduzível a partir do manual fornecido. | Uma pessoa de fora da equipe instala e executa o sistema usando apenas o manual. | Média | — | — | CA-07 |
| NFR-06 | Conteúdo voltado ao usuário e documentação de engenharia são escritos em português do Brasil; identificadores CWE/OWASP/WSTG mantêm a forma padrão em inglês; o código-fonte é escrito em inglês. | Inspeção dos textos dos achados, da interface, das mensagens de erro e dos documentos. | Média | 5 | — | CA-02 |
| NFR-07 | Cabeçalhos de requisição sensíveis (Cookie, Authorization, chaves de API) são mascarados no log de execução e nunca persistidos. | O log não contém nenhum valor completo de credencial e nenhuma coluna persistida guarda um. | Alta | 10 | RNF-005 (G2) | CA-02 |
| NFR-08 | Uma nova verificação é adicionada como um plugin que implementa `ScannerPlugin`, sem alterar a lógica do orquestrador. | Um plugin registrado é executado sem nenhum código específico de vulnerabilidade acrescentado a `engine/runner.py`. | Média | 2 | RNF-003 (G2) | CA-01 |

Contagem de requisitos: 13 funcionais e 8 não funcionais, acima do mínimo de 12 e 5 definido para a
entrega E1.

Histórico do NFR-06: até 2026-11-24 ele declarava a documentação de engenharia em inglês. A pedido
da equipe, a documentação foi traduzida e o requisito passou a declará-la em português; o
código-fonte continua em inglês.

## Rastreabilidade com a arquitetura

Todo requisito de alta prioridade está mapeado para o componente que o realiza em
[ARCHITECTURE.md](ARCHITECTURE.md) e na seção 6.1 do documento da Fase 3. A base medida das
decisões de estrutura de dados por trás do NFR-01 está em
[ALGORITHM_MEASUREMENTS.md](ALGORITHM_MEASUREMENTS.md).

## Regra da pontuação

A pontuação começa em 100. Cada achado crítico, alto, médio ou baixo desconta 30, 15, 7 ou 2
pontos, respectivamente. O resultado é limitado ao intervalo 0–100. Essa regra, intencionalmente
simples e determinística, é adequada para comparação; não é uma medida universal da segurança de uma
aplicação.
