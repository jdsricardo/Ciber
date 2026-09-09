# SentinelScope — Artigo Científico (rascunho ABNT)

> **Nota de formatação (aplicar no editor de texto antes de entregar).** Este arquivo é o *conteúdo* do artigo. Ao transportá-lo para o Word/Google Docs, aplique a formatação ABNT do modelo da UNIASSELVI: papel A4; fonte Arial ou Times New Roman tamanho 12 (citações longas, notas, legendas e paginação em tamanho 10); margens superior e esquerda 3 cm, inferior e direita 2 cm; espaçamento entre linhas 1,5 no texto e simples nas citações com mais de três linhas, no resumo e nas referências; título das seções alinhado à esquerda e numerado em algarismos arábicos (NBR 6024); citações no sistema autor-data (NBR 10520:2023); referências alinhadas à esquerda, espaço simples, separadas entre si por um espaço em branco (NBR 6023:2018). A estrutura abaixo segue a NBR 6022:2018 (artigo em publicação técnica e/ou científica).

---

**PLATAFORMA WEB DE APOIO À ANÁLISE DE SEGURANÇA DE APLICAÇÕES ORIENTADA AO DESENVOLVEDOR: EXPLICABILIDADE DE ACHADOS E REDUÇÃO DE RUÍDO EM TESTES DINÂMICOS NÃO DESTRUTIVOS**

Ricardo José da Silva[^1]

[^1]: Acadêmico do curso de Engenharia de Software, Centro Universitário Leonardo da Vinci (UNIASSELVI). Turma EGS0011 — Experiência Profissional (TCC). E-mail: [inserir e-mail]. Orientador(a): [inserir nome do orientador].

---

## RESUMO

A avaliação de segurança de aplicações web costuma ocorrer de forma tardia e pontual em equipes de desenvolvimento que não dispõem de um profissional dedicado à segurança da informação. Com isso, vulnerabilidades permanecem desconhecidas até etapas avançadas do ciclo de vida do software, o que eleva o custo de correção. Ferramentas automatizadas de teste dinâmico (DAST) existem há décadas, mas a literatura registra que os desenvolvedores as subutilizam. Elas produzem grande volume de resultados de difícil interpretação, com muitos falsos positivos e pouca orientação de correção. Este trabalho apresenta o SentinelScope, uma plataforma web de apoio à análise de segurança pensada sob a ótica do desenvolvedor. Seu objetivo é identificar possíveis vulnerabilidades e apresentar cada achado com severidade, confiança, evidência e orientação prática de correção, de modo verificável e não destrutivo. A solução foi construída como uma aplicação PHP sem framework, apoiada por um motor de varredura em Python organizado em camadas. O motor reúne verificações passivas (34 checagens de transporte, cabeçalhos, cookies, CORS, cache, exposição de informação e de segredos) e verificações ativas seguras (injeção de SQL, XSS refletido, travessia de diretório, redirecionamento aberto, injeção de comando, SSTI, XXE, CRLF, host header, adulteração de verbo HTTP, injeção NoSQL, CORS e SSRF). Todas operam sob salvaguardas de escopo, orçamento de requisições e negação de alvos privados. Um diferencial central é separar a severidade, que expressa o impacto potencial, da confiança, que expressa a força da evidência. A esse desenho soma-se uma camada de explicabilidade, que traduz cada observação técnica em impacto para a aplicação e em recomendação de correção acessível, acompanhada de um exemplo de código "vulnerável → corrigido". A ferramenta também testa campos de formulário via POST e alcança áreas autenticadas por cabeçalho de sessão. A verificação foi conduzida por uma suíte de 94 testes automatizados, que exercitam cada plugin contra fixtures vulneráveis e seguros em um servidor HTTP local real. Conclui-se que uma ferramenta de apoio orientada à explicabilidade e à redução de ruído é tecnicamente viável no escopo acadêmico e ataca uma lacuna reconhecida entre a capacidade de detecção e a capacidade de ação do desenvolvedor. Como continuidade, propõe-se uma avaliação empírica comparativa contra aplicações deliberadamente vulneráveis.

**Palavras-chave:** segurança de aplicações web; teste dinâmico de segurança (DAST); OWASP Top 10; usabilidade de ferramentas de segurança; DevSecOps.

---

## 1 INTRODUÇÃO

O software tornou-se o principal meio pelo qual organizações prestam serviços, e a aplicação web permanece uma das superfícies de ataque mais expostas, por ser acessível pela rede pública e por concentrar dados sensíveis. À medida que o número de aplicações mantidas por uma mesma equipe cresce, cresce também a dificuldade de garantir que cada nova versão ou manutenção não introduza falhas de segurança. Em equipes que não contam com um profissional dedicado exclusivamente à segurança da informação, cenário comum em pequenas e médias operações de desenvolvimento, as verificações tendem a ocorrer de maneira pontual, e não a cada entrega. Como resultado, vulnerabilidades permanecem desconhecidas até etapas posteriores do ciclo de vida do software (McGRAW, 2006).

Esse adiamento tem custo. É princípio consolidado da engenharia de software que o custo de corrigir um defeito cresce à medida que ele avança pelas fases do ciclo de desenvolvimento, sendo substancialmente maior quando descoberto em produção do que quando detectado durante a construção (BOEHM, 1981). No caso específico da segurança, o defeito tardio vai além do retrabalho. Ele pode significar exposição indevida de informação, correções emergenciais e risco de incidente. Desse contexto emerge o movimento conhecido como *shift-left*, que propõe antecipar as atividades de verificação de segurança para as fases iniciais e recorrentes do desenvolvimento, aproximando-as da rotina de quem escreve o código (McGRAW, 2006; SHOSTACK, 2014).

A automação é o instrumento natural dessa antecipação. As ferramentas de *Dynamic Application Security Testing* (DAST), que analisam a aplicação em execução sem acesso ao código-fonte, existem há décadas. Ainda assim, a literatura empírica aponta de forma consistente duas limitações que reduzem sua adoção pelos desenvolvedores. A primeira é de eficácia. Estudos independentes mostram que scanners de caixa-preta divergem bastante entre si e deixam de detectar classes inteiras de vulnerabilidade, ao mesmo tempo em que geram falsos positivos (DOUPÉ; COVA; VIGNA, 2010; BAU et al., 2010; FONSECA; VIEIRA; MADEIRA, 2007). A segunda, mais determinante para este trabalho, é de usabilidade. Mesmo quando a ferramenta acerta, seus resultados costumam vir em linguagem técnica voltada ao especialista, sem explicar por que aquilo importa para a aplicação específica e como corrigir no código. Johnson et al. (2013), ao investigarem por que desenvolvedores não usam ferramentas de análise estática, identificam justamente o excesso de falsos positivos e a apresentação inadequada dos resultados como barreiras centrais; Green e Smith (2016) argumentam que ferramentas e APIs de segurança precisam ser projetadas para o desenvolvedor comum, e não para o especialista, sob pena de serem ignoradas.

Há, portanto, uma lacuna entre a **capacidade de detecção** das ferramentas e a **capacidade de ação** do desenvolvedor. É essa lacuna que este trabalho endereça.

### 1.1 Problema de pesquisa

Como oferecer a equipes de desenvolvimento sem especialista dedicado uma avaliação inicial de segurança de aplicações web que seja, ao mesmo tempo, automatizada, não destrutiva, incorporável à rotina e, sobretudo, apresentada de forma que o próprio desenvolvedor compreenda o risco e consiga corrigi-lo?

### 1.2 Objetivos

**Objetivo geral.** Desenvolver e verificar uma plataforma web de apoio à análise de segurança de aplicações, orientada ao desenvolvedor, que identifique possíveis vulnerabilidades por meio de verificações passivas e ativas não destrutivas e apresente cada achado com severidade, confiança, evidência e orientação prática de correção.

**Objetivos específicos.**

a) Levantar e organizar, a partir de padrões consolidados (OWASP Top 10, CWE, OWASP WSTG), um conjunto mínimo de verificações de segurança relevantes para aplicações web;

b) Projetar uma arquitetura em camadas que permita adicionar novas verificações sem alterar o núcleo do sistema e que imponha salvaguardas contra uso indevido (negação de alvos privados, controle de escopo e orçamento de requisições);

c) Implementar um modelo de pontuação que distinga explicitamente severidade de confiança, evitando que achados de forte impacto e evidência fraca sejam silenciosamente rebaixados;

d) Construir uma camada de apresentação que traduza cada achado em observação, impacto para a aplicação e recomendação de correção em linguagem acessível ao desenvolvedor;

e) Verificar o comportamento de cada verificação por meio de testes automatizados contra alvos vulneráveis e seguros controlados.

### 1.3 Justificativa

A relevância do tema nasce da combinação de dois fatores. De um lado, as vulnerabilidades web são críticas e estão sistematicamente catalogadas pelo OWASP Top 10 (OWASP, 2021). De outro, as ferramentas que deveriam mitigá-las são comprovadamente subutilizadas (JOHNSON et al., 2013; GREEN; SMITH, 2016). Ao deslocar o foco da simples detecção para a explicabilidade e a acionabilidade do achado, o trabalho se posiciona sobre uma lacuna reconhecida na literatura, com valor prático direto para o cenário descrito no termo de referência do projeto: uma equipe que mantém mais de cinco aplicações internas sem apoio especializado em segurança. No plano acadêmico, o trabalho articula três corpos de conhecimento em um artefato verificável: teste de segurança automatizado, taxonomias de vulnerabilidade e usabilidade de ferramentas de segurança.

### 1.4 Delimitação do escopo

Trata-se de uma ferramenta de apoio, e não de substituição de auditoria especializada ou de teste de intrusão profissional. Três frentes ficam deliberadamente fora do escopo. A primeira é a exploração automática ou destrutiva das vulnerabilidades, pois a proposta é comprovar a existência do problema com a evidência mínima necessária, sem comprometer disponibilidade, integridade ou dados. A segunda é a análise de código-fonte, já que a solução não pressupõe acesso ao repositório. A terceira é o monitoramento contínuo em tempo real. Além disso, a primeira versão limita-se ao conjunto de verificações implementado e não pretende detectar todas as classes de vulnerabilidade existentes. Estas delimitações são retomadas na Seção 6.

## 2 REFERENCIAL TEÓRICO

### 2.1 Segurança de aplicações web e o custo do defeito tardio

Construir segurança dentro do software, em vez de acoplá-la ao final, é a tese central da disciplina de segurança de software (McGRAW, 2006; VIEGA; McGRAW, 2001). Essa perspectiva se contrapõe ao modelo em que a segurança é tratada como uma etapa de auditoria posterior à construção. O argumento econômico que a sustenta é clássico: o custo de remover um defeito cresce de forma acentuada conforme ele avança pelas fases do ciclo de vida (BOEHM, 1981). Aplicado à segurança, isso quer dizer que uma falha detectada durante o desenvolvimento é muito mais barata de corrigir do que a mesma falha explorada em produção. O movimento *DevSecOps* e a prática de *shift-left security* colocam essa ideia em operação, integrando verificações de segurança automatizadas ao fluxo contínuo de desenvolvimento e entrega (SHOSTACK, 2014).

### 2.2 Padrões e taxonomias de vulnerabilidade

Para que achados de segurança sejam comparáveis, rastreáveis e verificáveis, é necessário ancorá-los em taxonomias reconhecidas. Quatro referências estruturam este trabalho:

a) **OWASP Top 10** — lista consensual das dez categorias de risco mais críticas para aplicações web, amplamente adotada na indústria como linha de base de conscientização e priorização (OWASP, 2021). O SentinelScope mapeia cada achado a uma categoria do Top 10, acompanhando a revisão de 2025 do documento.

b) **CWE (Common Weakness Enumeration)** — catálogo mantido pela MITRE que identifica *tipos de fraqueza* de software por meio de identificadores estáveis (por exemplo, CWE-89 para injeção de SQL), permitindo precisão maior do que a categorização genérica do Top 10 (MITRE, 2024).

c) **OWASP Web Security Testing Guide (WSTG)** — guia metodológico que descreve *como testar* cada classe de vulnerabilidade, com identificadores versionados (por exemplo, WSTG-INPV-05 para injeção de SQL), usado aqui para ancorar a técnica de cada verificação (OWASP, 2020).

d) **CVSS (Common Vulnerability Scoring System)** — padrão da FIRST para expressar a severidade de uma vulnerabilidade de modo estruturado (FIRST, 2019). Embora o SentinelScope adote um esquema de severidade simplificado e determinístico (Seção 5.4), a lógica de separar *impacto potencial* de outras dimensões dialoga diretamente com a filosofia do CVSS.

Complementarmente, o NIST SP 800-115 fornece o enquadramento metodológico do teste de segurança técnico, distinguindo técnicas de revisão, identificação de alvos e validação de vulnerabilidades, e enfatizando a necessidade de autorização explícita e de controle de escopo (SCARFONE et al., 2008) — princípio incorporado às salvaguardas da ferramenta.

### 2.3 Teste de segurança automatizado: SAST, DAST e os limites do scanner de caixa-preta

Duas grandes abordagens automatizadas coexistem. O *Static Application Security Testing* (SAST) analisa o código-fonte sem executá-lo. Já o *Dynamic Application Security Testing* (DAST) analisa a aplicação em execução, observando e provocando seu comportamento pela interface externa, sem necessariamente acessar o código (BAU et al., 2010). As duas têm pontos cegos complementares. O SAST enxerga o código, mas não o comportamento em tempo de execução; o DAST enxerga o comportamento, mas não a causa no código. O SentinelScope se situa na abordagem DAST, coerente com a delimitação de não pressupor acesso ao repositório.

Uma consequência prática dessa escolha é que o DAST exige uma instância da aplicação em execução e acessível ao scanner. Isso não significa, porém, que a aplicação precise estar publicada na internet. Na rotina de desenvolvimento, o alvo pode ser a própria máquina do desenvolvedor (por exemplo, um endereço de *localhost*), um servidor de homologação interno ou um ambiente efêmero criado por um *pipeline* de integração contínua. É por essa razão que o motor prevê, como opção explícita de laboratório, a análise de alvos em rede privada (Seção 3.3). Assim, o modelo de uso permanece compatível com o *shift-left*: testa-se cedo e com frequência, tão logo exista um build executável, sem depender de uma implantação pública.

A eficácia dos scanners DAST de caixa-preta, no entanto, é limitada e desigual. Doupé, Cova e Vigna (2010), em avaliação que ficou conhecida pelo título "Why Johnny Can't Pentest", demonstraram que os scanners automáticos falham de forma sistemática ao lidar com o estado da aplicação e deixam de alcançar partes relevantes da superfície de ataque. Bau et al. (2010) e Fonseca, Vieira e Madeira (2007) documentaram ampla variação de cobertura entre ferramentas, além da coexistência de falsos negativos e falsos positivos, sobretudo em injeção de SQL e XSS. Antunes e Vieira (2010) propuseram *benchmarks* para tornar essa comparação metodologicamente rigorosa. A lição para este trabalho é dupla. Primeiro, nenhuma ferramenta automatizada deve ser apresentada como garantia de ausência de vulnerabilidades, o que fundamenta o posicionamento de apoio. Segundo, reduzir falsos positivos e qualificar a confiança de cada achado não são refinamentos opcionais, e sim requisitos centrais de utilidade.

### 2.4 O fator humano: usabilidade das ferramentas de segurança

A terceira base teórica desloca o foco da máquina para a pessoa. Mesmo ferramentas tecnicamente competentes fracassam quando seus resultados não são acionáveis. Johnson et al. (2013), em estudo qualitativo com desenvolvedores, concluíram que a subutilização das ferramentas de análise decorre principalmente de dois fatores: o volume de falsos positivos e a forma como os resultados são comunicados, sem explicação suficiente e sem integração com o fluxo de trabalho. Bessey et al. (2010), relatando anos de uso industrial de análise estática, reforçam que a confiança do desenvolvedor no resultado é um recurso frágil. Poucos falsos positivos ruidosos já bastam para que a ferramenta seja abandonada. Smith et al. (2015) mapearam as perguntas que os desenvolvedores fazem ao diagnosticar um alerta de segurança e revelaram que a informação de que eles precisam raramente é a que as ferramentas oferecem. Acar et al. (2016) mostraram, de forma experimental, que a fonte de informação usada pelo desenvolvedor influencia diretamente a segurança do código produzido. É uma evidência de que orientação clara e correta embutida na ferramenta tem efeito prático mensurável. Green e Smith (2016) resumem esse conjunto em um princípio de projeto: "desenvolvedores não são o inimigo". A segurança utilizável precisa encontrá-los onde eles estão, com linguagem e exemplos que compreendam.

Essa literatura fundamenta a hipótese de projeto do SentinelScope: para o desenvolvedor, o valor de um achado de segurança não está apenas em detectá-lo, mas em explicá-lo e torná-lo corrigível. A separação entre severidade e confiança, a supressão de sinais instáveis e a apresentação em três camadas (o que se observou, por que importa e como corrigir) são respostas diretas às barreiras identificadas por Johnson et al. (2013) e Green e Smith (2016).

## 3 METODOLOGIA

### 3.1 Classificação da pesquisa

Quanto à natureza, esta é uma **pesquisa aplicada**, pois gera um artefato de software destinado a uso prático (GIL, 2002; PRODANOV; FREITAS, 2013). Quanto aos objetivos, é **exploratória e descritiva** (GIL, 2002). Quanto ao procedimento, adota o método de **pesquisa de desenvolvimento (ou pesquisa-artefato)**, no qual o conhecimento é produzido pela construção e avaliação de um artefato tecnológico que responde a um problema real (WAZLAWICK, 2014). A abordagem é predominantemente **qualitativa** na concepção e **quantitativa** na verificação (contagem de verificações, cobertura de testes e, como trabalho futuro, métricas de detecção).

### 3.2 Materiais e ambiente

A plataforma foi construída com PHP 8.2 (sem framework), Python 3.10 (sem dependências externas ao interpretador padrão), banco de dados MariaDB 10.4 e interface em HTML e CSS sem framework de front-end. A opção deliberada por não utilizar frameworks visou manter o código auditável e explícito, adequado a um trabalho acadêmico em que cada decisão precisa ser justificável, e reduzir a superfície de dependências de terceiros. O ambiente de desenvolvimento e teste utilizou a pilha XAMPP sobre Windows 11. O controle de versão foi feito com Git. A redação, a estrutura e a apresentação deste artigo seguem as normas da Associação Brasileira de Normas Técnicas para trabalhos acadêmicos e artigos científicos (ABNT, 2011, 2018, 2023).

### 3.3 Princípios éticos e de segurança do próprio artefato

Uma ferramenta de teste de segurança é, por definição, de uso dual. Adotaram-se três princípios inegociáveis, alinhados ao NIST SP 800-115 (SCARFONE et al., 2008): (i) **autorização explícita** — o registro de um alvo exige confirmação de propriedade ou autorização; (ii) **não destrutividade** — nenhuma verificação explora, enumera ou altera dados, parando na evidência mínima necessária para comprovar a existência da falha; (iii) **contenção técnica** — alvos em redes privadas, de loopback e reservadas são negados por padrão (mitigando o risco de a própria ferramenta ser usada para SSRF), o escopo é fixado ao host e porta autorizados, e há orçamento máximo de requisições e tempo por análise.

### 3.4 Método de verificação

A verificação seguiu a estratégia de **testes automatizados com fixtures controlados**, organizada em níveis (unidade, integração e aceitação) segundo a prática consolidada de teste de software (PRESSMAN; MAXIM, 2016): para cada verificação implementada, construiu-se pelo menos um alvo deliberadamente vulnerável e um alvo seguro/endurecido, servidos por um servidor HTTP local real (sockets reais, tempo real, bytes reais na rede), de modo que um teste aprovado signifique que a verificação funciona contra um servidor de fato, e não apenas contra objetos de resposta fabricados em memória. Essa decisão metodológica responde diretamente ao risco de falsos positivos discutido na Seção 2.3. A cobertura e os resultados são apresentados na Seção 5.

## 4 DESENVOLVIMENTO: A PLATAFORMA SENTINELSCOPE

### 4.1 Visão geral e arquitetura em camadas

O SentinelScope adota uma arquitetura em camadas com implantação local. O navegador comunica-se com uma aplicação PHP que valida entradas, orquestra as análises, renderiza os resultados e persiste os dados por meio de *prepared statements* nativos do PDO. Sob demanda, a aplicação PHP invoca um processo Python separado, que executa a requisição HTTP controlada e retorna um documento JSON estruturado. O MariaDB armazena aplicações, análises e achados, em um modelo relacional `aplicações 1—N análises 1—N achados`, com índices que sustentam a consulta de histórico e a comparação (Seção 4.7).

A separação entre a aplicação web (PHP) e o motor de varredura (Python) não é acidental. Ela isola o componente que executa requisições potencialmente sensíveis em um processo com fronteira e orçamento próprios. Também permite que o motor evolua e seja testado de forma independente da camada de apresentação. Trata-se da aplicação direta dos princípios de baixo acoplamento e alta coesão da engenharia de software (PRESSMAN; MAXIM, 2016; SOMMERVILLE, 2018).

### 4.2 O motor de varredura

O motor Python foi projetado para que **adicionar uma nova verificação nunca exija tocar no núcleo**. Ele se organiza nos seguintes módulos:

- **Modelo de dados tipado** (`engine/models.py`): representações compartilhadas de requisição, resposta, ponto de entrada, evidência, achado, contexto de página e limites, usadas por todos os plugins;
- **Descoberta** (`engine/discovery.py`): identificação estável de pontos de entrada por localização e nome, a partir da *query string* e de formulários HTML;
- **Normalização** (`engine/normalization.py`): remoção de conteúdo volátil (carimbos de tempo, UUIDs, valores aleatórios longos, *nonces* e *tokens* CSRF) antes de qualquer comparação, e inferência do contexto da página (possui formulários, campo de senha, aparenta estar autenticada) para manter a severidade proporcional;
- **Segurança/transporte** (`engine/safety.py`, `engine/transport.py`): o único caminho autorizado a realizar uma requisição HTTP, responsável por fixação de host e porta, verificação de re-resolução de DNS, negação de rede privada, limitação de taxa, orçamentos de requisição e tempo, arquivo de cancelamento, limite de tamanho de resposta e registro de requisições em JSONL com cabeçalhos sensíveis redigidos;
- **Confiança** (`engine/confidence.py`): o único ponto que converte força da evidência, reprodutibilidade e ambiguidade em uma pontuação de confiança de 0 a 100 e em um *status* (Seção 4.4);
- **Orquestrador** (`engine/runner.py`): coleta as requisições de *baseline*, constrói o contexto de página e executa cada plugin registrado; não contém lógica específica de nenhuma vulnerabilidade.

### 4.3 Plugins passivos e ativos seguros

Cada família de vulnerabilidade é implementada como uma classe de plugin que declara seus próprios metadados (categoria, CWE, OWASP, WSTG, tipo e risco operacional) e o conjunto de identificadores de verificação que possui, ancorados nos catálogos internacionais correspondentes (OWASP, 2021; MITRE, 2024; OWASP, 2020). Duas modalidades coexistem:

a) **Passivos** (34 verificações): observam as respostas de *baseline* sem enviar cargas de teste. Cobrem segurança de transporte e TLS, cabeçalhos de segurança, atributos de cookies, CORS, políticas de cache, exposição de informação e exposição de segredos (formatos de credencial de alta assinatura mais uma heurística baseada em entropia que ignora tokens rotativos por requisição).

b) **Ativos seguros** (*safe-active*): enviam cargas de teste não destrutivas contra parâmetros já descobertos, encerrando na evidência mínima necessária. Estão implementados plugins para injeção de SQL, XSS refletido, travessia de diretório, redirecionamento aberto, injeção de comando, injeção em template do lado do servidor (SSTI), XXE, injeção de CRLF, injeção de *host header*, adulteração de verbo HTTP, injeção NoSQL, CORS ativo e SSRF.

O teste de parâmetros é agnóstico à sua origem: uma abstração central (`send_probe`) roteia o *probe* para o canal correto — parâmetros de *query string* trafegam na URL (GET) e campos de formulário são submetidos no corpo (POST) —, de modo que um plugin testa um parâmetro sem precisar saber onde ele reside. Nesta versão, o teste de campos de formulário via POST está habilitado para todos os detectores de injeção de valor — injeção de SQL, XSS refletido, travessia de diretório, redirecionamento aberto, injeção de comando, SSTI e SSRF; os detectores de CRLF (reflexão em cabeçalho) e injeção NoSQL (mutação da chave `campo[$ne]`) permanecem restritos à *query string* por construírem o *probe* de forma específica ao canal.

Um exemplo ilustra o rigor do modo ativo. Seguindo as orientações de teste do OWASP WSTG (OWASP, 2020), o plugin de injeção de SQL tenta as técnicas em ordem crescente de custo: primeiro a baseada em erro, depois a diferencial booleana e, por fim, a baseada em tempo. A cadeia para na primeira técnica que produz evidência confirmada, e o plugin nunca enumera tabelas nem extrai registros. A técnica de diferencial booleano compara uma condição logicamente verdadeira (`' AND '1'='1`), que deve manter a resposta equivalente à *baseline*, com uma condição falsa (`' AND '1'='2`), que deve divergir, além de um *probe* de controle inócuo. Essa construção evita um erro comum: usar `OR '1'='1'` em um parâmetro cujo valor de *baseline* já é verdadeiro, o que nunca divergiria e levaria a uma conclusão inválida.

### 4.4 Confiança separada de severidade

Uma das contribuições centrais do trabalho é tratar severidade e confiança como dimensões independentes. Essa distinção dialoga com a filosofia do CVSS, que expressa o impacto de uma vulnerabilidade de modo estruturado e separado de outras dimensões (FIRST, 2019). A severidade responde à pergunta "quão grave seria isto se fosse verdadeiro". A confiança responde a outra: "quão seguro o detector está de que é verdadeiro". Um achado crítico com evidência fraca permanece como crítico de baixa confiança. Ele nunca é rebaixado em silêncio para uma severidade menor apenas para compensar a incerteza, uma prática que esconderia riscos reais do desenvolvedor.

A confiança é calculada por uma combinação ponderada de fatores de evidência e de instabilidade:

confiança = 0,35·(força da evidência) + 0,25·(reprodutibilidade) + 0,20·(qualidade diferencial) + 0,20·(confirmação independente) − 0,30·(instabilidade) − 0,20·(ambiguidade)

O resultado, limitado ao intervalo de 0 a 100, é traduzido em um *status* legível: *confirmado*, *alta confiança*, *provável*, *possível*, *informativo* ou *revisão manual necessária*. Por construção, verificações puramente passivas e de observação única não alcançam o *status* "confirmado", reservado a detecções ativas que reproduzem o resultado por uma técnica independente. Esse desenho responde diretamente à advertência de Bessey et al. (2010) e Johnson et al. (2013) sobre o custo dos falsos positivos. Em vez de afirmar mais do que a evidência sustenta, a ferramenta comunica de forma explícita o seu grau de certeza e sinaliza o que exige revisão humana.

### 4.5 Redução de ruído e proporcionalidade

Antes de qualquer comparação entre respostas, a normalização remove o conteúdo volátil que, se fosse ignorado, geraria diferenças espúrias e, portanto, falsos positivos. Alguns sinais são instáveis, como um texto de erro presente em apenas uma de duas requisições de *baseline* ou um valor de alta entropia que muda a cada requisição (um token rotativo). Nesses casos, o achado é rebaixado a "revisão manual necessária" ou excluído, em vez de confirmado. O contexto de página mantém a severidade proporcional. Uma resposta que não é HTML, por exemplo, não é penalizada pela ausência de *Content-Security-Policy*. No plano técnico, essas decisões concretizam o requisito de utilidade discutido na Seção 2.4.

### 4.6 Camada de explicabilidade

A interface apresenta cada achado em três camadas de leitura crescente, deliberadamente ordenadas para o desenvolvedor:

1. **O que o scanner observou** — a evidência factual, sem jargão;
2. **Por que isso importa para sua aplicação** — o impacto traduzido para consequência prática;
3. **Como corrigir** — a recomendação de mitigação acionável, acompanhada de um **exemplo concreto de código "vulnerável → corrigido"** (código de aplicação em PHP ou configuração de servidor em `.htaccess`, conforme a natureza do achado).

O exemplo de correção é o que distingue a explicabilidade proposta. Em vez de descrever a correção de forma abstrata, a ferramenta a mostra. Cada verificação que um plugin pode emitir tem um par de trechos, escrito uma única vez em uma tabela central (`plugins/remediation_examples.py`) e mesclado a todo achado no momento de sua construção. Essa decisão responde diretamente às conclusões de Smith et al. (2015) sobre as perguntas que o desenvolvedor faz diante de um alerta, muitas vezes "como eu conserto isto no meu código?". Responde também ao efeito demonstrado por Acar et al. (2016): a fonte de informação embutida na ferramenta influencia a segurança do código produzido.

Abaixo dessas camadas, um painel recolhível de contexto técnico reúne o identificador da verificação, a taxonomia completa (categoria, CWE, OWASP e WSTG), a URL e o parâmetro afetados e a evidência estruturada em JSON, para quem quiser aprofundar. Severidade e confiança aparecem como selos distintos. Esse formato concretiza o princípio de Green e Smith (2016): a informação de que o desenvolvedor precisa vem primeiro, na linguagem dele, enquanto o detalhe para o especialista fica disponível, porém em segundo plano.

### 4.7 Varredura autenticada

Boa parte da superfície de risco de uma aplicação só fica acessível após a autenticação. Para alcançá-la sem acoplar um mecanismo de *login* específico, o motor aceita cabeçalhos de autenticação, em geral um *cookie* de sessão ou um *token* Bearer, e os anexa a toda requisição, passiva ou ativa, no único ponto de saída HTTP autorizado. Por construção, esses cabeçalhos só trafegam para o host e a porta fixados pelo controle de escopo e são ocultados no registro de requisições. Na aplicação web, eles são usados de forma transitória em uma única análise e nunca ficam armazenados. Dessa forma, uma extensão pequena e localizada habilita a varredura autenticada para todas as verificações de uma vez, sem alterar nenhum plugin.

### 4.8 Pontuação, histórico e comparação

Cada análise concluída recebe uma Pontuação de Segurança de 0 a 100, calculada por uma regra determinística. A pontuação parte de 100 e cada achado crítico, alto, médio ou baixo desconta 30, 15, 7 e 2 pontos, respectivamente, com o resultado limitado ao intervalo de 0 a 100. A regra é propositalmente simples e reprodutível, adequada à comparação entre análises da mesma aplicação. Ela não pretende ser uma medida universal de segurança, e essa limitação é assumida de forma explícita na interface e neste artigo. O histórico por aplicação e a comparação entre duas análises sustentam o uso incremental da ferramenta ao longo das entregas: cada achado recebe uma impressão digital estável, o que permite classificá-lo como *novo*, *ainda presente* ou *corrigido*. Para integrar-se ao fluxo de trabalho da equipe, a interface também permite filtrar os achados por severidade, copiar o exemplo de correção com um clique e exportar a análise concluída em JSON legível por máquina, adequado a *pipelines* de integração contínua e a sistemas de tíquetes.

### 4.9 Salvaguardas de segurança da aplicação

A própria aplicação foi construída sob as mesmas práticas que ela verifica, em coerência com o princípio de embutir segurança desde o projeto (McGRAW, 2006; OWASP, 2021). As operações que alteram dados exigem um *token* CSRF vinculado à sessão. Toda a saída passa por codificação, o que mitiga o XSS armazenado. E todo acesso ao banco usa *prepared statements* nativos, o que previne a injeção de SQL. A versão acadêmica pressupõe uma instalação local, monousuário e confiável; para qualquer implantação compartilhada, recomendam-se autenticação e controle de acesso por papéis.

## 5 AVALIAÇÃO E DISCUSSÃO

### 5.1 Estratégia de verificação e resultados dos testes automatizados

A verificação funcional foi conduzida por uma suíte de **94 testes automatizados** em Python (framework `unittest`), complementada por **40 verificações no lado PHP**. A suíte cobre os níveis clássicos de teste (PRESSMAN; MAXIM, 2016): a fundação do motor (`test_engine.py`), cada plugin contra fixtures vulnerável e seguro (`test_plugins.py` e os testes por plugin ativo), a integração catálogo/orquestrador (`test_scanner.py`), a camada de exemplos de correção (`test_remediation_examples.py`), o arcabouço de avaliação empírica (`test_evaluation.py`), a varredura autenticada e o teste de formulários via POST (`test_authenticated_and_forms.py`), o retry do transporte em falhas transitórias (`test_transport.py`), e as classes puras do lado PHP — renderização, exemplos de código, cálculo de pontuação, comparação de análises e um benchmark de 1.000 achados (`php_test.php`). Na execução de referência, os 94 testes Python foram aprovados (resultado "OK"), em tempo total da ordem de 180 segundos — tempo dominado pelos testes de detecção baseada em tempo, que empregam atrasos reais na rede para exercitar a lógica temporal de forma fidedigna.

Cada plugin passivo é testado, no mínimo, com: um fixture vulnerável, um fixture endurecido e um caso sensível ao contexto (por exemplo, uma resposta não-HTML não é penalizada por ausência de CSP; um padrão de *stack trace* visto em apenas uma de duas *baselines* é rebaixado a "revisão manual necessária" em vez de confirmado; um valor de alta entropia que muda entre *baselines* é tratado como token rotativo, e não como segredo estático). Essa cobertura evidencia empiricamente o comportamento de **redução de falsos positivos** descrito na Seção 4.5.

Quadro 1 — Casos de teste representativos e resultado.

| Caso | Resultado esperado | Situação |
|---|---|---|
| Varredura passiva de resposta controlada | 34 verificações concluídas; achados persistidos com severidade, confiança e status | Teste automatizado fornecido — aprovado |
| Verificação de completude do achado | Categoria, CWE, OWASP, WSTG, severidade, confiança, evidência, impacto e remediação presentes | Testes de plugin/scanner fornecidos — aprovados |
| Proteção contra SSRF | Alvo privado negado por padrão | Teste automatizado fornecido — aprovado |
| Redução de falso positivo | Sinal instável (erro em uma só baseline, token rotativo) rebaixado ou excluído, não confirmado | Testes de plugin fornecidos — aprovados |
| Consistência plugin/catálogo | Cada entrada do catálogo é declarada por exatamente um plugin; todo plugin declara metadados completos | Teste automatizado fornecido — aprovado |

Fonte: o autor (2026).

### 5.2 Discussão

Os resultados sustentam a viabilidade técnica da proposta e, principalmente, a viabilidade do seu diferencial. É possível construir, no escopo de um trabalho acadêmico, um motor DAST não destrutivo que qualifica a confiança de cada achado e reduz o ruído por normalização e verificação de estabilidade. A cobertura de testes inclui fixtures seguros, e não apenas vulneráveis. Essa é a evidência de que a ferramenta foi projetada para não soar o alarme diante de configurações corretas, um requisito que a literatura aponta como decisivo para a adoção (JOHNSON et al., 2013; BESSEY et al., 2010).

Cabe, porém, distinguir com honestidade o que foi verificado do que ainda não foi. Os testes comprovam que cada verificação funciona como especificado contra alvos controlados. Eles ainda não medem o desempenho da ferramenta contra uma aplicação real e desconhecida, ou seja, sua taxa de detecção (revocação, do inglês *recall*) e sua taxa de acerto entre os alertas emitidos (precisão, do inglês *precision*) em condições não controladas. Essa é a fronteira entre o que este trabalho entrega e o que a Seção 5.3 propõe.

### 5.3 Proposta de avaliação empírica (trabalho de continuidade)

Para elevar a evidência de "funciona como especificado" a "detecta com que eficácia", propõe-se uma avaliação empírica comparativa, seguindo a tradição metodológica de Fonseca, Vieira e Madeira (2007), Bau et al. (2010) e Antunes e Vieira (2010):

a) **Alvos.** Aplicações deliberadamente vulneráveis de referência — *Damn Vulnerable Web Application* (DVWA), *OWASP Juice Shop* e *OWASP WebGoat* — executadas em laboratório isolado e autorizado;

b) **Base de comparação (baseline).** OWASP ZAP em modo *baseline* (OWASP, 2024), ferramenta livre amplamente utilizada, como referência de mercado;

c) **Métricas.** Para cada classe de vulnerabilidade conhecida no alvo, apurar verdadeiros positivos, falsos positivos e falsos negativos, derivando precisão (*precision*), revocação (*recall*) e a medida F1, além do tempo de execução e do número de requisições emitidas;

d) **Variável qualitativa (o diferencial da tese).** Avaliação da explicabilidade dos achados por um pequeno grupo de desenvolvedores, medindo se a apresentação em três camadas reduz o tempo até a compreensão do risco e da correção em relação à saída de uma ferramenta convencional — instrumento inspirado nas questões levantadas por Smith et al. (2015) e no princípio de Green e Smith (2016).

O Quadro 2 apresenta a estrutura de coleta a ser preenchida com os dados reais dessa etapa.

Quadro 2 — Modelo de tabulação da avaliação empírica proposta (a preencher).

| Classe (CWE) | Presente no alvo | SentinelScope: VP/FP/FN | ZAP baseline: VP/FP/FN | Precision/Recall/F1 |
|---|---|---|---|---|
| Injeção de SQL (CWE-89) | — | — | — | — |
| XSS refletido (CWE-79) | — | — | — | — |
| Travessia de diretório (CWE-22) | — | — | — | — |
| ... | — | — | — | — |

Fonte: o autor (2026).

### 5.4 Ameaças à validade e limitações

Reconhecem-se quatro limitações. A primeira é de construção: o esquema de pontuação é uma heurística de comparação, não uma medida absoluta de segurança. A segunda é de cobertura: o conjunto de verificações é finito e não detecta todas as classes de vulnerabilidade. Falhas de lógica de negócio e vulnerabilidades que dependem de estado autenticado complexo estão além do alcance de um scanner de caixa-preta, como já demonstraram Doupé, Cova e Vigna (2010). A terceira é de avaliação: como discutido, a eficácia em alvos reais ainda não foi medida (Seção 5.3). A quarta é de generalização: os testes automatizados usam alvos controlados construídos pelo próprio autor, o que torna necessária a avaliação independente proposta para reduzir o viés. Essas limitações não invalidam a contribuição, mas delimitam com precisão o alcance das conclusões. Essa é, aliás, a postura que a própria literatura de scanners recomenda como antídoto ao exagero de capacidade (BAU et al., 2010).

## 6 CONSIDERAÇÕES FINAIS

Este trabalho partiu de um problema concreto e recorrente: equipes de desenvolvimento sem apoio especializado em segurança, que verificam suas aplicações de forma tardia e pontual. Partiu também de uma lacuna reconhecida na literatura, a distância entre a capacidade de detectar vulnerabilidades e a capacidade de o desenvolvedor agir sobre elas. A resposta construída, o SentinelScope, é uma plataforma DAST de apoio, não destrutiva. Ela ancora seus achados em taxonomias consolidadas (OWASP Top 10, CWE e WSTG), separa de forma explícita a severidade da confiança, reduz o ruído por normalização e verificação de estabilidade e, acima de tudo, apresenta cada achado em uma camada de explicabilidade orientada à correção.

Os objetivos específicos foram atendidos: levantou-se e organizou-se um conjunto de 34 verificações passivas e 13 famílias de verificações ativas seguras ancoradas em padrões; projetou-se uma arquitetura em camadas extensível e com salvaguardas; implementou-se o modelo de confiança separado da severidade; construiu-se a camada de explicabilidade em três níveis, com exemplos de código de correção; e verificou-se o comportamento por uma suíte de 94 testes automatizados em Python (mais 40 verificações PHP) aprovados contra fixtures vulneráveis e seguros. O objetivo geral — uma avaliação de segurança automatizada, não destrutiva e compreensível pelo desenvolvedor — foi demonstrado como tecnicamente viável no escopo acadêmico.

A principal contribuição não está em detectar mais do que as ferramentas existentes, mas em **comunicar melhor** o que se detecta, atacando a barreira de usabilidade que a literatura identifica como causa central da subutilização das ferramentas de segurança (JOHNSON et al., 2013; GREEN; SMITH, 2016). Reforçando essa contribuição, a camada de explicabilidade foi ampliada com exemplos de código "vulnerável → corrigido" por verificação (Seção 4.6), a varredura passou a alcançar áreas autenticadas por meio de cabeçalhos de sessão (Seção 4.7) e o teste de parâmetros passou a cobrir campos de formulário via POST nos detectores de maior valor (Seção 4.3). Como continuidade, destacam-se: (i) a execução da avaliação empírica comparativa proposta na Seção 5.3, com métricas de *precision/recall/F1* contra alvos de referência e uma baseline de mercado; (ii) a extensão do teste via POST aos demais detectores ativos; (iii) a automação de sequências de *login* (formulário e OAuth) além do cabeçalho de sessão já suportado; e (iv) a introdução de autenticação e controle de acesso por papéis para uso multiusuário da própria ferramenta. Conclui-se que o tema é relevante, plausível e viável como trabalho de conclusão de curso, e que o artefato produzido oferece base sólida tanto para a defesa acadêmica quanto para evolução prática.

## REFERÊNCIAS

ACAR, Yasemin et al. You Get Where You're Looking For: The Impact of Information Sources on Code Security. In: IEEE SYMPOSIUM ON SECURITY AND PRIVACY (S&P), 2016, San Jose. **Proceedings** [...]. Los Alamitos: IEEE, 2016. p. 289-305.

ANTUNES, Nuno; VIEIRA, Marco. Benchmarking Vulnerability Detection Tools for Web Services. In: IEEE INTERNATIONAL CONFERENCE ON WEB SERVICES (ICWS), 2010, Miami. **Proceedings** [...]. Los Alamitos: IEEE, 2010. p. 203-210.

ASSOCIAÇÃO BRASILEIRA DE NORMAS TÉCNICAS. **NBR 6022**: informação e documentação: artigo em publicação periódica técnica e/ou científica: apresentação. Rio de Janeiro: ABNT, 2018.

ASSOCIAÇÃO BRASILEIRA DE NORMAS TÉCNICAS. **NBR 6023**: informação e documentação: referências: elaboração. Rio de Janeiro: ABNT, 2018.

ASSOCIAÇÃO BRASILEIRA DE NORMAS TÉCNICAS. **NBR 10520**: informação e documentação: citações em documentos: apresentação. Rio de Janeiro: ABNT, 2023.

ASSOCIAÇÃO BRASILEIRA DE NORMAS TÉCNICAS. **NBR 14724**: informação e documentação: trabalhos acadêmicos: apresentação. Rio de Janeiro: ABNT, 2011.

BAU, Jason et al. State of the Art: Automated Black-Box Web Application Vulnerability Testing. In: IEEE SYMPOSIUM ON SECURITY AND PRIVACY (S&P), 2010, Oakland. **Proceedings** [...]. Los Alamitos: IEEE, 2010. p. 332-345.

BESSEY, Al et al. A few billion lines of code later: using static analysis to find bugs in the real world. **Communications of the ACM**, New York, v. 53, n. 2, p. 66-75, 2010.

BOEHM, Barry W. **Software Engineering Economics**. Englewood Cliffs: Prentice-Hall, 1981.

DOUPÉ, Adam; COVA, Marco; VIGNA, Giovanni. Why Johnny Can't Pentest: An Analysis of Black-Box Web Vulnerability Scanners. In: INTERNATIONAL CONFERENCE ON DETECTION OF INTRUSIONS AND MALWARE, AND VULNERABILITY ASSESSMENT (DIMVA), 7., 2010, Bonn. **Proceedings** [...]. Berlin: Springer, 2010. p. 111-131.

FIRST — FORUM OF INCIDENT RESPONSE AND SECURITY TEAMS. **Common Vulnerability Scoring System version 3.1**: specification document. [S. l.]: FIRST, 2019. Disponível em: https://www.first.org/cvss/. Acesso em: 8 set. 2026.

FONSECA, José; VIEIRA, Marco; MADEIRA, Henrique. Testing and Comparing Web Vulnerability Scanning Tools for SQL Injection and XSS Attacks. In: IEEE PACIFIC RIM INTERNATIONAL SYMPOSIUM ON DEPENDABLE COMPUTING (PRDC), 13., 2007, Melbourne. **Proceedings** [...]. Los Alamitos: IEEE, 2007. p. 365-372.

GIL, Antônio Carlos. **Como elaborar projetos de pesquisa**. 4. ed. São Paulo: Atlas, 2002.

GREEN, Matthew; SMITH, Matthew. Developers are Not the Enemy!: The Need for Usable Security APIs. **IEEE Security & Privacy**, Los Alamitos, v. 14, n. 5, p. 40-46, 2016.

JOHNSON, Brittany et al. Why don't software developers use static analysis tools to find bugs? In: INTERNATIONAL CONFERENCE ON SOFTWARE ENGINEERING (ICSE), 35., 2013, San Francisco. **Proceedings** [...]. Piscataway: IEEE, 2013. p. 672-681.

McGRAW, Gary. **Software Security**: Building Security In. Boston: Addison-Wesley, 2006.

MITRE CORPORATION. **CWE — Common Weakness Enumeration**. [S. l.], 2024. Disponível em: https://cwe.mitre.org/. Acesso em: 8 set. 2026.

OWASP FOUNDATION. **OWASP Top 10 — 2021**: The Ten Most Critical Web Application Security Risks. [S. l.]: OWASP, 2021. Disponível em: https://owasp.org/Top10/. Acesso em: 8 set. 2026.

OWASP FOUNDATION. **Web Security Testing Guide (WSTG) v4.2**. [S. l.]: OWASP, 2020. Disponível em: https://owasp.org/www-project-web-security-testing-guide/. Acesso em: 8 set. 2026.

OWASP FOUNDATION. **OWASP ZAP — Zed Attack Proxy**. Versão 2.15. [S. l.]: OWASP, 2024. Disponível em: https://www.zaproxy.org/. Acesso em: 8 set. 2026.

PRESSMAN, Roger S.; MAXIM, Bruce R. **Engenharia de software**: uma abordagem profissional. 8. ed. Porto Alegre: AMGH, 2016.

PRODANOV, Cleber Cristiano; FREITAS, Ernani Cesar de. **Metodologia do trabalho científico**: métodos e técnicas da pesquisa e do trabalho acadêmico. 2. ed. Novo Hamburgo: Feevale, 2013.

SCARFONE, Karen et al. **Technical Guide to Information Security Testing and Assessment**: NIST Special Publication 800-115. Gaithersburg: National Institute of Standards and Technology, 2008.

SHOSTACK, Adam. **Threat Modeling**: Designing for Security. Indianapolis: Wiley, 2014.

SMITH, Justin et al. Questions developers ask while diagnosing potential security vulnerabilities with static analysis. In: JOINT MEETING ON FOUNDATIONS OF SOFTWARE ENGINEERING (ESEC/FSE), 10., 2015, Bergamo. **Proceedings** [...]. New York: ACM, 2015. p. 248-259.

SOMMERVILLE, Ian. **Engenharia de software**. 10. ed. São Paulo: Pearson Education do Brasil, 2018.

VIEGA, John; McGRAW, Gary. **Building Secure Software**: How to Avoid Security Problems the Right Way. Boston: Addison-Wesley, 2001.

WAZLAWICK, Raul Sidnei. **Metodologia de pesquisa para ciência da computação**. 2. ed. Rio de Janeiro: Elsevier, 2014.
