# Manual de Instalação e do Usuário

SentinelScope 1.0 · para quem instala o sistema e para o desenvolvedor que o utiliza.
Siga os passos na ordem; cada um termina com uma verificação que indica que deu certo.

> **Autorização.** O SentinelScope envia requisições HTTP ao endereço que você registra — no
> modo completo, requisições contendo payloads de teste. Analise apenas aplicações que são suas
> ou que você está explicitamente autorizado, por escrito, a avaliar.

---

## Parte A — Instalação

### A.1 Requisitos

| Componente | Versão | Observações |
|---|---|---|
| Sistema operacional | Windows 10/11 (testado no Windows 11 Pro) | Linux funciona com os mesmos passos e os caminhos equivalentes. |
| XAMPP | 8.2.x | Fornece Apache 2.4, PHP 8.2 e MariaDB 10.4. Baixe em apachefriends.org. |
| Extensões PHP | `pdo_mysql`, `mbstring` | Habilitadas por padrão no XAMPP. Confira com `php -m`. `proc_open` não pode constar em `disable_functions`. |
| Python | 3.10 ou superior | Somente a biblioteca padrão — não é preciso `pip install`. Durante a instalação, marque **Add python.exe to PATH**. |
| Navegador | qualquer navegador atual | |

**Verificação:** em um terminal novo, `python --version` mostra 3.10 ou superior e
`C:\xampp\php\php.exe -m` lista `pdo_mysql` e `mbstring`.

### A.2 Posicione os arquivos

Copie (ou `git clone https://github.com/jdsricardo/Ciber.git`) o projeto para a pasta web do
XAMPP. Este manual assume `C:\xampp\htdocs\www\Ciber`; se escolher outra pasta, ajuste a URL do
passo A.6 (a URL é o caminho da pasta abaixo de `htdocs`, seguido de `/public/`).

**Verificação:** `C:\xampp\htdocs\www\Ciber\public\index.php` existe.

### A.3 Inicie o Apache e o MySQL

Abra o **XAMPP Control Panel** e clique em **Start** ao lado de **Apache** e **MySQL**.

**Verificação:** os dois módulos ficam verdes. Se a porta 80 ou 3306 estiver ocupada, encerre o
programa que a usa ou altere a porta no XAMPP (botão `Config`) e use essa porta em A.5 e A.6.

### A.4 Crie o banco de dados e o seu usuário

1. Abra `http://localhost/phpmyadmin/`.
2. **Importar** → escolha `database.sql` na pasta do projeto → **Importar** (no fim da página).
   Isso cria o banco `sentinelscope` com as tabelas `applications`, `analyses` e `findings`.
   Importá-lo de novo mais tarde é seguro: ele só acrescenta o que estiver faltando.
3. Abra a aba **SQL** e execute os comandos abaixo, trocando `CHOOSE_A_PASSWORD` por uma senha
   forte de sua escolha. Eles criam um usuário que pode ler e gravar os dados da aplicação e
   nada mais:

```sql
CREATE USER 'sentinelscope_app'@'localhost' IDENTIFIED BY 'CHOOSE_A_PASSWORD';
CREATE USER 'sentinelscope_app'@'127.0.0.1' IDENTIFIED BY 'CHOOSE_A_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE ON sentinelscope.* TO 'sentinelscope_app'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON sentinelscope.* TO 'sentinelscope_app'@'127.0.0.1';
FLUSH PRIVILEGES;
```

**Verificação:** o painel esquerdo do phpMyAdmin mostra `sentinelscope` com três tabelas.

### A.5 Configure o `.env`

Na pasta do projeto, copie `.env.example` para um novo arquivo chamado `.env` (exatamente esse
nome, com o ponto inicial) e edite-o:

| Chave | O que escrever |
|---|---|
| `DB_HOST` | `127.0.0.1` |
| `DB_PORT` | `3306` (ou a porta escolhida em A.3) |
| `DB_NAME` | `sentinelscope` |
| `DB_USER` | `sentinelscope_app` |
| `DB_PASSWORD` | a senha escolhida em A.4 |
| `PYTHON_BINARY` | `python`. Se depois a análise falhar com *"O scanner retornou uma resposta inválida"*, escreva o caminho completo, por exemplo `C:\Users\you\AppData\Local\Programs\Python\Python312\python.exe` (descubra-o com `where python`). |
| `ALLOW_PRIVATE_TARGETS` | `false`. Escreva `true` **somente** para analisar uma aplicação rodando na sua própria máquina ou em uma rede de laboratório (A.7). |

O `.env` contém uma senha: nunca o envie a ninguém e nunca o faça commit (o Git já o ignora).

### A.6 Primeiro acesso

Abra `http://localhost/www/Ciber/public/`.

**Verificação:** a página **Painel** aparece com o título *"Encontre o risco. Entregue a correção."*
e o texto *"Nenhuma aplicação registrada ainda."*

| O que aparece no lugar | Causa e correção |
|---|---|
| *"Configuração necessária: copie .env.example para .env…"* | O `.env` não existe ou tem outro nome (o Windows pode tê-lo salvo como `.env.txt`). Refaça A.5. |
| *"Ocorreu um erro inesperado. Consulte o log do servidor."* | Normalmente o banco de dados: MySQL não iniciado (A.3), `database.sql` não importado (A.4) ou usuário/senha errados no `.env`. O motivo exato está em `C:\xampp\apache\logs\error.log`, na última linha que começa com `SentinelScope:`. |
| *Object not found* (404) | A URL não corresponde à pasta de A.2. |

### A.7 Verifique o scanner (recomendado)

O projeto inclui uma aplicação de laboratório deliberadamente vulnerável, para que a instalação
possa ser verificada sem tocar em nenhum sistema real.

1. Em um terminal, na pasta do projeto: `python tests/e2e/lab_target.py --port 8765`
   (deixe-o rodando).
2. No `.env`, defina `ALLOW_PRIVATE_TARGETS=true`.
3. No navegador, siga B.1 e B.2 com a URL `http://127.0.0.1:8765/`.

**Verificação:** a análise termina com status *completed*, **34** verificações executadas e uma
lista de achados (cabeçalhos de segurança ausentes, cookie sem HttpOnly, …). Encerre o
laboratório com `Ctrl+C` e volte a definir `ALLOW_PRIVATE_TARGETS=false` depois.

### A.8 Recomendações para uma instalação compartilhada ou próxima de produção

- Aponte o `DocumentRoot` do Apache para a pasta `public`, de modo que nenhum outro arquivo do
  projeto fique acessível.
- Sirva por HTTPS e coloque a aplicação atrás de autenticação: esta versão pressupõe uma
  instalação local, confiável e de usuário único, e não tem login próprio.
- Mantenha `ALLOW_PRIVATE_TARGETS=false`.
- Mantenha `display_errors=Off` no `php.ini` (a aplicação também o força desligado).
- Uma análise no modo completo pode levar até ~10 minutos em um alvo grande. A própria aplicação
  eleva o limite de tempo do PHP para essa requisição; se houver um proxy na frente do Apache,
  dê a ele um tempo limite de leitura de pelo menos 11 minutos.

---

## Parte B — Uso

### B.1 Registre uma aplicação

**Adicionar aplicação** → informe um **nome** e a **URL base** de um ambiente de teste ou
homologação (`https://staging.example.com/`) → marque a declaração de autorização →
**Registrar aplicação**.

A URL deve começar com `http://` ou `https://` e não pode conter usuário ou senha. Sem a marcação
de autorização, a aplicação não é registrada.

### B.2 Execute uma análise

No **Painel**, cada aplicação tem um cartão com o botão **Executar análise**.

| Opção | Efeito |
|---|---|
| *(padrão)* **Passiva** | Apenas observa as respostas: transporte, cabeçalhos de segurança, cookies, CORS, cache, divulgação de informações, segredos expostos — 34 verificações. Envia duas requisições GET comuns por página. Normalmente leva segundos. |
| **Análise completa (ativa)** | Também envia payloads de teste seguros a cada parâmetro e campo de formulário encontrado (SQL injection, XSS, travessia de diretório, redirecionamento aberto, injeção de comandos, SSTI, XXE, CRLF, cabeçalho Host, verbos HTTP, NoSQL, CORS, SSRF) — 64 verificações. Atenção: a verificação de verbos HTTP envia OPTIONS, POST, PUT, DELETE, PATCH e TRACE uma vez a **cada** página visitada (até 20 no modo completo); um alvo vulnerável pode de fato executá-los. Use o modo completo somente em ambientes de teste ou homologação. Exige a segunda marcação de autorização. Pode levar vários minutos. |
| **Área autenticada (opcional)** | Cole um cookie de sessão (por exemplo `PHPSESSID=…`) de um usuário de teste para analisar páginas atrás do login. Ele é enviado apenas ao endereço registrado, durante esta análise, e nunca é armazenado. |

O scanner começa pela URL registrada e segue links, formulários de busca (GET),
redirecionamentos e URLs escritas no JavaScript da aplicação (por exemplo
`fetch('api/pedidos.php?id=' + id)`), sempre no mesmo site, até 50 páginas no modo passivo e 40
no completo. Telas que só mudam pelo valor de um parâmetro (`index.php?p=12`, `index.php?p=14`)
são analisadas uma a uma; já páginas que repetem o mesmo modelo com outros dados (os produtos de
um catálogo) são reconhecidas e analisadas uma vez só. Ele nunca segue links de logout nem links
ou endereços que alteram dados (como `?action=delete`, `/usuario/excluir/5` ou
`delete_user_ajax.php`).

Para analisar um sistema com login, faça login no navegador com um usuário de teste, copie o
cookie de sessão (DevTools → *Application* → *Cookies*, por exemplo `PHPSESSID=…`) e registre como
endereço a **página inicial já logada**, não a tela de login — assim o menu fica a um clique. Não
clique em **Sair** no navegador enquanto a análise roda: isso encerraria a sessão que o scanner
está usando.

Enquanto a análise roda, o botão mostra **Analisando…** e uma mensagem de progresso; não feche a
página. Quando termina, a página de resultado é aberta.

### B.3 Leia o resultado

O cabeçalho mostra a **Pontuação de Segurança** (0–100) e as métricas: verificações
executadas, páginas analisadas, achados, status HTTP da primeira página e duração.

A seção **Cobertura da análise**, depois dos achados, diz quanto do site o resultado representa:
a lista das páginas analisadas, quantos arquivos JavaScript foram lidos em busca de endpoints e
quantas variações de um mesmo modelo não foram repetidas. Se aparecer o aviso *"N páginas
encontradas não foram analisadas"*, a análise atingiu o limite de páginas, de requisições ou de
tempo, ou essas páginas não responderam: elas (listadas em **Ver quais**) podem ter problemas que
não aparecem no resultado. Para cobri-las, registre como aplicação a primeira delas — o
rastreamento parte dela e alcança as demais — ou cada uma separadamente.
Uma página para a qual nada aponta, ou que só existe depois de o JavaScript montar a tela no
navegador, não é encontrada — registre o endereço dela diretamente.

Cada achado é lido de cima para baixo: **o que foi observado**, **por que importa**, **como
corrigir** e um exemplo de código **vulnerável vs. corrigido** que você copia com um clique. Dois
selos são independentes:

- **Severidade** — quão grave seria se for real (crítico, alto, médio, baixo).
- **Confiança / status** — quão seguro o scanner está. *Revisão manual* significa que uma pessoa
  deve confirmar o achado antes de agir.

Os chips acima da lista filtram os achados por severidade. O painel **Contexto técnico** de cada
achado mostra a evidência bruta.

Como a pontuação é calculada: começa em 100 e perde 30 / 15 / 7 / 2 pontos por achado crítico /
alto / médio / baixo, nunca ficando abaixo de 0. Ela serve para comparar análises sucessivas da
mesma aplicação, não para certificar segurança.

Se a análise não pôde ser concluída, a página diz o porquê — por exemplo, o endereço não
respondeu, ou aponta para uma rede privada enquanto isso não é permitido.

### B.4 Compare antes e depois de uma correção

Depois de implantar as correções, execute uma nova análise. No cartão da aplicação, escolha a
análise mais antiga e a mais nova e clique em **Comparar**. A página lista **Novos problemas**,
**Ainda presentes** e **Corrigidos**, cada um com a página e o parâmetro onde o achado está, além
da variação da pontuação.

### B.5 Relatório e exportação

- **Relatório para impressão** → **Imprimir / Salvar como PDF** gera um PDF com o cabeçalho, as
  métricas e todos os achados com sua explicação e correção.
- **Exportar JSON** baixa a análise para pipelines de CI ou ferramentas de chamados: a aplicação
  e a data, um resumo (achados por severidade, achados que precisam de revisão manual, pontuação)
  e todos os achados com sua taxonomia, evidência e exemplo de correção.

### B.6 Histórico

Cada cartão lista todas as análises daquela aplicação, da mais recente para a mais antiga, com
data (UTC), modo, status, pontuação e número de verificações. Clique no número de uma análise para
abri-la.

Para consultar um período, preencha **De** e/ou **Até** em *Histórico por período*, acima dos
cartões, e clique em **Filtrar**: cada cartão passa a listar apenas as análises iniciadas naquele
período (os dois dias incluídos; deixe um campo vazio para um extremo aberto). **Limpar** volta a
mostrar o histórico completo.

---

## Parte C — Solução de problemas

| Problema | O que fazer |
|---|---|
| *"O scanner retornou uma resposta inválida. Verifique a configuração do Python."* | O Apache não encontra o Python. Coloque o caminho completo do `python.exe` em `PYTHON_BINARY` (A.5). Teste: `"<esse caminho>" scanner\scanner.py https://example.com` deve imprimir uma linha de JSON. |
| *"Alvos em rede privada, loopback, link-local ou endereços reservados são bloqueados por padrão."* | Proteção esperada: o endereço está na sua máquina ou em uma rede privada. Defina `ALLOW_PRIVATE_TARGETS=true` somente para um laboratório autorizado. |
| *"Falha de rede ao acessar o alvo"* | O nome do alvo não pôde ser resolvido (DNS): confira a grafia da URL, a VPN ou o DNS da rede. |
| *"Nenhuma página pôde ser acessada no alvo"* | O endereço não respondeu ou a conexão HTTPS falhou: confira-o no navegador, a VPN ou um firewall. |
| Alvo HTTPS com certificado inválido, expirado ou autoassinado, ou que só aceita TLS anterior ao 1.2 | O motor valida o certificado e exige TLS 1.2 ou superior, então a análise falha com *"Nenhuma página pôde ser acessada no alvo."*. Analise um ambiente com certificado válido. |
| *"A análise excedeu o tempo máximo de … segundos e foi interrompida."* | O alvo é lento ou grande demais para uma análise. Execute o modo passivo ou analise uma URL mais específica. |
| *"Falha ao gravar o resultado da análise."* | O banco de dados recusou a gravação (disco cheio, permissões). Veja a última linha `SentinelScope:` de `C:\xampp\apache\logs\error.log`. |
| *"Seu token de sessão expirou."* | A página ficou aberta por tempo demais ou os cookies estão bloqueados; recarregue-a e repita. |
| *"Informe as datas no formato AAAA-MM-DD."* / *"A data inicial deve ser anterior ou igual à data final."* | Corrija o período em *Histórico por período* ou clique em **Limpar**. |
| Uma análise listada como *running* | Somente enquanto está em andamento. Uma análise é sempre encerrada como *completed* ou *failed* quando sua requisição termina. |
