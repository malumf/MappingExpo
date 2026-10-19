<img width="1264" height="843" alt="image" src="https://github.com/user-attachments/assets/286d4893-e1e6-4dc4-b112-03f0c19287c6" />

# Console Web — MappingExpo

> Dashboard web local com tema Matrix para todas as operações do MappingExpo.
> Rode scans, pré-visualize dorks, acompanhe a saída ao vivo e navegue pelos resultados — tudo pelo navegador.

-----

## Visão Geral

`mappingexpo_web.py` é uma interface web baseada em Flask que envolve todo o pipeline do
`mappingexpo.py` numa UI de navegador. Ela abre um servidor local (bind apenas em
`127.0.0.1`), spawna scans como jobs em background e faz stream da saída deles em tempo
real via **Server-Sent Events (SSE)**.

Nenhum dado sai da máquina. O dashboard é uma ferramenta local — não foi projetado
para ser exposto numa interface de rede.

**Vive em:** `MappingExpo/Tools/mappingexpo_web.py`

-----

## Requisitos

```bash
pip install flask
```

`requests` e `rich` são usados pelos módulos subjacentes, mas não são exigidos pela camada web em si.

-----

## Uso

### Via `mappingexpo.py` (recomendado)

```bash
# Inicia na porta padrão 8080
python mappingexpo.py --ui

# Inicia numa porta customizada
python mappingexpo.py --ui --port 9090
```

### Standalone

```bash
python Tools/mappingexpo_web.py
python Tools/mappingexpo_web.py --port 9090
python Tools/mappingexpo_web.py --port 9090 --no-browser
```

-----

## Flags

### Via `mappingexpo.py`

|Flag      |Default|Descrição                                                      |
|----------|-------|-----------------------------------------------------------------|
|`--ui`    |off    |Inicia o Console Web e abre o navegador automaticamente        |
|`--port N`|`8080` |Porta preferida — auto-incrementa em até +100 se a porta estiver em uso|

### Standalone (`python Tools/mappingexpo_web.py`)

|Flag          |Default|Descrição                             |
|--------------|-------|----------------------------------------|
|`--port N`    |`8080` |Porta inicial                           |
|`--no-browser`|off    |Inicia o servidor sem abrir o navegador|

-----

## Seleção Automática de Porta

Se a porta preferida estiver em uso, o servidor varre as portas de `start` até
`start + 100` e binda na primeira livre. A URL real é impressa na inicialização:

```
  ▸ URL     →  http://127.0.0.1:8082
  ▸ Porta   →  8082  (selecionada automaticamente)
```

O socket é criado com `SO_REUSEADDR`, então a porta é liberada imediatamente no
encerramento, mesmo após um kill forçado (`TIME_WAIT` não é problema).

-----

## Seções do Dashboard

### ◈ Dashboard

Tela inicial com estatísticas de relance e botões de ação rápida:

|Card                |Mostra                                      |
|------------        |-------------------------------------        |
|Jobs Ativos         |Número de jobs de scan rodando agora         |
|Total de Jobs       |Todos os jobs lançados nesta sessão          |
|Arquivos de Resultado|Número de arquivos em `Dump/`               |
|Tamanho do Dump     |Uso total de disco de `Dump/`                |

Os botões de ação rápida levam direto a: **Novo Scan**, **Testador de URL**, **DorkGen**, **Varredura DB**, **Resultados**.

A tabela **Jobs Recentes** mostra os últimos 6 jobs com badges de status e um
botão TERM para anexar o terminal a qualquer um deles.

-----

### ◉ Novo Scan

Formulário de scan completo cobrindo toda opção do pipeline do `mappingexpo.py`.

**Alvo**

- String de dork — única ou multilinha (uma por linha). A entrada multilinha é
  escrita automaticamente num arquivo `.txt` temporário em `Dump/` e passada via `-d`.
- Máximo de resultados por dork (`-c`)
- Nome do arquivo de saída (`-o`) — a extensão determina o formato; default `.html`

**Modo & Opções**

|Toggle          |Flag mapeada      |
|--------------  |------------------|
|Stealth         |`--stealth`       |
|Detecção SQLi   |`--sqli`          |
|Detecção XSS    |`--xss`           |
|Pular Análise   |`--no-analyze`    |
|Sem Fingerprint |`--no-fingerprint`|

Seletor de tipo XSS (`--xss-type`): `all` / `reflected` / `stored` / `dom`.

**Seletor de modo** (`--mode`): `soft` / `medium` / `aggressive` (default: aggressive na UI).

**Seções recolhíveis** (expanda conforme precisar):

|Seção              |Flags expostas                                                                                                     |
|-------------------|------------------------------------------------------------------------------------------------------------------|
|⊞ Gerador de Dorks |`--dg=CAT`, `--templates`, `--dg-max`                                                                             |
|◧ Filtros          |`--blacklist`, `--whitelist`, `--config`                                                                          |
|🔬 Pipeline de Análise|`--analyze`, `--analyze-fetch`, `--analyze-fetch-max`, `--analyze-fmt`, `--analyze-out`                           |
|🕸 Crawl Adaptativo |`--crawl`, `--crawl-rounds`, `--crawl-max`, `--crawl-per-dork`, `--crawl-stealth`, `--crawl-report`, `--crawl-out`|
|🗄 Varredura de Portas DB |`--dbscan`, `--dbscan-timeout`, `--dbscan-threads`, `--dbscan-max-hosts`                                          |

-----

### ◎ Testador de URL

Teste direto de vulnerabilidade numa URL única — mapeia para `mappingexpo.py -u`.

|Campo     |Flag mapeada |
|----------|------------|
|URL alvo  |`-u`        |
|Teste SQLi|`--sqli`    |
|Teste XSS |`--xss`     |
|Tipo XSS  |`--xss-type`|
|Stealth   |`--stealth` |
|Saída     |`-o`        |

-----

### ⊞ Gerador de Dorks

Pré-visualize e exporte combinações de dorks sem rodar um scan.

|Controle       |Descrição                                                                     |
|--------------|--------------------------------------------------------------------------------|
|Templates     |Dropdown populado com todos os arquivos `.yaml` de `Templates/`                       |
|Categoria     |Populada dinamicamente do template selecionado via `/api/templates/categories`|
|Modo          |`soft` / `medium` / `aggressive`                                                |
|Máx. de combinações|Limite de combinações geradas (10–10.000)                                       |
|Botão PREVIEW |Busca até 200 dorks inline para revisão                                       |
|EXPORT TXT    |Baixa o conjunto completo como `mappingexpo_dorks_<ts>.txt`                              |

Ordem de resolução de template:

1. `default` / vazio → `Templates/dorks_templates.yaml` se presente, senão o primeiro `.yaml` encontrado
1. `all` → todo `.yaml` em `Templates/`
1. Nome específico → aquele arquivo; fallback para o default se não encontrado

-----

### ▣ Jobs

Tabela de todos os jobs lançados nesta sessão:

|Coluna |Descrição                                       |
|-------|--------------------------------------------------|
|ID     |Hex de 8 caracteres (job ID)                     |
|Label  |Descrição legível do job                         |
|Status |`running` (animado) / `done` / `error` / `killed`|
|Iniciado|Timestamp                                       |
|Encerrado|Timestamp (ou `—` se ainda rodando)             |
|Saída  |Nome do arquivo de saída                          |
|Ações  |Botões TERM / VIEW / KILL                        |

- **TERM** — anexa a barra de terminal ao stream ao vivo daquele job
- **VIEW** — abre o relatório `.html` numa nova aba do navegador (só para saídas `.html`)
- **KILL** — envia `SIGTERM` ao subprocess

-----

### ◧ Resultados

Navegador de arquivos do diretório `Dump/`. Mostra todos os arquivos `.html`, `.json`,
`.txt`, `.csv`, `.md` (arquivos temporários começando com `_` ficam ocultos).

|Coluna   |Descrição                                        |
|---------|--------------------------------------------|
|Nome     |Nome do arquivo — clique para abrir `.html` no navegador|
|Tamanho  |Tamanho legível                                 |
|Modificado|Timestamp da última modificação                 |
|FILE MODE|Reprocessar com `mappingexpo.py -f`             |
|↓ DL     |Baixar o arquivo                                |
|OPEN     |Abrir relatórios `.html` numa nova aba           |

-----

## Barra de Terminal

Faixa de terminal persistente no rodapé da página. Faz stream da saída do
job ativo via SSE.

|Controle     |Ação                                                       |
|------------|---------------------------------------------------------|
|Clique no cabeçalho|Alterna entre altura normal (200px) e expandida (400px)|
|COPY         |Copia todo o texto do terminal para a área de transferência  |
|CLEAR        |Limpa o conteúdo do terminal                                |
|KILL         |Mata o job ativo (visível só durante execução)         |

**Coloração de linhas** (ordem de precedência do `colorLine`):

|Cor      |Padrões casados                                                                       |
|------    |---------------------------------------------------------------------------------------|
|Verde    |`[✓]`, `SAFE`, ` saved `, `done`, `completed`, `salvo`, `salvos`, `Concluíd`, `[ Open ]` — classe default para linhas sem match|
|Amarelo  |`[~]`, `WARNING`, `WAF`, `skipping`, `Pulando`, `pulad`, `Interrompid`                  |
|Vermelho |`[!]`, `VULNERABLE`, `CRITICAL`, `error`, `Erro`, `potential`, `found`, `vuln`, `payload`, `potencial`, `encontrad`, `[ Closed ]` |
|Azul     |`[*]`, `Searching`, `Analyz`, `Loading`, `Starting`, `Buscando`, `Analisando`, `Carregando`, `Iniciando`, `Processando`, `DBScan`, `db.port`, `portscan`, box-drawing |
|Dim      |Linhas vazias                                                                          |

Códigos ANSI e rich markup são removidos da saída do subprocess antes da exibição.

-----

## Sistema de Jobs

Cada scan roda como subprocess em background via `subprocess.Popen`. A camada web
não bloqueia — múltiplos jobs podem rodar concorrentemente.

**Ciclo de vida do job:**

```
api/run POST  →  JobManager.spawn()  →  Popen(mappingexpo.py ...)
                                        ↓
                                  stdout/stderr merged
                                        ↓
                              Job.lines (deque, max 20,000)
                                        ↓
                              /api/stream/<jid>  (SSE)
                                        ↓
                              Barra de terminal no navegador
```

- O `stdin` é pré-alimentado com `n\n` para auto-responder o prompt
  `Executar análise nos resultados? [y/N]` (evita o job travar num prompt interativo)
- `PYTHONUNBUFFERED=1`, `NO_COLOR=1`, `FORCE_COLOR=0` são definidos no ambiente do subprocess
- O `cwd` do subprocess é a raiz do projeto, para que paths relativos resolvam corretamente

-----

## Endpoints da API

|Método|Endpoint                   |Descrição                                    |
|------|---------------------------|-----------------------------------------------|
|GET   |`/`                        |HTML principal do dashboard                    |
|GET   |`/api/status`              |Status do servidor: versão, porta, contagem de jobs ativos|
|GET   |`/api/jobs`                |Lista todos os jobs (resumo)                  |
|GET   |`/api/jobs/<jid>`          |Detalhe do job + linhas completas de saída     |
|DELETE|`/api/jobs/<jid>`          |Mata um job em execução                       |
|GET   |`/api/stream/<jid>`        |Stream SSE da saída do job                    |
|POST  |`/api/run`                 |Lança um novo job (scan / urltest / file)     |
|GET   |`/api/dump`                |Lista arquivos em `Dump/`                     |
|GET   |`/api/templates/list`      |Lista arquivos `.yaml` em `Templates/`        |
|GET   |`/api/templates/categories`|Lista categorias de um arquivo de template    |
|POST  |`/api/dorkgen/preview`     |Gera e retorna até 200 dorks                  |
|POST  |`/api/dorkgen/export`      |Gera e retorna a lista completa de dorks como `.txt`|
|GET   |`/dump/<filename>`         |Serve um arquivo de `Dump/`                    |

-----

## Resolução de Paths

O módulo web resolve a raiz do projeto na inicialização subindo a árvore de
diretórios a partir de `mappingexpo_web.py` procurando por `mappingexpo.py`:

```
MappingExpo/
    mappingexpo.py          ← âncora da raiz
    Dump/               ← diretório de saída
    Templates/          ← templates de dorks
    Tools/
        mappingexpo_web.py  ← começa aqui
```

Funciona tanto se `mappingexpo_web.py` for executado direto de `Tools/` quanto da raiz do projeto.

-----

## Notas de Segurança

- O servidor binda exclusivamente em `127.0.0.1` — ele **não é alcançável de outras
  máquinas** da rede.
- A resolução de path de template inclui um **guard de directory traversal**: qualquer
  path que resolva fora de `Templates/` é rejeitado, com fallback para o template default.
- O SIGINT é restaurado ao handler default antes de iniciar o Flask, para que o Ctrl+C
  encerre corretamente o servidor Werkzeug (o MappingExpo instala um handler SIGINT
  customizado que, de outro modo, interceptaria o sinal e impediria o encerramento limpo).

-----

## Encerramento

```
Ctrl+C
```

O servidor encerra limpo, libera a porta imediatamente (SO_REUSEADDR) e imprime:

```
  [!] Servidor parado. Porta liberada.
```

-----

## Dependências

|Pacote    |Exigida                 |Usada para                          |
|----------|------------------------|----------------------------------|
|`flask`   |**sim**                 |Servidor HTTP, rotas, SSE         |
|`werkzeug`|sim (bundled com Flask) |`make_server`, socket SO_REUSEADDR|
|`requests`|opcional                |Usada pelos módulos de scan       |
|`rich`    |opcional                |Usada pelos módulos de scan       |

```bash
pip install flask requests rich
```
