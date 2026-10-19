

# Referência CLI — Projeto MappingExpo

> Todas as flags, todos os valores aceitos, todas as combinações.
> Cheat sheet de página única — deixe aberto enquanto você opera.

-----

## Fontes de entrada — uma obrigatória

|Flag               |Tipo|Descrição                                                                       |
|-------------------|----|----------------------------------------------------------------------------------|
|`--wizard`         |bool|Abre a sessão interativa guiada (menus para tudo)                      |
|`-d DORK`, `--dork`|str |String de dork única **ou** caminho para arquivo `.txt` (um dork por linha, `#` = comentário)|
|`-u URL`, `--url`  |str |URL única — teste direto de vulnerabilidade (SQLi + XSS), sem busca          |
|`-f FILE`, `--file`|str |Carrega resultados salvos do MappingExpo (`.json` ou `.txt`) para reprocessamento                  |
|`--dg[=CATEGORY]`  |str |Ativa o Gerador de Dorks; valor = nome da categoria ou `all` (default se omitido)      |
|`--create-config`  |bool|Grava o `mappingexpo_config.yaml` de exemplo em disco e sai                               |
|`--ui`             |bool|Abre o Console Web (dashboard Flask) — ver seção **Console Web**            |

-----

## Saída

|Flag                 |Default                      |Descrição                                                |
|---------------------|-----------------------------|-----------------------------------------------------------|
|`-o FILE`, `--output`|`report_YYYYMMDD_HHMMSS.html`|Arquivo de saída — a extensão determina o formato (ver tabela abaixo)|
|`-c N`, `--count`    |`50`                         |Máximo de resultados por dork no DuckDuckGo                       |

Todos os arquivos de saída são salvos na pasta `Dump/` (criada automaticamente).

-----

## Configuração

|Flag             |Descrição                                                    |
|-----------------|---------------------------------------------------------------|
|`--config FILE`  |Carrega uma configuração YAML ou JSON customizada (mesclada com os defaults)|
|`--create-config`|Gera o `mappingexpo_config.yaml` de exemplo e sai                 |

-----

## Comportamento do scan

|Flag              |Default|Descrição                                                        |
|------------------|-------|-------------------------------------------------------------------|
|`--sqli`          |off    |Habilita detecção multi-método de SQL injection em cada resultado        |
|`--xss`           |off    |Habilita detecção multi-método de XSS em cada resultado                  |
|`--stealth`       |off    |Modo stealth — delays 1,4×–1,8× mais longos, pausas estendidas em rate limit |
|`--no-analyze`    |off    |Pula a análise HEAD de arquivos (sem tamanho / content-type / status)  |
|`--no-fingerprint`|off    |Desabilita a rotação de fingerprint HTTP (fallback para rotação básica de UA)|
|`--blacklist EXT…`|none   |Extensões separadas por espaço a excluir (ex.: `.jpg .png .gif`)      |
|`--whitelist EXT…`|none   |Extensões separadas por espaço — apenas estas são mantidas                   |

-----

## Detecção XSS

Requer `Tools/xss.py`. Ativado via `--xss`. Todos os métodos rodam por default (`--xss-type all`).

|Flag             |Default|Descrição                                                      |
|-----------------|-------|-----------------------------------------------------------------|
|`--xss`          |off    |Habilita o pipeline de detecção XSS (reflected + stored + dom + header)|
|`--xss-type TYPE`|`all`  |Método(s) de detecção a executar — ver tabela **Tipos de XSS** abaixo       |

### Tipos de XSS (`--xss-type`)

|Valor      |Método                                                                                             |
|-----------|---------------------------------------------------------------------------------------------------|
|`reflected`|Injeta payloads em parâmetros GET; verifica reflexão sem escape na resposta                        |
|`stored`   |POST de payload por parâmetro individual, refetch via GET, verifica se o marker persiste                       |
|`dom`      |Análise estática de padrões source-to-sink em JS (scripts inline + até 5 scripts externos)          |
|`header`   |Injeta marker em `X-Forwarded-For`, `Referer`, `User-Agent`, `X-Forwarded-Host`, `X-Original-URL`|
|`all`      |Executa os quatro métodos em sequência (default)                                                         |

### Níveis de Confiança XSS

|Nível     |Significado                                                            |
|----------|-------------------------------------------------------------------|
|`NONE`    |Nenhum XSS detectado                                                    |
|`LOW`     |Análise estática de DOM: 3–5 pares source/sink coocorrentes            |
|`MEDIUM`  |Análise de DOM: 6+ pares; ou reflected/stored com header CSP presente|
|`HIGH`    |Reflexão sem escape confirmada (reflected/stored/header), sem CSP   |
|`CRITICAL`|Múltiplos métodos confirmados — pontuação de confiança combinada ≥ 5         |


> **Nota** — A análise de DOM sozinha nunca chega a HIGH/CRITICAL; SPAs modernos (React/Vue/Angular)
> produzem pares source/sink das internals do framework. Resultados abaixo do limiar de 3 pares são
> registrados apenas como informativos.

-----

## Detecção de SQL Injection

|Flag    |Default|Descrição                                                |
|--------|-------|-----------------------------------------------------------|
|`--sqli`|off    |Habilita detecção multi-método de SQL injection em cada resultado|

### Níveis de Confiança SQLi

|Nível     |Significado                                                 |
|----------|--------------------------------------------------------|
|`NONE`    |Nenhuma injeção detectada                                   |
|`LOW`     |Sinal fraco (ex.: apenas col-mismatch de UNION)              |
|`MEDIUM`  |Diferencial booleano blind ou time-based confirmado      |
|`HIGH`    |Assinatura de erro de banco casada ou evidência forte de UNION     |
|`CRITICAL`|Múltiplos métodos confirmados entre parâmetros (pontuação ≥ 5)|

### Detecção de WAF

Detectado automaticamente durante os testes de SQLi e XSS. Assinaturas suportadas:

Cloudflare · ModSecurity · Wordfence · Sucuri · Imperva · Akamai · F5 BigIP · Barracuda ·
FortiWeb · AWS WAF · DenyAll · Reblaze · genérico (403/406/419/429 com corpo curto)

-----

## Gerador de Dorks

|Flag              |Default               |Descrição                                                           |
|------------------|----------------------|----------------------------------------------------------------------|
|`--dg[=CATEGORY]` |`all`                 |Categoria a gerar (`all` = todas as categorias do template)             |
|`--dg-max N`      |`800`                 |Máximo de combinações de dorks por arquivo de template                               |
|`--mode MODE`     |`soft`                |Intensidade de geração: `soft` / `medium` / `aggressive`                |
|`--templates=FILE`|`dorks_templates.yaml`|Arquivo de template dentro de `Templates/`; `all` = todo `.yaml` da pasta|

⚠ `--templates` exige sintaxe com `=`: `--templates=arquivo.yaml` ✓ — `--templates arquivo.yaml` ✗

-----

## Agents — Análise Integrada Pós-Busca

|Flag                   |Default|Descrição                                               |
|-----------------------|-------|----------------------------------------------------------|
|`--analyze`            |off    |Executa o pipeline completo de análise (triage → segredos → relatório)|
|`--analyze-fetch`      |off    |Baixa o conteúdo das páginas dos resultados HIGH / CRITICAL         |
|`--analyze-fetch-max N`|`20`   |Máximo de páginas a baixar durante a análise                     |
|`--analyze-fmt FORMAT` |`html` |Formato do relatório de análise: `html` / `md` / `json` / `txt`    |
|`--analyze-out FILE`   |auto   |Path customizado para o relatório de análise                       |

Requer `mappingexpo_agents.py` em `Tools/`. Se ausente, `--analyze` e `--crawl` são silenciosamente desabilitados.

-----

## Crawl Recursivo Adaptativo

|Flag                |Default|Descrição                                               |
|--------------------|-------|----------------------------------------------------------|
|`--crawl`           |off    |Habilita crawl adaptativo de múltiplas rodadas após a busca inicial|
|`--crawl-rounds N`  |`4`    |Máximo de rodadas de refinamento                                 |
|`--crawl-max N`     |`300`  |Limite total de resultados em todas as rodadas                        |
|`--crawl-per-dork N`|`20`   |Resultados do DuckDuckGo por dork gerado por rodada           |
|`--crawl-stealth`   |off    |Delays mais longos entre buscas do crawl                      |
|`--crawl-report`    |off    |Gera um relatório HTML dedicado ao crawl                    |
|`--crawl-out FILE`  |auto   |Path customizado para o relatório do crawl                          |

O crawler analisa os resultados iniciais (domínios, paths, tecnologias, extensões), gera
dorks refinados, busca de novo e repete até retornos decrescentes.

-----

## Varredura de Portas DB

Requer `Tools/db_portscan.py`. Ativado via `--dbscan` no pipeline principal,
ou executado standalone como `python Tools/db_portscan.py`.

### Flags integradas (via `mappingexpo.py`)

|Flag                  |Default|Descrição                                                        |
|----------------------|-------|-------------------------------------------------------------------|
|`--dbscan`            |off    |Executa a varredura de portas DB em todos os hosts únicos extraídos dos resultados        |
|`--dbscan-timeout N`  |`2.5`  |Timeout de conexão TCP por porta, em segundos                            |
|`--dbscan-threads N`  |`60`   |Threads de trabalho por host (máx. 200)                                  |
|`--dbscan-max-hosts N`|`200`  |Máximo de hosts a escanear (IPs privados/loopback excluídos automaticamente)|

### Flags standalone (`python Tools/db_portscan.py`)

|Flag          |Default     |Descrição                                           |
|--------------|------------|------------------------------------------------------|
|`results_file`|*(required)*|Arquivo de resultados `.json` do MappingExpo                          |
|`--timeout`   |`2.5`       |Timeout de conexão TCP em segundos                        |
|`--threads`   |`60`        |Threads de trabalho por host                               |
|`--ports N…`  |all DB ports|Lista de portas separadas por espaço                     |
|`--max-hosts` |`200`       |Máximo de hosts a escanear                                     |
|`--stealth`   |off         |Adiciona delay entre hosts (1,5–3,5 s)                      |
|`--out FILE`  |auto        |Path base de saída (grava `_dbscan_<ts>.json` + `.txt`)|

### Serviços e portas detectados

|Serviço      |Porta(s)     |Método de probe                                       |
|-------------|------------|---------------------------------------------------|
|MySQL        |3306        |TCP banner                                         |
|PostgreSQL   |5432        |TCP banner                                         |
|MongoDB      |27017/18/19 |OP_MSG isMaster handshake                          |
|Redis        |6379        |`PING` → `+PONG` = sem autenticação                         |
|Elasticsearch|9200 / 9300 |HTTP GET `/` — verifica `cluster_name` na resposta   |
|CouchDB      |5984        |HTTP GET `/` — verifica `couchdb` na resposta        |
|InfluxDB     |8086        |HTTP GET `/ping` — 204 = vivo                     |
|Neo4j        |7474        |HTTP GET `/` — verifica `neo4j`/`bolt` na resposta   |
|MSSQL        |1433        |TCP banner                                         |
|Oracle       |1521        |TCP banner                                         |
|Cassandra    |9042        |TCP banner                                         |
|Memcached    |11211       |`stats\r\n` → `STAT` = sem autenticação                     |
|RethinkDB    |28015 / 5000|TCP banner                                         |
|DB2          |50000       |TCP banner *(não padrão — fora do set de scan default)*|
|Riak HTTP    |8098        |HTTP GET `/`                                       |

### Níveis de Severidade do DBScan

|Nível     |Significado                                                  |
|----------|---------------------------------------------------------|
|`CRITICAL`|Porta aberta **e** acesso sem autenticação confirmado       |
|`HIGH`    |Porta aberta e serviço confirmado via probe de banner/protocolo|
|`MEDIUM`  |Porta aberta, identidade do serviço incerta                      |
|`INFO`    |Porta fechada / filtrada / timeout                         |

Hints de porta são extraídos automaticamente de strings de dork, paths de URL e títulos de
página para priorizar portas relevantes (ex.: um resultado contendo "phpmyadmin" escaneia a porta 3306 primeiro).

-----

## Console Web

Requer Flask (`pip install flask`). Abre um dashboard local com tema Matrix
que envolve o pipeline completo do `mappingexpo.py` numa interface de navegador.

### Flags (via `mappingexpo.py`)

|Flag      |Default|Descrição                                                     |
|----------|-------|----------------------------------------------------------------|
|`--ui`    |off    |Inicia o Console Web e abre o navegador                      |
|`--port N`|`8080` |Porta preferida; auto-incrementa em até +100 se a porta estiver em uso|

### Standalone (`python Tools/mappingexpo_web.py`)

|Flag          |Default|Descrição                             |
|--------------|-------|----------------------------------------|
|`--port N`    |`8080` |Porta inicial                           |
|`--no-browser`|off    |Inicia o servidor sem abrir o navegador|

O console detecta automaticamente uma porta livre, binda apenas em `127.0.0.1`, faz
stream da saída do subprocess via SSE e expõe todas as opções do pipeline numa
interface baseada em formulários (Scan, Testador de URL, DorkGen, Jobs, Resultados).
A pasta `Dump/` é navegável e os arquivos podem ser abertos ou baixados diretamente.

-----

## Valores Aceitos

### `--mode`

|Valor       |Comportamento                                         |Pegada|
|------------|--------------------------------------------------|---------|
|`soft`      |Apenas dorks de baixo risco — expansão mínima de variáveis  |Mínima  |
|`medium`    |Padrões de cobertura soft + medium                   |Moderada |
|`aggressive`|Todas as combinações de dorks — expansão máxima de variáveis|Máxima  |

### `-o` / `--output` — formato por extensão

|Extensão|Formato                       |Observações                                                                                                                                                                   |
|---------|-----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|`.html`  |Relatório interativo com tema escuro|Matrix rain, barra de filtros, painel de busca, painéis de export (TXT/JSON/CSV), navegador de arquivos, popup de detalhes ⓘ, badges de WAF                                                           |
|`.json`  |JSON estruturado              |Bloco completo de metadados + estatísticas. **Dispara o prompt interativo de análise**                                                                                              |
|`.csv`   |CSV de planilha              |Todas as colunas: url, title, snippet, dork, timestamp, extension, category, file_size, content_type, accessible, status_code, sqli_vulnerable, sqli_confidence, waf_detected|
|`.txt`   |Texto puro numerado          |Detalhes por resultado (título, categoria, status SQLi, status XSS, WAF)                                                                                                      |

Se nenhuma extensão for informada, `.json` é anexado automaticamente.

### `--analyze-fmt`

|Valor |Saída                                                         |
|------|---------------------------------------------------------------|
|`html`|HTML completo com tema escuro e seções de triage, segredos e credenciais|
|`md`  |Markdown com tabelas                                           |
|`json`|JSON estruturado (chaves pii, emails, subdomains, cve_dorks)      |
|`txt` |Resumo em texto puro                                             |

-----

## Regras de Compatibilidade

### Entradas mutuamente exclusivas

```
--wizard  ←→  -d  ←→  -u  ←→  -f  ←→  --dg  ←→  --create-config  ←→  --ui
```

Apenas uma fonte de entrada por invocação.

### Restrições de `-u`

- `--sqli` e `--xss` são auto-habilitados mesmo sem serem especificados
- Incompatível com `--analyze`, `--crawl`, `-d`, `-f`, `--dg`
- A execução para imediatamente após os testes de vulnerabilidade
- O resultado é salvo em `-o`, se informado

### Restrições de `--xss`

- `--xss-type` só tem efeito quando `--xss` está ativo
- Compatível com `-d`, `-u`, `-f`, `--dg`
- Requer `Tools/xss.py` — caso contrário, é pulado silenciosamente
- WAF pré-detectado pelo probe SQLi é compartilhado automaticamente com o engine XSS

### Restrições de `--dbscan`

- `--dbscan-timeout`, `--dbscan-threads`, `--dbscan-max-hosts` só têm efeito quando `--dbscan` está ativo
- Funciona com `-d`, `-f`, `--dg` — não com `-u` (sem pool de URLs de onde extrair hosts)
- Pula IPs privados/loopback automaticamente (192.168.x, 10.x, 127.x etc.)
- Salva um arquivo `_dbscan_<ts>.json` + `_dbscan_<ts>.txt` separado junto da saída principal

### Restrições de `--dg`

- Apenas um valor de `--dg` — `--dg=sqli` ✓, duas flags `--dg` ✗
- Deve usar a sintaxe `--templates=ARQUIVO` (com `=`, sem espaço)
- `-c` / `--count` é **ignorado** — o gerador usa 50 resultados fixos por dork

### Restrições de `--analyze`

- `--analyze-fetch-max` só tem efeito quando `--analyze-fetch` também está definido
- `--analyze-out` exige `--analyze` ativo (ou saída `.json`)
- Requer `mappingexpo_agents.py` em `Tools/` — caso contrário, é pulado silenciosamente

### Restrições de `--ui`

- Não pode ser combinado com nenhuma outra flag de entrada na mesma invocação
- O Flask precisa estar instalado (`pip install flask`)
- Binda apenas em `127.0.0.1` — não exposto na LAN
- Todos os scans iniciados pela UI são enfileirados como jobs em background com streaming SSE ao vivo

### Comportamento especial da saída `.json`

Quando `-o` termina em `.json` e `--analyze` **não** está definido explicitamente,
o MappingExpo exibe um prompt interativo:

```
Executar análise nos resultados? [y/N]:
```

Use `--analyze` para forçar sim e pular o prompt (útil para scripting).

### Comportamento de `-f` / `--file`

- Busca primeiro no diretório atual, depois em `Dump/`
- `.json` aceita os formatos `{"results": [...]}` e `[...]` cru
- `.txt` lê uma URL por linha (linhas começando com `http`)
- Combine livremente com `--sqli`, `--xss`, `--analyze`, `--crawl`, `--dbscan`
- Hashes de URLs existentes são reconstruídos para evitar falsos duplicados

-----

## Controle de Interrupção

|Ação                         |Efeito                                     |
|-------------------------------|-------------------------------------------|
|**Ctrl+C único**              |Pula o dork / tarefa atual → continua para o próximo|
|**Ctrl+C duplo** (em até 1,5s)|Sai imediatamente → salva resultados parciais    |

Funciona durante: buscas, análise de arquivos, testes SQLi/XSS, delays entre dorks,
análise, crawl, varredura de portas DB.

-----

## Termux / Android

Auto-detectado — sem flags. Rodando dentro do Termux:

- Timeout de conexão: 3s (vs 4s)
- Amostras de baseline SQLi: 1 (vs 2)
- Amostras de probe: 2 (vs 3), amostras booleanas: 2 (vs 3)
- Confirmações time-based: 1 (vs 2)
- O banner exibe: `Android / Termux | economia de bateria ativa`

-----

## Combinações Comuns

```bash
# ── WIZARD ───────────────────────────────────────────────────────────────
python mappingexpo.py --wizard

# ── CONSOLE WEB ──────────────────────────────────────────────────────────
python mappingexpo.py --ui
python mappingexpo.py --ui --port 9090
python Tools/mappingexpo_web.py --port 9090 --no-browser

# ── BUSCA DE DORKS ──────────────────────────────────────────────────────────
python mappingexpo.py -d "site:example.com filetype:pdf" -o results.html
python mappingexpo.py -d dorks.txt -c 100 -o results.json
python mappingexpo.py -d "inurl:.php?id=" --sqli --stealth -o results.json
python mappingexpo.py -d "inurl:.php?id=" --sqli --xss --stealth -o results.json
python mappingexpo.py -d dorks.txt --analyze --analyze-fetch -o results.json
python mappingexpo.py -d dorks.txt --sqli --xss --analyze --crawl -o results.json  # pipeline completo

# ── GERADOR DE DORKS ───────────────────────────────────────────────────────
python mappingexpo.py --dg=all
python mappingexpo.py --dg=sqli --mode=medium --sqli -o results.json
python mappingexpo.py --dg=all --mode=aggressive --dg-max=10000 -o results.json
python mappingexpo.py --dg=sqli --sqli --xss --analyze --analyze-fetch -o results.json

# ── TESTE DIRETO DE URL ──────────────────────────────────────────────────
python mappingexpo.py -u "https://target.com/page.php?id=1"
python mappingexpo.py -u "https://target.com/page.php?id=1" --sqli --xss --stealth -o out.json
python mappingexpo.py -u "https://target.com/page.php?id=1" --xss --xss-type reflected -o out.json

# ── REPROCESSAMENTO DE ARQUIVO ────────────────────────────────────────────
python mappingexpo.py -f Dump/results.json --sqli -o retest.json
python mappingexpo.py -f Dump/results.json --sqli --xss -o retest.json
python mappingexpo.py -f Dump/results.json --analyze --analyze-fetch -o reanalysis.json
python mappingexpo.py -f Dump/results.json --sqli --xss --analyze --crawl -o full.json
python mappingexpo.py -f Dump/results.json --dbscan --dbscan-timeout 3 -o dbscan.json

# ── VARREDURA DE PORTAS DB ─────────────────────────────────────────────────
python mappingexpo.py -d dorks.txt --dbscan -o results.json
python mappingexpo.py -d dorks.txt --dbscan --dbscan-timeout 3 --dbscan-threads 80 -o results.json
python Tools/db_portscan.py Dump/results.json
python Tools/db_portscan.py Dump/results.json --timeout 3 --threads 80
python Tools/db_portscan.py Dump/results.json --ports 3306 5432 27017 6379
python Tools/db_portscan.py Dump/results.json --stealth --max-hosts 50

# ── SCAN SOMENTE XSS ────────────────────────────────────────────────────────
python mappingexpo.py -d dorks.txt --xss --xss-type reflected -o results.json
python mappingexpo.py -d dorks.txt --xss --xss-type dom -o results.json

# ── AGENTS STANDALONE ────────────────────────────────────────────────────
python mappingexpo_analyze.py Dump/results.json --fetch --fmt=html

# ── PIPELINE COMPLETO (gerar + buscar + sqli + xss + análise + crawl + dbscan) ──
python mappingexpo.py \
  --dg=sqli \
  --mode=aggressive \
  --sqli \
  --xss \
  --stealth \
  -o full.json \
  --analyze \
  --analyze-fetch \
  --analyze-fetch-max=100 \
  --crawl \
  --crawl-rounds=6 \
  --crawl-stealth \
  --crawl-report \
  --dbscan \
  --dbscan-timeout=2.5 \
  --dbscan-threads=80 \
  --dbscan-max-hosts=200
```
