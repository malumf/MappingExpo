<img width="1264" height="843" alt="image" src="https://github.com/user-attachments/assets/33f47b3f-55c9-4661-be19-8b107e315d13" />

# MappingExpo — Referência Completa de Uso

Toda flag, todo modo, toda combinação — explicados.

```
 ___
__H__       xploits3c.github.io/DorkEye
 [d]
 [e]
 [;]    MappingExpo Project
 |_|
  V
```

---

## 🗂️ Navegação

[![Core Flags](https://img.shields.io/badge/Core_Flags-0077BB?style=flat-square)](#-flags-principais)
[![Detection & Stealth](https://img.shields.io/badge/Detection_%26_Stealth-0077BB?style=flat-square)](#-detecção--stealth)
[![XSS Detection](https://img.shields.io/badge/XSS_Detection-0077BB?style=flat-square)](#-detecção-xss)
[![SQLi Detection](https://img.shields.io/badge/SQLi_Detection-0077BB?style=flat-square)](#-sqli---detecção-de-sql-injection)
[![Dork Generator](https://img.shields.io/badge/Dork_Generator-0077BB?style=flat-square)](#-gerador-de-dorks)
[![Analysis Pipeline](https://img.shields.io/badge/Analysis_Pipeline-0077BB?style=flat-square)](#-pipeline-de-análise-pós-busca)
[![Recursive Crawl](https://img.shields.io/badge/Recursive_Crawl-0077BB?style=flat-square)](#-crawl-recursivo-adaptativo)
[![Interrupt Control](https://img.shields.io/badge/Interrupt_Control-0077BB?style=flat-square)](#-controle-de-interrupção)
[![Termux](https://img.shields.io/badge/Termux_%2F_Android-0077BB?style=flat-square)](#-termux--android)
[![Combinations](https://img.shields.io/badge/Recommended_Combos-0077BB?style=flat-square)](#-combinações-recomendadas)
[![Flag Reference](https://img.shields.io/badge/Complete_Flag_Reference-0077BB?style=flat-square)](#-referência-completa-de-flags)

---

## 📌 Sintaxe Básica

```bash
python3 mappingexpo.py [OPTIONS]
```

O MappingExpo opera em **cinco modos distintos**, cada um disparado por flags diferentes:

| Modo | Gatilho | Descrição |
|---|---|---|
| **Wizard interativo** | `--wizard` | Sessão guiada por menus |
| **Busca de dorks** | `-d` | Busca com dorks manuais ou de arquivo |
| **Gerador de Dorks** | `--dg` | Gera dorks automaticamente a partir de templates YAML |
| **Teste direto de URL** | `-u` | Testa uma URL única para SQLi / XSS |
| **Recarga de arquivo** | `-f` | Reprocessa resultados salvos (SQLi / XSS / analyze / crawl) |

Mínimo exigido: pelo menos um de `-d`, `--dg`, `-u` ou `-f`. A saída `-o` é gerada automaticamente se omitida.

---

## ══════════════════════════════════════════
## FLAGS PRINCIPAIS
## ══════════════════════════════════════════

### 🔹 `--wizard` — Modo Interativo

Abre uma sessão totalmente guiada com menus numerados. Cobre busca de dorks, geração de dorks, análise e crawl — sem precisar de flags.

```bash
python3 mappingexpo.py --wizard
```

O wizard vai perguntar:

- Dork de entrada (string única ou arquivo)
- Resultados por dork
- Toggles de SQLi / XSS / stealth / fingerprinting
- Tipo de XSS (`all` / `reflected` / `stored` / `dom`)
- Nome e formato do arquivo de saída
- Análise pós-busca (se a saída for `.json`)
- Opções de crawl recursivo

---

### 🔹 `-d` / `--dork` — Entrada de Dorks

Define a consulta de busca. Aceita uma string de dork única ou um arquivo `.txt` (um dork por linha, linhas `#` ignoradas).

```bash
# Dork único
python3 mappingexpo.py -d "inurl:admin filetype:php" -o output.html

# Arquivo com vários dorks
python3 mappingexpo.py -d dorks.txt -c 100 -o output.json
```

💡 Para automação e scans em larga escala, use sempre arquivos.

---

### 🔹 `-u` / `--url` — Teste Direto de URL

Testa uma URL única diretamente para SQL injection e/ou XSS. Nenhuma busca é feita.
Habilita `--sqli` automaticamente se nem `--sqli` nem `--xss` forem especificados.

```bash
# Apenas teste SQLi
python3 mappingexpo.py -u "https://example.com/page.php?id=1" --sqli

# Apenas teste XSS
python3 mappingexpo.py -u "https://target.com/search?q=test" --xss

# SQLi e XSS juntos, com stealth e saída
python3 mappingexpo.py -u "https://example.com/page.php?id=1" --sqli --xss --stealth -o result.json
```

**A saída inclui:**

- Status de vulnerabilidade (SAFE / VULNERABLE)
- Nível de confiança (NONE → LOW → MEDIUM → HIGH → CRITICAL)
- Método de detecção, parâmetro e evidência
- Tipo(s) de XSS encontrados (reflected / stored / dom / header)
- Detecção de WAF

---

### 🔹 `-f` / `--file` — Carregar Resultados Salvos

Carrega resultados de um arquivo `.json` ou `.txt` salvo anteriormente e os reprocessa.
Combine com `--sqli`, `--xss`, `--analyze` ou `--crawl` para rodar análises adicionais sobre dados existentes.

```bash
# Re-executar SQLi em resultados salvos
python3 mappingexpo.py -f Dump/results.json --sqli -o retest.json

# Re-executar XSS em resultados salvos
python3 mappingexpo.py -f Dump/results.json --xss --xss-type=reflected -o xss_retest.json

# Rodar o pipeline de análise em resultados salvos
python3 mappingexpo.py -f Dump/results.json --analyze -o reanalyzed.json

# Reprocessamento completo: SQLi + XSS + análise + crawl
python3 mappingexpo.py -f Dump/results.json --sqli --xss --analyze --crawl -o full_retest.json
```

**Formatos aceitos:**

- `.json` — saída JSON do MappingExpo (aceita `{"results": [...]}` e `[...]` cru)
- `.txt` — uma URL por linha (linhas começando com `http`)

O arquivo é buscado primeiro no diretório atual, depois em `Dump/`.

---

### 🔹 `-o` / `--output` — Nome do Arquivo de Saída

Especifica o nome do arquivo de saída. O arquivo é salvo dentro da pasta `Dump/`.
O formato é inferido da extensão.

```bash
python3 mappingexpo.py -d dorks.txt -o results.json
python3 mappingexpo.py -d dorks.txt -o report.html
python3 mappingexpo.py -d dorks.txt -o export.csv
python3 mappingexpo.py -d dorks.txt -o links.txt
```

| Extensão | Formato | Recursos |
|---|---|---|
| `.json` | JSON estruturado | Metadados completos, estatísticas, detalhes SQLi + XSS. Habilita o prompt de `--analyze`. |
| `.html` | Relatório interativo | Tema escuro matrix, filtros, busca, painéis de export, badges SQLi + XSS, labels de WAF, navegador de arquivos, seção de export XSS |
| `.csv` | Pronto para planilha | Todas as colunas, incluindo status SQLi, status XSS, tipos, WAF, confiança |
| `.txt` | Texto puro | Lista numerada com detalhes por resultado, incluindo status SQLi e XSS |

Se `-o` for omitido, o MappingExpo gera automaticamente `report_YYYYMMDD_HHMMSS.html`.

💡 Usar saída `.json` dispara automaticamente o prompt de análise pós-busca.

---

### 🔹 `-c` / `--count` — Resultados por Dork

Limita o número máximo de resultados buscados por consulta de dork. Default: **50**.

```bash
python3 mappingexpo.py -d dorks.txt -c 200 -o output.html
```

**Observações:**

- Valores altos = scans mais lentos e maior risco de rate limit
- Use `--stealth` quando `-c > 100`
- O MappingExpo aplica automaticamente delays estendidos a cada 100 resultados (configurável)

---

### 🔹 `--config` — Arquivo de Configuração Customizado

Carrega um arquivo de configuração YAML ou JSON que sobrepõe os defaults.

```bash
python3 mappingexpo.py -d dorks.txt --config custom_config.yaml -o scan.json
```

Configurações disponíveis incluem: mapa de extensões, blacklist/whitelist, timeouts, contagem de retries, modo stealth, fingerprinting, detecção SQLi, detecção XSS, tipo de XSS e o limiar de delay estendido.

Veja `--create-config` para gerar um template inicial.

---

### 🔹 `--create-config` — Gerar Config Default

Grava um `mappingexpo_config.yaml` de exemplo em disco.

```bash
python3 mappingexpo.py --create-config
```

---

## ══════════════════════════════════════════
## DETECÇÃO & STEALTH
## ══════════════════════════════════════════

### 🔹 `--stealth` — Modo Stealth

Reduz riscos de detecção e rate limit aumentando delays e randomização.

```bash
python3 mappingexpo.py -d dorks.txt --stealth -o stealth_scan.html
```

**O que ativa:**

- Delays aleatórios estendidos entre requisições (multiplicador de 1,4×–1,8×)
- Esperas mais longas entre dorks
- Pausas estendidas de rate limit (120–150s vs. 85–110s)
- Delays adicionais durante os testes de SQLi e XSS

✅ Fortemente recomendado para: alvos sensíveis, scans longos, testes SQLi/XSS, valores altos de `-c`.

---

### 🔹 `--no-fingerprint` — Desabilitar Fingerprint HTTP

Desabilita o sistema de rotação de fingerprint de navegador. Faz fallback para rotação básica de User-Agent.

```bash
python3 mappingexpo.py -d dorks.txt --no-fingerprint -o output.html
```

Por default, o MappingExpo carrega `http_fingerprints.json` e rota perfis completos de navegador (User-Agent, Accept, Accept-Language, Accept-Encoding, Sec-Fetch-*, Cache-Control) para imitar tráfego real de navegador.

---

### 🔹 `--no-analyze` — Desabilitar Análise de Arquivos

Pula a análise HEAD de arquivos para scans mais rápidos. Sem checagens de tamanho, content-type ou acessibilidade.

```bash
python3 mappingexpo.py -d dorks.txt --no-analyze -o fast_scan.txt
```

| Modo | Velocidade | Metadados |
|---|---|---|
| Default | Média | Tamanho do arquivo, content-type, status HTTP |
| `--no-analyze` | Rápida | Nenhum |

---

### 🔹 `--blacklist` — Lista Negra de Extensões

Exclui tipos específicos de arquivo dos resultados.

```bash
python3 mappingexpo.py -d "site:target.com" --blacklist .jpg .png .gif -o no_images.html
```

---

### 🔹 `--whitelist` — Lista Branca de Extensões

Inclui apenas tipos específicos de arquivo. Todas as outras extensões são ignoradas.

```bash
python3 mappingexpo.py -d "site:target.com" --whitelist .pdf .xls .docx -o documents.html
```

---

## ══════════════════════════════════════════
## DETECÇÃO XSS
## ══════════════════════════════════════════

### 🔹 `--xss` — Detecção XSS

Habilita o engine multi-método de detecção XSS em todas as URLs descobertas. Funciona junto de `--sqli` ou sozinho.

```bash
# XSS numa busca de dorks
python3 mappingexpo.py -d "inurl:search?q=" --xss -o xss_scan.html

# XSS + SQLi combinados
python3 mappingexpo.py -d dorks.txt --sqli --xss -o full_scan.json

# XSS numa URL direta
python3 mappingexpo.py -u "https://target.com/search?q=test" --xss

# XSS em resultados salvos
python3 mappingexpo.py -f Dump/results.json --xss -o xss_retest.json
```

---

### 🔹 `--xss-type` — Escopo da Detecção XSS

Limita o teste XSS a um método específico. Default: `all`.

```bash
python3 mappingexpo.py -d dorks.txt --xss --xss-type=reflected -o reflected.json
python3 mappingexpo.py -d dorks.txt --xss --xss-type=stored    -o stored.json
python3 mappingexpo.py -d dorks.txt --xss --xss-type=dom       -o dom.json
python3 mappingexpo.py -d dorks.txt --xss --xss-type=all       -o full_xss.json
```

---

### 🔹 Pipeline de Detecção XSS (4 métodos)

Os quatro métodos rodam em sequência quando `--xss-type=all`. Cada um é totalmente independente e pode ser selecionado individualmente.

#### Método 1 — Reflected

Injeta payloads em parâmetros GET e verifica reflexão sem escape na resposta.

**51 payloads no total** em duas camadas:

| Camada | Contagem | Exemplos |
|---|---|---|
| Padrão | 29 | `<script>`, `<svg/onload>`, `<img onerror>`, eventos autofocus, MathML, `formaction`, quebra de atributo |
| WAF bypass | 16 | Mistura de caixa, dupla codificação de URL, inserção de comentário (`<scr<!---->ipt>`), tab/newline em tags, iframe via data URI, atributos backtick |
| OOB | 6 | Callback blind via parâmetro `oob_url` da API (endpoint interactsh) |

**Redução de falso positivo:**

- Pula respostas com `Content-Type` não-HTML (JSON, XML, texto puro)
- Verifica que a estrutura completa da tag sobrevive, não só a palavra marker
- Rejeita reflexão dentro de `<!-- comentários HTML -->`
- Rejeita reflexão onde escape `\u003C` é detectado num bloco `<script>`
- Usa janela de contexto de 60 chars (vs 20 nas versões anteriores)

**Confiança:**
- `HIGH` quando sem escape e sem CSP
- `MEDIUM` quando sem escape, mas com `Content-Security-Policy` presente (sem `unsafe-inline`)

#### Método 2 — Stored

Envia payloads via POST em cada parâmetro individualmente (não todos de uma vez), depois refaz a página via GET e verifica persistência.

Detecção em dois estágios:

| Estágio | Gatilho | Confiança |
|---|---|---|
| Estágio 1 | Payload ecoado na resposta imediata do POST | MEDIUM |
| Estágio 2 | Payload persiste na requisição GET subsequente | HIGH |

Gate de content-type aplicado tanto na resposta do POST quanto no refetch GET.

#### Método 3 — DOM

Baixa a página, extrai blocos `<script>` inline e até 5 arquivos `.js` externos, e então realiza análise estática source-to-sink.

**Sources detectados:** `location.hash`, `location.search`, `location.href`, `document.URL`, `document.documentURI`, `document.referrer`, `window.name`, `history.state`

**Sinks detectados:** `document.write`, `innerHTML =`, `outerHTML =`, `eval()`, `setTimeout("…")`, `location.href =`, `insertAdjacentHTML`, `.setAttribute("src"/"href"/"on*")`, `document.createElement("script")`

**Redução de falso positivo:**
- Source e sink precisam coexistir no **mesmo bloco deslizante de 40 linhas** — não é usado matching global de página
- Linhas de analytics, escritas de string estática e comentários de código são excluídas antes da análise
- Confiança `LOW` para um único par source/sink, `MEDIUM` para 2+ pares distintos no mesmo bloco

#### Método 4 — Header

Injeta o marker XSS em headers de requisição HTTP que alguns servidores refletem de volta em páginas de erro, saída de debug ou interfaces de log-replay.

**Headers testados:** `X-Forwarded-For` · `Referer` · `User-Agent` · `X-Forwarded-Host` · `X-Original-URL`

Confiança: `HIGH` em reflexão sem escape. Gate de content-type aplicado por resposta.

---

### 🔹 Pontuação de Confiança XSS

A confiança de cada método individual é agregada numa pontuação geral:

| Pontuação | Confiança geral |
|---|---|
| ≥ 5 | CRITICAL |
| ≥ 3 | HIGH |
| ≥ 2 | MEDIUM |
| < 2 | LOW |

---

### 🔹 Saída de Terminal XSS

```
[!] XSS potencial encontrado (high) [reflected]: https://target.com/search?q=test
    ↳ tipo: reflected [payload: "><script>alert("MPXSS7x")</script>]  evidência: Reflexão sem escape no parâmetro [q]: ...
```

---

### 🔹 Formatos de Saída XSS

Os resultados XSS são persistidos em todos os formatos de saída:

| Formato | Dados XSS incluídos |
|---|---|
| `.json` | dict `xss_test` por resultado; metadados: `xss_detection_enabled`, `xss_type`, `xss_vulnerabilities_found` |
| `.html` | Coluna XSS na tabela de resultados; banner de alerta XSS; contador de estatísticas XSS; submenu de filtro XSS (VULN / SAFE); seção de export XSS no painel de Links (todos os testados / vuln / safe) |
| `.csv` | Colunas `xss_vulnerable`, `xss_types`, `xss_confidence` |
| `.txt` | Linha `XSS: VULNERABLE (high) [reflected, stored]` por resultado |

---

## ══════════════════════════════════════════
## SQLi — DETECÇÃO DE SQL INJECTION
## ══════════════════════════════════════════

### 🔹 `--sqli` — Detecção de SQL Injection

Habilita o engine multi-método de detecção SQLi em todas as URLs descobertas.

```bash
python3 mappingexpo.py -d "site:example.com .php?id=" --sqli -o sqli_scan.html
```

---

### 🔹 Pipeline de Detecção SQLi (7 métodos)

| Método | Descrição | Confiança |
|---|---|---|
| **Error-based** | Injeta payloads que disparam assinaturas de erro específicas de banco (MySQL, PostgreSQL, MSSQL, SQLite, Oracle) | HIGH |
| **UNION-based** | Sonda a contagem de colunas com `UNION SELECT NULL,…` e detecta erros de mismatch ou anomalias de resposta | MEDIUM–HIGH |
| **Boolean blind** | Compara tamanhos de resposta de pares de condição true/false com filtragem estatística de ruído | MEDIUM |
| **Time-based blind** | Mede delays induzidos por `SLEEP()` acima do baseline + margem | MEDIUM |
| **Stacked queries** | Injeta após `;` — mira PDO multi-statement, stored procedures, APIs que executam múltiplas queries | HIGH |
| **Heavy query time** | Delays intensivos de CPU sem `SLEEP`/`WAITFOR` — bypassa WAFs que bloqueiam essas keywords | MEDIUM |
| **Header injection** | Injeta em `X-Forwarded-For`, `X-Real-IP`, `User-Agent`, `Referer`, `CF-Connecting-IP` | MEDIUM–HIGH |

**Contagens de payloads:**

| Método | Payloads |
|---|---|
| Error-based | 8 (+ updatexml, erro BENCHMARK, CONVERT MSSQL, cast PG, XMLType Oracle) |
| UNION-based | 4 × 5 profundidades de coluna |
| Boolean blind | 4 pares true/false |
| Time-based | 6 (+ WAITFOR MSSQL, pg_sleep PG, dbms_pipe Oracle, bypass OR SLEEP) |
| Stacked queries | 11 |
| Heavy query | 12 |
| Header injection | 5 headers × error + boolean |

---

### 🔹 Recursos Adicionais SQLi

- Ordenação por prioridade de parâmetro: alto risco (`id`, `page`, `cat`) → médio (`search`, `q`) → baixo
- Probe adaptativo de ruído antes de cada teste de parâmetro
- Detecção de WAF (12 provedores: Cloudflare, ModSecurity, Wordfence, Sucuri, Imperva, Akamai, F5 BigIP, Barracuda, FortiWeb, AWS WAF, DenyAll, Reblaze)
- Circuit breaker: pula automaticamente hosts inalcançáveis
- Pontuação de confiança: NONE → LOW → MEDIUM → HIGH → CRITICAL (limiar `best >= 6`)
- Injeção POST e JSON disponível via `SQLiDetector.test_post_sqli()` e `test_json_sqli()`

---

### 🔹 Saída de Terminal SQLi

```
[!] SQLi potencial encontrado (critical): https://target.com/product.php?id=7
    ↳ método: error_based [parâmetro: id]  evidência: assinatura de erro MYSQL: extractvalue(0,...
    ↳ método: time_based_blind         evidência: SLEEP(3) decorrido=3.4s > limiar=3.2s
```

---

## ══════════════════════════════════════════
## GERADOR DE DORKS
## ══════════════════════════════════════════

### 🔹 `--dg` — Ativar o Gerador de Dorks

Gera Google dorks estruturados a partir de arquivos de template YAML. Substitui a escrita manual de dorks por um engine escalável baseado em categorias.

```bash
# Todas as categorias, modo soft (default)
python3 mappingexpo.py --dg

# Categoria específica
python3 mappingexpo.py --dg=sqli
python3 mappingexpo.py --dg=backups
python3 mappingexpo.py --dg=sensitive
python3 mappingexpo.py --dg=admin

# Todas as categorias, explícito
python3 mappingexpo.py --dg=all
```

**Nota de arquitetura:** `--dg` controla a *geração de dorks*. `--sqli` e `--xss` controlam a *detecção de vulnerabilidades*. São totalmente independentes.

```bash
# Gerar dorks SQLi E testá-los para SQLi E XSS
python3 mappingexpo.py --dg=sqli --sqli --xss --mode=aggressive -o report.html
```

---

### 🔹 `--mode` — Modo de Geração

Controla a intensidade de geração de dorks. Default: `soft`.

| Modo | Comportamento |
|---|---|
| `soft` | Seguro, pegada mínima. Menos combinações. |
| `medium` | Cobertura equilibrada. |
| `aggressive` | Cobertura máxima. Todas as expansões de variáveis. |

```bash
python3 mappingexpo.py --dg=all --mode=aggressive -o results.json
```

---

### 🔹 `--templates` — Seleção de Arquivo de Template

Especifica qual arquivo de template YAML usar do diretório `Templates/`. Use a sintaxe com `=` (sem espaço).

```bash
# Template padrão
python3 mappingexpo.py --dg=sqli --templates=dorks_templates.yaml

# Todos os arquivos YAML de Templates/
python3 mappingexpo.py --dg=all --templates=all

# Template de pesquisa específico
python3 mappingexpo.py --dg=backups --templates=dorks_templates_research.yaml
```

---

### 🔹 `--dg-max` — Máximo de Combinações de Dorks

Limita o número máximo de combinações de dorks geradas por template. Default: **800**.

```bash
python3 mappingexpo.py --dg=all --dg-max=10000 -o big_scan.json
```

---

## ══════════════════════════════════════════
## PIPELINE DE ANÁLISE PÓS-BUSCA
## ══════════════════════════════════════════

O pipeline de análise é movido pelo `mappingexpo_agents.py` e roda análise pós-busca autônoma: triage, fetch de páginas, detecção de segredos, PII e geração de relatório — sem IA externa.

### 🔹 `--analyze` — Habilitar o Pipeline de Análise

Roda o pipeline completo de análise após a busca terminar. Prompt automático quando a saída é `.json`.

```bash
# Ativação explícita
python3 mappingexpo.py -d dorks.txt -o results.json --analyze

# Também funciona com modo arquivo
python3 mappingexpo.py -f Dump/results.json --analyze -o reanalyzed.json
```

**Estágios do pipeline:**

1. **TriageAgent** — Prioriza resultados por nível de risco (SQLi/XSS confirmados ganham pontos de bônus)
2. **PageFetchAgent** — Baixa o conteúdo das páginas (se `--analyze-fetch`)
3. **SecurityAgent** — Veredito de ameaça por resultado (phishing/malware/exploit/ofuscação)
4. **HeaderIntelAgent** — Analisa headers de resposta (vazamentos de info, headers ausentes)
5. **TechFingerprintAgent** — Detecta CMS/frameworks/versões e gera dorks de CVE
6. **SecretsAgent** — Detecta credenciais, API keys, tokens, dados sensíveis
7. **PiiDetectorAgent** — Detecta PII (CPF/CNPJ/CEP/Pix BR, cartões, SSN, DOB)
8. **EmailHarvesterAgent** — Coleta e categoriza e-mails
9. **SubdomainHarvesterAgent** — Extrai subdomínios e gera dorks de follow-up
10. **ReportAgent** — Gera o relatório de análise
11. **DBPortScanAgent** — Varredura de portas DB expostas (opt-in: `--dbscan`)

---

### 🔹 `--analyze-fetch` — Habilitar Download de Páginas

Baixa o conteúdo real das páginas dos resultados de prioridade HIGH/CRITICAL, habilitando detecção mais profunda de segredos.

```bash
python3 mappingexpo.py -d dorks.txt -o results.json --analyze --analyze-fetch
```

---

### 🔹 `--analyze-fetch-max` — Máximo de Páginas a Baixar

Limita o número de páginas baixadas durante a análise. Default: **20**.

```bash
python3 mappingexpo.py --dg=sqli -o results.json --analyze --analyze-fetch --analyze-fetch-max=5000
```

---

### 🔹 `--analyze-fmt` — Formato do Relatório de Análise

Define o formato de saída do relatório de análise. Default: `html`.

| Formato | Extensão |
|---|---|
| `html` | Relatório HTML interativo |
| `md` | Markdown |
| `json` | JSON estruturado |
| `txt` | Texto puro |

```bash
python3 mappingexpo.py -d dorks.txt -o results.json --analyze --analyze-fmt=md
```

---

### 🔹 `--analyze-out` — Path do Relatório de Análise

Path customizado para o relatório de análise. Default: gerado automaticamente junto do arquivo `-o`.

```bash
python3 mappingexpo.py -d dorks.txt -o results.json --analyze --analyze-out=custom_report.html
```

---

## ══════════════════════════════════════════
## CRAWL RECURSIVO ADAPTATIVO
## ══════════════════════════════════════════

O crawler (`DorkCrawlerAgent`) faz refinamento automático de múltiplas rodadas: analisa os resultados iniciais, extrai padrões (domínios, paths, tecnologias, extensões), gera novos dorks refinados e busca de novo — iterando até retornos decrescentes.

### 🔹 `--crawl` — Habilitar Crawl Recursivo

Ativa o crawl adaptativo após a busca inicial.

```bash
python3 mappingexpo.py -d "site:example.com inurl:admin" --crawl -o crawl.json
```

Novos resultados do crawl são mesclados com os resultados iniciais e salvos juntos.

---

### 🔹 `--crawl-rounds` — Máximo de Rodadas de Crawl

```bash
python3 mappingexpo.py --dg=sqli --crawl --crawl-rounds=5 -o crawl.json
```

---

### 🔹 `--crawl-max` — Máximo Total de Resultados do Crawl

```bash
python3 mappingexpo.py -d dorks.txt --crawl --crawl-max=200 -o crawl.json
```

---

### 🔹 `--crawl-per-dork` — Resultados por Dork do Crawl

```bash
python3 mappingexpo.py -d dorks.txt --crawl --crawl-per-dork=30 -o crawl.json
```

---

### 🔹 `--crawl-stealth` — Crawl Stealth

Aplica delays mais longos durante as rodadas de crawl.

```bash
python3 mappingexpo.py -d dorks.txt --crawl --crawl-stealth -o crawl.json
```

---

### 🔹 `--crawl-report` — Gerar Relatório de Crawl

```bash
python3 mappingexpo.py --dg=sqli --crawl --crawl-rounds=5 --crawl-report -o crawl.json
```

---

### 🔹 `--crawl-out` — Path do Relatório de Crawl

```bash
python3 mappingexpo.py -d dorks.txt --crawl --crawl-stealth --crawl-out=crawl_report.html -o crawl.json
```

---

## ══════════════════════════════════════════
## CONTROLE DE INTERRUPÇÃO
## ══════════════════════════════════════════

O MappingExpo suporta tratamento de interrupção elegante em todas as operações:

| Ação | Efeito |
|---|---|
| **Ctrl+C único** | Pula o dork / tarefa atual e vai para o próximo |
| **Ctrl+C duplo** (em até 1,5s) | Sai imediatamente, salva resultados parciais |

Funciona durante: buscas, análise de arquivos, testes SQLi/XSS, delays, análise e crawl. O sinal de interrupção se propaga automaticamente para os sub-módulos `sqli.py` e `xss.py`.

---

## ══════════════════════════════════════════
## TERMUX / ANDROID
## ══════════════════════════════════════════

O MappingExpo detecta o Termux no Android automaticamente e ativa o modo economia de bateria:

- Menos amostras de baseline para latência SQLi
- Contagens menores de amostras de probe e booleanas
- Timeouts de conexão mais curtos
- Menos rodadas de confirmação time-based

Sem flags — a detecção é automática.

---

## ══════════════════════════════════════════
## COMBINAÇÕES RECOMENDADAS
## ══════════════════════════════════════════

### Stealth Profissional — SQLi + XSS + Análise

```bash
python3 mappingexpo.py -d dorks.txt --stealth --sqli --xss -c 150 -o pro_scan.json --analyze --analyze-fetch
```

### Apenas XSS — Tipo Reflected, Stealth

```bash
python3 mappingexpo.py -d "inurl:search?q=" --xss --xss-type=reflected --stealth -o xss_reflected.html
```

### Scan Completo de Vulnerabilidades — Gerador + SQLi + XSS

```bash
python3 mappingexpo.py --dg=all --mode=aggressive --sqli --xss -c 80 -o full_scan.json
```

### Recon Rápido (Sem Análise)

```bash
python3 mappingexpo.py -d dorks.txt --no-analyze -c 200 -o recon.txt
```

### Colheita de Documentos

```bash
python3 mappingexpo.py -d "site:.gov" --whitelist .pdf .docx .xlsx -o docs.html
```

### Pipeline Completo — Gerar + Buscar + SQLi + XSS + Analisar + Crawl

```bash
python3 mappingexpo.py \
  --dg=sqli \
  --mode=aggressive \
  --sqli \
  --xss \
  --stealth \
  -c 80 \
  -o full_report.json \
  --analyze \
  --analyze-fetch \
  --crawl \
  --crawl-rounds=4 \
  --crawl-report
```

### Re-testar Resultados Salvos — SQLi + XSS

```bash
python3 mappingexpo.py -f Dump/old_results.json --sqli --xss --analyze --crawl -o retested.json
```

### URL Direta — Teste SQLi + XSS

```bash
python3 mappingexpo.py -u "https://target.com/item.php?id=42" --sqli --xss --stealth -o direct_test.json
```

### Análise Standalone em Arquivo Salvo

```bash
python3 mappingexpo_analyze.py Dump/results.json --fetch --fmt=html
```

---

## ══════════════════════════════════════════
## REFERÊNCIA COMPLETA DE FLAGS
## ══════════════════════════════════════════

| Flag | Tipo | Default | Descrição |
|---|---|---|---|
| `--wizard` | flag | — | Abre o wizard interativo |
| `-d` / `--dork` | string | — | String de dork única ou arquivo `.txt` |
| `-u` / `--url` | string | — | URL direta para teste SQLi / XSS |
| `-f` / `--file` | string | — | Carrega resultados de `.json` / `.txt` salvo |
| `-o` / `--output` | string | auto | Nome do arquivo de saída (salvo em `Dump/`) |
| `-c` / `--count` | int | 50 | Resultados por dork |
| `--config` | string | — | Arquivo de config YAML/JSON customizado |
| `--create-config` | flag | — | Gera o `mappingexpo_config.yaml` de exemplo |
| `--sqli` | flag | off | Habilita detecção de SQL injection |
| `--xss` | flag | off | Habilita detecção XSS (reflected, stored, DOM, header) |
| `--xss-type` | string | `all` | Escopo XSS: `reflected` / `stored` / `dom` / `header` / `all` |
| `--stealth` | flag | off | Habilita modo stealth |
| `--no-fingerprint` | flag | off | Desabilita fingerprinting HTTP |
| `--no-analyze` | flag | off | Desabilita análise de arquivos (requisições HEAD) |
| `--blacklist` | list | — | Extensões a excluir (ex.: `.jpg .png`) |
| `--whitelist` | list | — | Extensões a incluir exclusivamente |
| `--dg` | string | — | Ativa o gerador de dorks (`all` ou categoria) |
| `--dg-max` | int | 800 | Máximo de combinações de dorks por template |
| `--mode` | string | soft | Modo de geração: `soft` / `medium` / `aggressive` |
| `--templates` | string | default | Arquivo de template em `Templates/` (use sintaxe `=`) |
| `--analyze` | flag | off | Roda o pipeline de análise pós-busca |
| `--analyze-fetch` | flag | off | Baixa páginas durante a análise |
| `--analyze-fetch-max` | int | 20 | Máximo de páginas a baixar |
| `--analyze-fmt` | string | html | Formato do relatório: `html` / `md` / `json` / `txt` |
| `--analyze-out` | string | auto | Path customizado do relatório de análise |
| `--crawl` | flag | off | Habilita crawl recursivo adaptativo |
| `--crawl-rounds` | int | — | Máximo de rodadas de refinamento do crawl |
| `--crawl-max` | int | — | Máximo total de resultados do crawl |
| `--crawl-per-dork` | int | — | Resultados por dork de crawl gerado |
| `--crawl-stealth` | flag | off | Delays stealth durante o crawl |
| `--crawl-report` | flag | off | Gera relatório HTML do crawl |
| `--crawl-out` | string | auto | Path customizado do relatório de crawl |

---

## ⚠️ Aviso Legal

Use **somente** em:

- Alvos autorizados
- Dados públicos
- Ambientes educacionais / de pesquisa

Atacar alvos sem consentimento mútuo prévio é ilegal.
É responsabilidade do usuário final obedecer a todas as leis locais, estaduais e federais aplicáveis.

Poder sem controle é ruído. Seja preciso. Seja ético.
