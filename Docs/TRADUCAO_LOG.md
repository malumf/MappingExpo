# Log de Tradução PT-BR — MappingExpo

Regras da fase: traduzir apenas strings visíveis ao usuário e documentação
interna. Lógica, payloads, nomes, imports, chaves de config e paths
preservados. Backups em `.traducao_backup/`. Nada commitado.

---

## 2026-10-14 12:20 — Tools/dork_generator.py

- **Backup**: `.traducao_backup/dork_generator.py.20261014_121655.bak`
- **Linhas alteradas**: 33 (verificado via `git diff --stat`: 33 insertions / 33 deletions)
- **Strings traduzidas**: 27 unidades
  - 3 mensagens visíveis (2 exceptions + 1 print de aviso)
  - 8 blocos de docstring
  - 12 comentários inline
  - 4 cabeçalhos de seção
- **Verificação**: `python -m py_compile` — SINTAXE OK
- **Correção aplicada na aprovação**: L200 `# INTROSPECÇÃO` (Ç único, conforme revisão)
- **Não tocado (deliberadamente)**:
  - L1–2 (autor/marca — fase de rename posterior)
  - Chaves do dict `get_stats()` (consumidas por `dorkeye_web.py`)
  - Termos técnicos mantidos: placeholder, template, dedup→"deduplicação" no texto

---

## 2026-10-14 12:35 — Templates/example.yaml + Templates/sql.yaml

- **Backups**: `.traducao_backup/example.yaml.20261014_123502.bak`,
  `.traducao_backup/sql.yaml.20261014_123502.bak`
- **Linhas alteradas**: 7 (example.yaml: 2 · sql.yaml: 5 — verificado via `git diff --stat`: 7 insertions / 7 deletions)
- **Strings traduzidas**: 7 unidades (todos comentários descritivos)
- **Verificação**: `git diff` inspecionado — apenas linhas de comentário; estrutura YAML intacta (PyYAML indisponível no ambiente, validação por inspeção)
- **Não tocado (deliberadamente)**:
  - L1 de ambos (referência ao autor original — preservada)
  - Valores de `sqli_errors`, `param`, `extension`, `domain` (strings de busca literais)
  - Dorks e chaves `mode: soft|medium|aggressive` (Fase 2 — regionalização BR)

---

## 2026-10-14 13:15 — Tools/dorkeye_patterns.py

- **Backup**: `.traducao_backup/dorkeye_patterns.py.20261014_131249.bak`
- **Linhas alteradas**: 178 (verificado via `git diff --stat`: 178 insertions / 178 deletions)
- **Strings traduzidas**: ~120 unidades
  - Lote A: docstring do módulo + 3 docstrings de função + ~40 comentários (incl. caixa ASCII com padding recalculado)
  - Lote B: 26 hints do TRIAGE_RULES
  - Lote C: 23 descriptions do SECRET_RULES + 22 do PII_RULES
- **Ajustes da aprovação**: "code injection hint" → "indício de injeção de código"; L53 `# ── Aliases de tipo` com traços originais preservados
- **Verificações**:
  - `python -m py_compile` — SINTAXE OK
  - **Verificação programática (backup vs. atual, via importlib)**: regex, flags, scores, categorias, severidades, FETCH_UA/POOL e SKIP_EXTENSIONS **100% idênticos**; divergências = 0. Descriptions alteradas exatamente como aprovado (TRIAGE=26, SECRET=23, PII=22; totais 28/48/24)
  - Consumo verificado antes: descriptions de patterns.py são display-only (analyze.py L381/482, agents.py L1548/1789/2339) — nenhum código compara seu texto
- **Mantidos (nomes próprios/formatos)**: AWS Access Key ID, Stripe/GitHub/Slack/Twilio/SendGrid/Mailgun API Key, Bcrypt/MD5/SHA-1/SHA-256/SHA-512/NTLM hash, IBAN, Emirates ID, Client secret, Bearer token, VAT, PAN, Aadhaar, NRIC etc.
- **Nota para fase posterior**: em `dorkeye_agents.py:946` existe `if "impersonation" in desc.lower()` — as descriptions do `_SecurityPatternDB` NÃO poderão ser traduzidas livremente quando agents.py for traduzido (são lógica, não só display)

---

## 2026-10-14 14:35 — Tools/dorkeye_analyze.py

- **Backup**: `.traducao_backup/dorkeye_analyze.py.20261014_142837.bak`
- **Linhas alteradas**: 150 (verificado via `git diff --stat`: 150 insertions / 150 deletions)
- **Strings traduzidas**: ~100 unidades
  - Lote A: 12 blocos de docstring (módulo + classes/funções; incl. 6 blocos com resíduo italiano)
  - Lote B: 22 comentários (incl. italianos L269, L294, L637, L669, L686, L702, L722–723, L850)
  - Lote C: 19 prints/logs (`[Report]` → `[Relatório]`; tags [Triage]/[Fetch]/[Secrets] mantidas)
  - Lote D: 17 argparse + CLI (description, epílogo "Esempi:"→"Exemplos:", helps, mensagens de erro)
  - Lote E: ~28 strings de template — `lang="it"` → `lang="pt-BR"`, HTML/MD/TXT traduzidos
- **Verificações**:
  - `python -m py_compile` — SINTAXE OK
  - **Verificação programática (AST mascarado, backup vs. atual)**: árvores idênticas com todas as strings substituídas por placeholder — prova que NOMES, ASSINATURAS, NÚMEROS, REGEX (`_SCRIPT_STYLE_RE_FALLBACK`), chaves de dict e estrutura não mudaram
  - Incidente de ferramenta: entidades HTML (`&`, `&#9888;`) no parâmetro de edição são decodificadas — contornado editando por segmentos sem entidade; resultado final na L529 verificado
- **Decisões confirmadas na aprovação**: "Autore:" → "Autor:" (só rótulo) · brand "DorkEye Analyzer" preservado, "Report" → "Relatório" · labels CRITICAL/HIGH/MEDIUM/LOW/SKIP mantidos (lógica) · `dorkeye_local_analysis_<ts>.<fmt>` intacto
- **Não tocado**: `Accept-Language: en-US,en;q=0.9,it;q=0.8` (L282, fingerprint — fase posterior), `verify=False`, chaves de dicts, JSON keys (meta/generated_at/target/engine) e valor brand do engine

### Anotações para fases futuras (registradas por determinação do aprovador)
1. **Fase rename**: o path default `dorkeye_local_analysis_<ts>.<fmt>` será renomeado para `mappingexpo_local_analysis_<ts>.<fmt>` — afeta docs e qualquer script que referencie o path
2. **Fase agents.py (REFORÇO)**: `dorkeye_agents.py:946` — `if "impersonation" in desc.lower()` — as descriptions do `_SecurityPatternDB` NÃO podem ser traduzidas livremente; o texto é usado como lógica de matching

---

## 2026-10-14 15:00 — Tools/db_portscan.py

- **Backup**: `.traducao_backup/db_portscan.py.20261014_145249.bak`
- **Linhas alteradas**: 144 (verificado via `git diff --stat`: 144 insertions / 144 deletions)
- **Strings traduzidas**: ~95 unidades
  - Lote A: 16 docstrings (módulo + 4 probes + agent + report + save)
  - Lote B: ~45 comentários (incl. cabeçalhos de seção, comentários do pacote BSON)
  - Lote C: ~19 probe details/logs — **verificados contra o check de confirmação L423–429** (keywords "mongo"/"redis"/"memcache"/"Memcached" preservadas nos textos; cases no_auth=True não passam pelo check)
  - Lote D: 21 strings do TXT report + CLI
- **Verificações** (todas PASSARAM):
  - `python -m py_compile` — SINTAXE OK
  - AST mascarado idêntico (nomes, números, portas, estrutura)
  - 14 chamadas de regex com source segment idêntico ao backup
  - `DORK_PORT_HINTS`: 12 regras, listas de portas idênticas
  - `DB_PORT_CATALOGUE`: 19 entradas idênticas (porta/nome/probe/path/keys/default_db)
- **Decisões confirmadas na aprovação**: keywords de confirmação preservadas · Accept-Language intacto (não existe neste arquivo; referência era do analyze L282) · badges `[ Open ]/[ Closed ]` mantidos (espelham status) · UA "DorkEye DBScan/1.0" intacto · brand "DorkEye — Relatório de Varredura de Portas DB" consistente com analyze
- **Flags para Fase 0 (saneamento ético)**: comentário L773 "TXT amigável ao Sqlmap" — tradução literal aplicada; revisar referência a ferramenta ofensiva na fase ética
- **Não tocado**: `verify=False`, status `open/closed/timeout/error`, severidades, chaves de stats, dataclass fields, `--stealth`, UA hardcoded

### Anotações para fases futuras (registradas por determinação do aprovador)
- **Fase rename**: `dorkeye_local_analysis_<ts>.<fmt>` e `dorkeye_dbscan_<ts>.json/txt` serão renomeados para `mappingexpo_*`
- **Fase agents.py**: descriptions do `_SecurityPatternDB` não traduzíveis livremente (L946 — matching por texto)

---

## 2026-10-14 15:40 — Tools/sqli.py

- **Backup**: `.traducao_backup/sqli.py.20261014_150952.bak`
- **Linhas alteradas**: 262 (verificado via `git diff --stat`: 262 insertions / 261 deletions — o +1 é uma linha em branco acrescentada dentro do docstring do `_test_time_based_blind`, cosmético)
- **Strings traduzidas**: ~155 unidades
  - G1: 38 docstrings (módulo + 37 funções/classes; marcadores [NEW-x]/[FP-x] preservados)
  - G2: 3 stderr/ValueError + 11 messages + 18 evidence (termos técnicos WAF/error-based/UNION/dual-metric/baseline/LOW/HIGH mantidos)
  - G3: ~75 comentários (incl. comentários de payload — payloads intocados)
- **Verificações** (todas PASSARAM, após refinamento metodológico):
  - `python -m py_compile` — SINTAXE OK
  - **AST normalizado** (JoinedStr → dumps das expressões dos FormattedValues): idêntico
  - 23 format specs (`:<8`, `:>2`, `:.0f`, `:.3f` etc.) idênticos
  - 110 chaves de dict idênticas
  - `SQL_ERROR_SIGNATURES` (6 chaves, 55 padrões), `WAF_SIGNATURES` (12/32), `USER_AGENTS` (4/9), `_HIGH_PRIORITY_PARAMS` (33), `_MEDIUM_PRIORITY_PARAMS` (25) — idênticos por valor
  - Enum `SQLiConfidence` (none/low/medium/high/critical) intacto
  - 7 chamadas de regex idênticas (incl. `_UNION_COL_MISMATCH_RE`, `_SCRIPT_TAG_RE_FALLBACK`)
  - Nota metodológica: o primeiro suite de verificação deu falso-positivo — (a) AST mascarado sinalizou a tradução L1005 que adicionou uma parte literal antes de `{db_type.upper()}` num f-string (benigno, display-only); (b) source segments das estruturas nomeadas incluíam comentários traduzidos dentro dos blocos. Suite refinado (por valor) confirmou integridade total.
- **Não tocado**: todos os payloads (incl. 4 variantes WAF-bypass L960-968), assinaturas SQL/WAF, UAs, `verify=False`, enum, priority tables, chaves de dicts
- **Anotações do aprovador registradas**:
  - dorkeye.py só consome `vulnerable`/`overall_confidence`/`waf_detected` dos dicts de finding — verificado
  - Marcadores [FP-x]/[NEW-x] são referências cruzadas e permanecem em inglês em TODO o projeto
  - Payloads de sqli.py (incl. WAF-bypass) ficam para Fase 0

---

## 2026-10-14 16:10 — Tools/xss.py

- **Backup**: `.traducao_backup/xss.py.20261014_154259.bak`
- **Linhas alteradas**: 181 (verificado via `git diff --stat`: 181 insertions / 181 deletions)
- **Strings traduzidas**: ~85 unidades
  - G1: 13 docstrings (bloco `Returns:` do test_xss mantido em inglês — contrato de API)
  - G2: 22 mensagens/evidence (incl. csrf_note; 4x "WAF pré-detectado pelo pipeline")
  - G3: ~50 comentários (incl. comentários dentro de _DOM_SAFE_PATTERNS — regex intocadas; marcadores [FIX-x]/[NEW-x] preservados)
- **Verificações** (todas PASSARAM):
  - `python -m py_compile` — SINTAXE OK
  - AST normalizado idêntico · `_MARKER = 'DEXSS7x'` · payloads: _REFLECTED (44), _BYPASS (26), _STORED (5), _HEADER (4) — comprimento e conteúdo idênticos
  - _DOM_SOURCES (16), _DOM_SINKS (21), _DOM_SAFE_PATTERNS (44), _ENCODED_MARKERS (15), _PRIVATE_IP_RE (pattern+flags) — idênticos
  - _WAF_SIGNATURES_FALLBACK, _NON_HTML_CONTENT_TYPES (7), _HEADER_INJECTION_TARGETS (5), _HARDCODED_AGENTS (3) — idênticos
  - _XSS_HIGH (36) / _MEDIUM (19) PRIORITY, _CONF_RANK, enum XSSConfidence, _STRUCTURE_WINDOW=300, 55 chaves de dict, 8 chamadas de regex — idênticos
  - Nota: SyntaxWarning preexistente sobre `\s` no docstring L1270 — confirmado presente no backup original; tradução preservou o constructo (sem regressão)
- **Não tocado**: marker DEXSS7x, todos os payloads, regex de detecção, UAs/headers de fingerprint, enum, chaves de dict, valores "reflected"/"stored"/"dom"/"header", `verify=False`
- **Anotações do aprovador registradas**:
  - dorkeye.py consome de test_xss apenas `vulnerable`, `overall_confidence`, `xss_types_found`, `waf_detected`, `csp_detected` — verificado; message/evidence/csrf_note são display-only
  - _BYPASS_PAYLOADS e OOB dinâmicos ficam para Fase 0
  - **Marker DEXSS7x é intocável em TODO o projeto**

---

## 2026-10-14 16:40 — Tools/dorkeye_web.py

- **Backup**: `.traducao_backup/dorkeye_web.py.20261014_160017.bak`
- **Linhas alteradas**: 137 (verificado via `git diff --stat`: 137 insertions / 137 deletions)
- **Strings traduzidas**: ~155 unidades
  - G1 (Python ~35): 3 docstrings, comentários, 3 strings italianas (L453/464/466), erros de API, labels de job, banner do launcher
  - G2 (HTML/JS ~120): `lang="pt-BR"`, título, nav, dashboard, todos os labels/botões dos formulários, mensagens JS, 2 strings italianas (L1108/1110)
- **Decisões**: colorLine intacta (Opção B — correção coordenada com dorkeye.py) · ASCII art "DORKEYE" e logo "DORK EYE" preservados (marca — fase rename) · `DorkGen: `/`Scan: `/`Stealth` mantidos · `description='DorkEye Web Dashboard'` mantido (marca) · ` dorkeye_dorks.txt` mantido (nome de arquivo) · entidade `&` (L695) contornada editando por segmentos
- **Verificações** (todas PASSARAM):
  - `python -m py_compile` — SINTAXE OK
  - 26 segmentos de lógica intactos: colorLine (9 regex de coloração), isProgressLine (5), parseProgress, `_ANSI_RE`, `subprocess.Popen`, `stdin 'n\n'`, `SECRET_KEY`, bind 127.0.0.1 (2 formas), `debug=False`, `DORKEYE_PY`/`DUMP_DIR`/`TEMPLATES_DIR`, logger, `dorkeye_dorks_<ts>.txt`, charset do matrix rain
  - Atributos: `value=` (41), `placeholder=` (9), `id=` (99) — multisets idênticos
  - Flags CLI `--xxx`: 197 ocorrências idênticas · Rotas `/api/*`: 25 idênticas · `data-s`: 6 idênticos
  - Nota: 1 falso positivo no primeiro suite (check com escape `\u2713` vs char literal `✓` na L934) — confirmado idêntico por verificação direta
  - **Flask ausente no ambiente → teste visual do Console Web PENDENTE (operação pelo operador: `python Tools/dorkeye_web.py --port 7777`, abrir http://127.0.0.1:7777, conferir labels PT-BR e coloração do terminal)**
- **Não tocado**: `colorLine`/`isProgressLine`/`parseProgress`/`_ANSI_RE`, subprocess, bind, SECRET_KEY, paths, valores de `<select>`, placeholders, IDs HTML/JS, flags CLI, rotas, charset do matrix rain, marca DorkEye

## PENDÊNCIAS CRÍTICAS

### PENDÊNCIA CRÍTICA — colorLine (dorkeye_web.py L932-941)
- colorLine() usa regex que casam com strings emitidas por dorkeye.py:
  /VULNERABLE|error/i, /SAFE| saved |done|completed/i, /Searching|Analyz/i
- Quando dorkeye.py for traduzido, essas regex PRECISAM ser atualizadas
  para casar com as novas strings PT-BR.
- **UPDATE (decisão do aprovador)**: os badges ThreatLevel de
  dorkeye_agents.py (L618-624: "🟢 CLEAN", "🔴 DANGEROUS" etc.)
  TAMBÉM dependem de strings em inglês — mantidos em inglês por:
  (1) consistência com triage labels HIGH/LOW/MEDIUM/CRITICAL, e
  (2) integração com colorLine (casa /CRITICAL|error/i no terminal).
  Se no futuro os badges forem traduzidos, a regex do colorLine precisa
  ser atualizada coordenadamente.
- Após a tradução de dorkeye.py, TESTAR VISUALMENTE o terminal colorido
  do Console Web (abrir http://127.0.0.1:7777, rodar um scan, verificar
  que as cores continuam funcionando).
- Se as cores não funcionarem, ajustar as regex em colorLine com base
  nas strings reais emitidas.

---

## 2026-10-14 17:15 — Tools/dorkeye_agents.py — LOTE 1 (L1–600)

- **Backup**: `.traducao_backup/dorkeye_agents.py.20261014_165835.bak`
- **Linhas alteradas**: 112 (verificado via `git diff --stat`: 112 insertions / 112 deletions)
- **Strings traduzidas**: ~48 unidades
  - Docstring do módulo (pipeline de 13 agentes, middleware, usos) + 14 docstrings (BaseAgent, TriageAgent, _ScriptStyleStripper, PageFetchAgent etc.)
  - ~20 comentários (incl. bloco do cabeçalho SecurityAgent com categorias de detecção)
  - 9 prints (TriageAgent ×3, PageFetchAgent ×5, RuntimeError LLM)
- **Decisões registradas**:
  - `Author: xPloits3c` → **`Autor: xPloits3c`** (L40) — consistência com dorkeye_analyze.py, que adotou "Autor:" (original "Autore:" italiano)
  - Badges ThreatLevel (L618-624) MANTIDOS em inglês — decisão do aprovador (consistência com labels + colorLine); registrado na PENDÊNCIA CRÍTICA
  - `_SecurityPatternDB` L671-852: congelamento total confirmado (incl. docstring da classe e comentários de seção — fronteira limpa)
  - Tags compactas de reason (`sqli:critical confirmed`, `accessible:200`, `get_params:N`) mantidas — formato de dado
- **Verificações** (todas PASSARAM):
  - `python -m py_compile` — SINTAXE OK
  - `_SecurityPatternDB`: source segment byte-identical ao backup
  - 2 prompts LLM (Assign `prompt`) idênticos
  - `_CMS_DORK_TEMPLATES` (9), `_TECH_CVE_DORK_TEMPLATES` (10), `_PATH_DORK_TEMPLATES` (7), `_EXT_DORK_TEMPLATES` (11), `_TECH_SIGNATURES` (37), `_TECH_DETECTION`, `_KNOWN_SAFE_DOMAINS` (9), `_CONFUSABLES` (11), `_REDIRECT_PARAMS` (9), `_EMAIL_CATEGORIES` (4), `_EMAIL_RE`, `_OUTDATED_VERSION_RE`, `_INTERESTING_PATHS`, `_SUSPICIOUS_PARAMS`, `sec_hdrs` — todos idênticos
  - Labels CRITICAL(44)/HIGH(38)/MEDIUM(22)/LOW(33)/SKIP(13): contagens idênticas
  - AST normalizado (f-string aware): idêntico
- Lotes restantes: L2 (SecurityAgent+analisadores L595-1430) · L3 (Secrets/Report L1432-1915) · L4 (HeaderIntel→SubdomainHarvester L1916-2450) · L5 (DorkCrawler+pipeline+CLI L2451-3397)

---

## 2026-10-14 17:55 — Tools/dorkeye_agents.py — LOTE 2 (L595–1430)

- **Backup**: mesmo do Lote 1 (`.traducao_backup/dorkeye_agents.py.20261014_165835.bak`)
- **Linhas alteradas no lote**: 96 (cumulativo do arquivo: 208 insertions / 208 deletions)
- **Strings traduzidas**: ~55 unidades
  - 19 docstrings (ThreatLevel, ThreatIndicator, SecurityVerdict, to_report_line, analisadores _URL/_Content/_Header, SecurityAgent + run/scan_single, get_threats_above, generate_console_report, generate_html_section, reset, _calculate_threat_score, get_security_agent, reset_security_agent, security_scan_hook)
  - 12 descriptions inline display-only dos analisadores (L881–1073) — sem comparação de texto (grep de segurança)
  - 9 prints/linhas de relatório (incl. `to_report_line` → "Pontuação:"/"Indicadores:"; console report traduz APENAS "Total escaneado:"; ths HTML → Nível/Pontuação/Indicadores)
  - ~18 comentários (fases 1–6, cabeçalhos de seção)
- **Verificações específicas do aprovador** (todas PASSARAM):
  - `_SecurityPatternDB`: byte-identical ao backup
  - Badges ThreatLevel: 6 intactos em inglês (CLEAN/LOW/SUSPICIOUS/DANGEROUS/CRITICAL/UNKNOWN)
  - Valores de category: contagens idênticas
  - Chaves de `verdict.to_dict()`: intactas
  - Labels do console report: mantidos em inglês (alinhados aos badges)
  - **L941**: fora da fronteira congelada (L941 > 852), traduzido com a keyword **"impersonation" literal preservada** — `"# Banco de padrões (pula brand impersonation em domínios conhecidos como seguros)"`
  - `_KNOWN_SAFE_DOMAINS`, `_CONFUSABLES`, `_REDIRECT_PARAMS`: idênticos
  - `python -m py_compile` — SINTAXE OK
- Exemplos de código dentro de docstrings (L1092–1095, L1396–1398, L1419–1427) mantidos

---

## 2026-10-14 18:40 — Tools/dorkeye_agents.py — LOTE 3 (L1432–1915)

- **Backup**: mesmo do Lote 1 (`.traducao_backup/dorkeye_agents.py.20261014_165835.bak`)
- **Linhas alteradas no lote**: ~70 (cumulativo do arquivo: 278 insertions / 278 deletions)
- **Strings traduzidas**: ~64 unidades
  - SecretsAgent: 2 docstrings, 5 prints, 3 comentários, header de seção
  - ReportAgent: class docstring, 3 prints, header; template Markdown (~24: headers/labels, `SECRETS`→`SEGREDOS`); template HTML (~22: `lang="it"`→`"pt-BR"`, título, h1/h2, ths, sections)
- **Anotação do aprovador registrada**: **L1780 `s.get('detection') == 'LLM'` é comparação de valor de dado — se o valor 'LLM' for alterado no futuro, essa comparação precisa ser atualizada coordenadamente** (values 'REGEX'/'LLM' intocados e verificados)
- **Verificações** (todas PASSARAM):
  - `python -m py_compile` — SINTAXE OK
  - Valores `detection` ('REGEX'/'LLM') e a comparação L1780: contagens idênticas
  - Labels de severity/métricas: 13 mantidos em inglês (🔴 CRITICAL, **TOTAL**, **PII**, **EMAILS**, 🟢 Clean…🚫 Blocked)
  - Chaves do dict `analysis`: contagens idênticas
  - Entidades HTML (`&#128065;`, `&nbsp;`, `&`, `&mdash;`): contagens idênticas — editadas por segmentos vizinhos
  - Pipe-tables: 8 separadores idênticos
  - Template HTML: `lang="pt-BR"`, ths/sections traduzidos, CSS/estrutura intacta, brand do engine intacto
  - Prompts LLM: 2 idênticos · `_SECRET_PATTERNS` importado de dorkeye_patterns.py (fonte única — descriptions já traduzidas lá, display-only)
- Decisão de brand: `"# DorkEye — Relatório de Análise"`, `<title>DorkEye Agents — Relatório — {…'Sessão'}</title>`, `<h1>&#128065; DorkEye — Relatório</h1>` — mesmo padrão do analyze.py (brand preservado + "Report" traduzido)

---

## 2026-10-14 19:20 — Tools/dorkeye_agents.py — LOTE 4 (L1916–2450)

- **Backup**: mesmo do Lote 1 (`.traducao_backup/dorkeye_agents.py.20261014_165835.bak`)
- **Linhas alteradas no lote**: ~77 (cumulativo do arquivo: 355 insertions / 355 deletions)
- **Strings traduzidas**: ~55 unidades
  - HeaderIntelAgent: docstring, 4 prints, 2 comentários, reasons de `_SECURITY_HEADERS_REQUIRED` (6, display-only), value L2007
  - TechFingerprintAgent: docstring, 3 prints, 1 docstring de método, ~9 comentários FIX italianos ("regex logico"→"regex lógica", "minore"→"menor", "critico"→"crítico", "con versione"→"com versão")
  - EmailHarvesterAgent / PiiDetectorAgent / SubdomainHarvesterAgent: docstrings + prints (~18)
- **Verificações** (todas PASSARAM):
  - `python -m py_compile` — SINTAXE OK
  - Chaves de `_SECURITY_HEADERS_REQUIRED` (6 nomes de header) e `_INFO_LEAK_HEADERS` (10): idênticas
  - `_OUTDATED_VERSION_RE`, `_EMAIL_RE`: idênticas
  - `_TECH_SIGNATURES` (37 entradas — nomes de CMS/framework intactos), `_TECH_CVE_DORK_TEMPLATES`, `_CMS_DORK_TEMPLATES`, `_EMAIL_CATEGORIES`, `_TECH_DETECTION`: idênticos
  - Categorias `admin/security/info/personal/noreply`: chaves intactas no order dict (L2256)
  - Follow-up dorks (L2442–2444): intactos
  - Chaves de dict da região (info_leaks, missing_security, outdated, techs, cve_dorks, emails_found, pii_found, subdomains): contagens idênticas
  - `_SecurityPatternDB`: ainda byte-identical

---

## 2026-10-14 20:10 — Tools/dorkeye_agents.py — LOTE 5 (L2451–3397) + CONCLUSÃO DO ARQUIVO

- **Backup**: mesmo do Lote 1 (`.traducao_backup/dorkeye_agents.py.20261014_165835.bak`)
- **Linhas alteradas no lote**: ~140 (cumulativo do arquivo: **495 insertions / 495 deletions**)
- **Strings traduzidas no lote**: ~60 unidades
  - DorkCrawlerAgent: docstring (pipeline de rodada + condições de parada), ~20 prints, painel de resumo, 3 comentários FIX italianos ("minore"→"menor")
  - Integração CLI: 2 adders completos (docstrings, grupos, 10 helps crawl + 3 helps security), run_crawl, print de relatório
  - Pipeline principal: docstring v3.1 (11 agentes), painéis (Triage/Segredos/Análise LLM), 6 prints, comentários de etapa, **L3166 italiano → PT-BR**
  - CLI standalone: description, epílogo "Exemplos:", 13 helps, 6 prints de erro, ~16 prints finais
- **Verificações do Lote 5** (todas PASSARAM):
  - Dorks de follow-up (L2843–2858): 7 intactos
  - **Ordem de execução do pipeline: idêntica** (11 instanciações na mesma sequência)
  - Flags argparse: 23 nomes idênticos; `choices` preservados
  - L3166: traduzida, italiano eliminado
  - Chaves do dict output (12) e valores stop_reason (8): intactos

### VERIFICAÇÃO FINAL COMPLETA — dorkeye_agents.py (backup vs. atual)
- **Linhas totais alteradas**: 495
- **Unidades traduzidas**: ~282 (L1:48 + L2:55 + L3:64 + L4:55 + L5:60)
- **Divergências não-aprovadas**: **0** (única divergência detectada = as 6 reasons de `_SECURITY_HEADERS_REQUIRED`, traduções aprovadas no Lote 4, chaves idênticas)
- **Congelamentos confirmados**:
  - `_SecurityPatternDB` L671–852: byte-identical
  - Badges ThreatLevel (6): em inglês
  - Dorks: `_CMS_DORK_TEMPLATES` (9), `_TECH_CVE_DORK_TEMPLATES` (10), `_PATH` (7), `_EXT` (11), follow-ups (7) — intactos
  - Labels CRITICAL/HIGH/MEDIUM/LOW/SKIP: contagens idênticas
  - Prompts LLM (2): idênticos
  - Chaves de dict (arquivo inteiro): 224 idênticas
  - Regex (_EMAIL_RE, _OUTDATED_VERSION_RE, _INTERESTING_PATHS, _SUSPICIOUS_PARAMS, _SCRIPT_STYLE_RE_FALLBACK): idênticas
  - AST normalizado (f-string aware): idêntico
  - Italiano residual: eliminado do arquivo
- `python -m py_compile` — SINTAXE OK

**STATUS: dorkeye_agents.py 100% TRADUZIDO.** Faltam: dorkeye.py (último arquivo) e atualização coordenada do colorLine.

---

## 2026-10-14 22:05 — dorkeye.py — LOTE D1 (L1–610)

- **Backup**: `.traducao_backup/dorkeye.py.20261014_215949.bak`
- **Linhas alteradas**: 84 (verificado via `git diff --stat`: 84 insertions / 84 deletions)
- **Strings traduzidas**: ~70 unidades
  - Docstrings (18) + comentários (incl. italianos L89–91/98/327/541–543) + stubs
  - Banner: "OSINT DORKING TOOL"→"OSINT FERRAMENTA DE DORKING", v5.0 estável, Autor/GitHub/Telegram (URLs mantidas), Stealth→"Mais lento, mais seguro", DorkGen Máx, Analyzer, Plataforma Android, **disclaimer legal PT-BR**
  - **WELCOME_MESSAGES: 25 itens 1:1** (correção: original tem 25, não 26) — 5 reenquadradas p/ ASM/CTI: "Burn what you touch."→"Registre suas ações para auditoria." · "You are visible."→"Sua atividade é visível." · "Stay invisible, {name}."→"Opere de forma discreta e responsável, {name}." · "Let's see what they forgot to hide"→"Vamos ver o que foi exposto por descuido, {name}." · "You wanna play a game?"→"Vamos ao trabalho." — ("Bom trabalho. Até a próxima." reservado p/ EXIT_MESSAGES no D4, onde está "Stay ghost.")
  - Strings italianas: checkpoint ×3 (L347/372/386), "Non critico", "NUOVO (punto 3)", "Dedup terminale", stub L98
  - Keywords colorLine (Estratégia B): `pulando` (L140), `Buscando` (L593/610)
  - Fallback de nome: `"friend"` → `"amigo"` (aprovado)
- **Verificações** (16/16 OK — 1 ERR era expectativa errada do script):
  - `python -m py_compile` — SINTAXE OK
  - WELCOME_MESSAGES: 25 itens nos dois, `{name}` preservado nas mesmas posições; WELCOME_COLORS (11) intacta
  - DEFAULT_CONFIG: idêntico · pickle keys + path `Dump/.checkpoints`: intactos
  - ASCII art DorkEye (3 linhas) + seringa (flag Fase 0) + URLs do autor: intactos
  - Marcadores `[!!]`/`[~]`/`[*]`: presentes · rich markup preservado
  - Italiano D1: eliminado · L88 corrigida cirurgicamente (3 headers homônimos — L2672/L3032 intactos p/ D5; 4 painéis `[ DB Port Scanner ]` intactos p/ D4/D5)

---

## 2026-10-14 22:50 — dorkeye.py — LOTE D2 (L620–1188)

- **Backup**: mesmo do D1 (`.traducao_backup/dorkeye.py.20261014_215949.bak`)
- **Linhas alteradas no lote**: ~74 (cumulativo: 158 insertions / 158 deletions)
- **Strings traduzidas**: ~45 unidades
  - search_dork: retries/backoff (5 prints)
  - analyze_results: Analisando/Testando/WAF detectado/SQLi e XSS potencial encontrado/↳ método/parâmetro/evidência/tipo + 2 comentários italianos "un solo"
  - run_search: docstring Checkpoint/Resume, CHECKPOINT ENCONTRADO, Retomar sessão?, Sessão retomada/Nova sessão, Busca com N dork(s), modos (stealth/SQLi/XSS/Android), [!!] Saída solicitada ×5 (replaceAll), delays, comentários italianos "Fine checkpoint setup"/"dopo ogni dork"
  - save_results/savers: docstrings, Formato de saída, Erro ao salvar, Título/Categoria (TXT)
- **Keywords colorLine emitidas (Estratégia B)**: `Analisando`, `encontrado`, `potencial`, `pulando`, `concluído`, `WAF`
- **Verificações** (todas OK — 2 falsos positivos de script resolvidos por verificação direta):
  - `python -m py_compile` — SINTAXE OK
  - Verdict labels `VULNERABLE`/`SAFE` (4 ternários): intactos · valores `sqli_s`/`xss_s`/`untested`: intactos
  - Chaves CSV/JSON: contagens idênticas · parsing input `("", "y", "yes")`: intacto
  - Lógica de delays (120-150/85-110/1.4-1.8/2**attempt): intacta · path Dump/: intacto
  - Escape JSON→HTML `.replace("</", "<\\/")`: 3 ocorrências idênticas old/new
  - Italiano D2: eliminado








### PENDÊNCIA — Teste visual do Console Web (pós-tradução dorkeye_web.py)
- Flask não instalado no ambiente de tradução. O operador deve:
  `pip install flask` → `python Tools/dorkeye_web.py --port 7777` →
  abrir http://127.0.0.1:7777 e conferir: labels PT-BR, formulários,
  jobs, mensagens JS e coloração do terminal.

### PENDÊNCIA — _SecurityPatternDB (dorkeye_agents.py L671-852)
- Banco de descriptions CONGELADO nesta fase (Opção A — decisão do aprovador).
- MOTIVO: L946 faz `if "impersonation" in desc.lower()` para pular
  padrões em domínios seguros; não podemos garantir que não existam
  comparações indiretas (eval, getattr, reflection) em runtime.
- CONDIÇÃO para traduzir no futuro:
  * Preservar a keyword "impersonation" literal em qualquer description
    que a contenha (ex: "Brand impersonation in domain" → "Impersonation
    de marca no domínio"), OU
  * Reescrever a L946 para usar uma flag booleana em vez de match
    de string — refactor preferível
  * Auditar TODAS as descriptions do banco para garantir que nenhuma
    outra keyword é comparada indiretamente
- Quando: preferencialmente junto com a Fase 0 (saneamento ético),
  já que o banco inteiro será revisado de qualquer forma.
- Verificação de segurança concluída (2026-10-14): varredura completa do
  arquivo encontrou UMA única comparação de desc (L946); L983/1055 são
  display; L341/458/1280/1669/3361 não envolvem desc.

---

## 2026-10-15 12:20 — dorkeye.py — LOTE D3 (L1188–2018, template HTML do relatório)

- **Backups**: novo `.traducao_backup/dorkeye.py.20261015_122017.pre_d3.bak` (estado pós-D2 — reversão isolada do D3); backup original D1/D2 (20261014_215949) preservado
- **Linhas alteradas no lote**: ~86 (cumulativo do arquivo: 232 insertions / 232 deletions — verificado via `git diff --numstat`)
- **Strings traduzidas**: 72 pares (~85 unidades)
  - Título/cabeçalho: `DorkEye | Report` → `DorkEye | Relatório` (brand preservado, mesmo padrão do analyze/agents) · "Generated:" → "Gerado:"
  - Alertas: SECURITY ALERT → ALERTA DE SEGURANÇA · XSS ALERT → ALERTA XSS · WAF-protected target(s) → alvo(s) protegido(s) por WAF (WAF mantido)
  - 6 stat-cards: TOTAL DE RESULTADOS · DUPLICADOS FILTRADOS · VULNERABILIDADES SQLI/XSS · WAF DETECTADO · TEMPO DE EXECUÇÃO
  - Filtros: [ FILTRO ] · TODOS · DOCS · ARQUIVOS · PÁGINAS (SCRIPTS mantido — idêntico em PT; extensões intocadas)
  - Busca: BUSCAR · LIMPAR · Correspondências · TÍTULO · CATEGORIA (URL/DORK/SCOPE mantidos)
  - Export: Exportar Links - Todos/SQLi/XSS · Todos os testados · Visão Atual · Visíveis
  - Arquivos: ARQUIVOS · Baixar Arquivos · Selecionados · NENHUM · LISTA (TXT/JSON)
  - Tabela: Título · Categoria · Tamanho (#, URL, SQLi, XSS, WAF mantidos)
  - Rodapé: disclaimer → "Apenas para pesquisa de segurança autorizada" (brand/autor intactos)
  - JS: toasts (Exportados/Nenhum resultado/Nenhum arquivo/Lista de arquivos exportada) · info bar (Exibindo/Filtro/resultado(s)) · export TXT (Título/Data/Hora/Exportação DorkEye/Escopo/Lista de Arquivos DorkEye/Categoria/Tamanho) · popup de detalhes (Título/Categoria/Extensão/Tamanho/Data/Hora/Trecho/Método SQLi/Detalhe XSS/Sem detalhes) · title="Fechar"/"Detalhes"
- **Decisões aprovadas**: `SQLi ALL`→`SQLi TODOS` · DOC→DOCS · PAGE→PÁGINAS · ARCHIVES→ARQUIVOS · TITLE→TÍTULO/CATEGORY→CATEGORIA nos scope buttons · export TXT 'DorkEye Export\nScope:'→'Exportação DorkEye\nEscopo:' · Time:/Timestamp→Data/Hora · Snippet→Trecho
- **Não tocado (verificado programaticamente)**:
  - CSS L1194–1396: byte-identical (16.771 chars) · charset do matrix canvas + IFE do matrix rain: idênticos
  - JS lógico: GROUP_CATS, SUB_PRED, _scopeLabel (values viram nomes de arquivo), _getRows, CSV headers — idênticos
  - dataset.*/data-* (contagens idênticas) · startsWith('VULN')/==='SAFE' intactos
  - Vereditos: SQLi CRITICAL/VULN/SAFE, VULN, SAFE, VULNERABLE, CRITICAL (HTML + valores Python) — intactos (Estratégia B)
  - Extensões PDF/DOCX/XLSX/PPT/PHP/ASP/SH/BAT/CONFIGS/CREDS + listas do SUB_PRED — intactas
  - Entidades HTML: 100% preservadas por contagem (&#9632; ×13, &#9888; ×6, &nbsp; ×7 etc.) — edição por segmentos vizinhos
- **Verificações** (todas PASSARAM):
  - `python -m py_compile` — SINTAXE OK
  - **Prova forte**: arquivo atual == backup .pre_d3 + exatamente os 72 pares aprovados (byte-identical à cópia da proposta) — nada fora dos pares mudou
  - Suíte direcionada: 117 checks — 115 OK diretos + 2 falsos-positivos de segmentação do próprio script (matrix rain comparado até `</html>`; _scopeLabel com terminador `}};` inexistente na one-liner) — ambos confirmados idênticos por verificação direta
  - Nota metodológica: L1978/1979 contêm `\\n` (escape duplo no fonte Python) — a exibição do Read collapsa para `\n`; pares ajustados aos bytes reais (repr verificado contra backup)
- **Método**: script Python com 72 pares (contagem verificada ANTES de aplicar; aplicado primeiro em cópia temporária; diff -U1 exibido e aprovado pelo aprovador; aplicação ao arquivo via mesmo script)

### PENDÊNCIA NOVA — badge "SQLi VULN" nos botões de export (registrada por determinação do aprovador)
- O badge "SQLi VULN" do painel de export usa a abreviação VULN, que não
  casa com a regex do colorLine `/VULNERABLE|i`. Comportamento
  pré-existente — validar no teste visual do Console Web. (Nota factual:
  os badges do relatório HTML não passam pelo terminal/colorLine; o
  colorLine atua sobre stdout do processo dorkeye.py.)

---

## 2026-10-15 15:40 — dorkeye.py — LOTE D4 (L2019–2600) — 4 SULOTES

- **Backup**: `.traducao_backup/dorkeye.py.20261015_154011.pre_d4.bak` (estado pós-D3 — reversão isolada do D4)
- **Método (corrigido a pedido do aprovador)**: diff revisável por linha (formato `LNNNN | - original / + proposta`), dividido em 4 sublotes, cada um exibido integralmente e aprovado antes da aplicação. Script apenas como mecanismo de aplicação dos pares aprovados.
- **Linhas alteradas no lote**: 140 (cumulativo do arquivo: 372 insertions / 372 deletions — verificado via `git diff --numstat`)
- **Strings traduzidas**: 131 pares
  - **D4.1 Helpers & Estatísticas (L2019–2191, 33 linhas)**: 9 docstrings · tabela de estatísticas completa (Estatísticas de Busca, Total de resultados encontrados, Resultados únicos, Duplicados removidos, Na lista negra, Vulnerabilidades SQLi/XSS, WAF detectado, Tempo de execução, Resultados por Categoria) · cabeçalho Helpers → Funções auxiliares · mensagens de _load_results_from_file/load_config/create_sample_config/resolve_templates/get_categories (comentário `# DorkEye Configuration` → `# Configuração do DorkEye`; chaves do YAML intactas)
  - **D4.2 Wizard (L2192–2381, 50 linhas)**: banner "Wizard interativo", (padrão N), (ex.: …), painéis OPÇÕES DE EXECUÇÃO/ANÁLISE DE RESULTADOS/CRAWL RECURSIVO, ~20 prompts ask_yes_no/ask_choice/ask_string, rodadas (rápido/equilibrado/minucioso/máximo), painel crawl completo, **italiano L2276 eliminado** ("non disponibile — mancante" → "indisponível — ausente")
  - **D4.3 Menu + EXIT_MESSAGES + Busca (L2382–2484, 29 linhas)**: MAIN_MENU (Busca de Google Dorks / Gerador de Dorks / Criar config de exemplo / Sair), MENU PRINCIPAL, **EXIT_MESSAGES LITERAIS**, painel BUSCA DE GOOGLE DORKS, submenu busca, CARREGADOS N DORK(S), painel DBScan wizard 1 → VARREDURA DE PORTAS DB, **italiano L2481/2483 eliminado** (Interrotto dall'utente/Errore)
  - **D4.4 Gerador + DBScan + Main (L2486–2600, 28 linhas)**: GERADOR DE DORKS, submenu gerador, CATEGORIA/TODAS as categorias, Modo, painel DBScan wizard 2, cabeçalho MAIN → PRINCIPAL, docstring Entry point, comentários Interface Web
- **Decisões do aprovador registradas**:
  - **EXIT_MESSAGES literais** (Fase 1 = tradução fiel): "Permaneça fantasma." · "Cubra seus rastros." · "Logs não mentem. Nós também não." · "Boa caçada." — **reenquadrar fica para Fase 0**. *Supersede a reserva do D1 ("Bom trabalho. Até a próxima." p/ "Stay ghost.") — era reenquadramento disfarçado.*
  - Painel/menu: **"BUSCA DE GOOGLE DORKS"** — "Google Dorks" é o termo da técnica; "NO GOOGLE" seria semanticamente falso (o motor é DuckDuckGo)
  - L2598 `# ── Interface Web ──`: travessões originais mantidos, só texto trocado (linha mais longa; cosmético irrelevante por determinação do aprovador)
  - Termos blacklist/whitelist mantidos (espelham config keys); "Blacklisted" → "Na lista negra"
- **Não tocado (verificado programaticamente)**: chaves de config (`config["sqli_detection"]` etc. — contagens idênticas; request_timeout/max_retries/user_agent_rotation/extended_delay só existem no YAML) · valores de input `("y","yes")`/`""`/`[Y/n]`/`[y/N]` · opções `soft/medium/aggressive` e `all/reflected/stored/dom` e `JSON/CSV/HTML/TXT` · paths e nomes (`dorkeye_config.yaml` ×4, `dorkeye_dbscan.json` ×4, `dorkeye_crawl_{ts}`, `Templates`, `Dump`, `dorks_templates.yaml`) · tags `[Agents]`/`[Crawl]`/`[DBScan]`/`[ DorkEye Wizard ]` · rich markup (contagens idênticas) · DEFAULT_CONFIG, DBPortScanAgent(...), type("A",(),{...}), _run_agents_pipeline, run_crawl(...) · **ocorrências gêmeas em main() preservadas p/ D5** (L2744, L2752/2754, L2931, L2980/2981, L3010, L3030, painéis DBScan L2942/3043, italiano L2937/2963/2965)
- **Verificações** (todas PASSARAM):
  - `python -m py_compile` — SINTAXE OK
  - **Prova forte**: arquivo atual byte-identical à proposta aprovada — nada fora dos 131 pares mudou
  - Contagem de linhas: 3079 == 3079 (só trocas de texto)
  - Suíte direcionada: 90 checks — 84 OK diretos + 6 falsos-positivos de expectativa do próprio script (4 config keys sem acessor `config[...]` no código; italiano L2937/2963 preservado por design p/ D5) — todos confirmados OK por verificação direta
- **Anotações para a correção coordenada do colorLine (pós-D5)** — keywords emitidas novas no D4: **"Iniciando", "Erro", "Interrompido", "salvos"** (acrescentar às regex em dorkeye_web.py L932-941 junto com as do D1/D2: pulando, Buscando, Analisando, encontrado, potencial, concluído, WAF)
- **Anotação Fase 0**: "Permaneça fantasma." e "Cubra seus rastros." ficam como estão na Fase 1; reenquadrar na Fase 0 (saneamento ético).

---

## 2026-10-15 18:55 — dorkeye.py — LOTE D5 (L2601–3078) — 5 SULOTES — CONCLUSÃO DO ARQUIVO

- **Backup**: `.traducao_backup/dorkeye.py.20261015_185557.pre_d5.bak` (estado pós-D4)
- **Método**: diff por linha em 5 sublotes exibido integralmente e aprovado antes da aplicação (88 pares + 1 par extra da observação (a))
- **Linhas alteradas no lote**: 95 vs backup .pre_d5 (94 do diff aprovado + L197 banner) — cumulativo vs HEAD: **466 insertions / 466 deletions** (L197 já contava como alterada desde o D1)
- **Strings traduzidas**: 89 pares
  - **D5.1 Web UI + argparse (22 linhas)**: comentários, mensagens ImportError do `--ui`, description, epílogo `Exemplos:` + `# Es:`→`# Ex.:`, **12 helps** (flags/choices/defaults intocados), formato `--templates`
  - **D5.2 Validações + análise + teste direto (17 linhas)**: 4 parser.error, painel ANÁLISE DE RESULTADOS + gêmeos (Analysis enabled/skipped), **italiano L2768-2769 eliminado** ("viene ignorato in modalità"), TESTE DE URL DIRETA
  - **D5.3 Teste direto -u (10 linhas)**: painéis RESULTADO DO TESTE SQLi/XSS, Não testado, método/evidência/parâmetro (consistente com D2), WAF detectado, Resultado salvo
  - **D5.4 Modo arquivo -f + DBScan (20 linhas)**: MODO DE ARQUIVO, Carregando/Carregados/Processando, **italiano L2937/2939/2943/2963/2965 eliminado** (non trovato/Nessun risultato/Avvio su/Interrotto/Errore), painel → VARREDURA DE PORTAS DB, comentários BUG FIX → CORREÇÃO (×2)
  - **D5.5 Fluxo final (25 linhas)**: Origem dos dorks, CARREGADOS N DORK(S), Busca interrompida pelo usuário!, relatórios, crawl, painel DBScan final, Stopped by user → Interrompido pelo usuário, Nenhum arquivo de saída
- **Decisões do aprovador registradas**:
  - **(a) Uniformização banner+description**: "Ferramenta de Dorking (OSINT)" — L197 (banner, território D1: OSINT continua vermelho, agora entre parênteses) + L2625 (description). Correção coordenada banner↔CLI
  - **L2672/L3032 intactos** por determinação — esclarecido que são **comentários internos** `# ── DB Port Scanner ──`, não painéis; os **painéis de console** L2942/3043 foram traduzidos para `[ VARREDURA DE PORTAS DB ]` (consistência com os do wizard aprovados no D4) — total 4/4 painéis PT-BR
  - `filename.yaml` → `arquivo.yaml` (placeholder), FILE MODE → MODO DE ARQUIVO
- **Não tocado (verificado programaticamente, 117+ checks)**: 33 nomes de flags argparse · choices (reflected/stored/dom/all, html/md/json/txt) · defaults (8080/50/800/soft/20/html/60/2.5/200/None) · add_crawler_args(parser) (def+chamada) · report_{ts}.html default · Dump/ paths · type("A", (), {...}) keys · getattr(args, ...) defaults · **vereditos VULNERABLE/SAFE intactos** (Estratégia B: L2811/2821/2846/2849 fora do diff) · rich markup · tags [DBScan]/[Crawl]/[Agents]/[Analyzer] · L2672/L3032
- **Verificações D5** (todas PASSARAM): py_compile SINTAXE OK · arquivo = proposta aprovada + exatamente as 2 linhas da observação (a) (byte-verificado) · suíte com 2 falsos-positivos de expectativa resolvidos por verificação direta (add_crawler_args==2 def+call; delta [bold white]+1 = banner aprovado)
- **Italiano no arquivo inteiro: ZERO** após D5

### VERIFICAÇÃO FINAL COMPLETA — dorkeye.py (backup original 20261014_215949 vs. atual pós-D5)
- **Linhas totais alteradas**: 466/466 (bate exato com `git diff --numstat`) · contagem de linhas do arquivo: 3079 == 3079 (só trocas de texto, zero linhas adicionadas/removidas)
- **AST mascarado (todas as strings → placeholder): IDÊNTICO** (dump de 285.687 chars) — prova estrutural: nomes, funções, classes, assinaturas, números, chaves de dict, chamadas, f-strings 100% preservados
- **Unidades por lote**: D1 ~70 · D2 ~45 · D3 72 pares · D4 131 pares · D5 89 pares
- **Congelamentos confirmados**: ASCII art do banner (idêntica) · URLs do autor (xPloits3c ×4, github ×1, t.me ×1) · WELCOME_COLORS (def+uso) · {name} ×18 · **DEFAULT_CONFIG byte-idêntico** (563 chars normalizado) · pickle.dump/load/HIGHEST_PROTOCOL + Dump/.checkpoints intactos · vereditos ("VULNERABLE" if ×4, else "SAFE" ×4, VULNERABLE ({_conf}), "&#9888; CRITICAL", f"VULN ({conf})", f"VULN [{_xtypes_short}]") · rich markup (contagens idênticas) · DEXSS7x (0 — não presente neste arquivo) · imports/código (DorkEyeEnhanced, run_search, DBPortScanAgent, SQLiDetector, XSSDetector...) · filenames preservados p/ Fase rename (dorkeye_crawl_, dorkeye_dbscan.json ×4, dorkeye_config.yaml ×4)
- **Falsos-positivos da suíte final (5, todos resolvidos por verificação direta)**: (1) conversão CRLF→LF **pré-existente da sessão anterior** (backup original todo CRLF, working file todo LF desde antes desta sessão — git avisa desde o início; 466 linhas batem exato após normalizar \r; git renormaliza no commit) · (2) WELCOME_COLORS ==2 (def+uso, expectativa ==1 errada) · (3) DEFAULT_CONFIG aparentava divergir por \r; normalizado = idêntico · (4) "pickle" 5× no atual = palavra dentro de docstring do D1 aprovada ("Serializa (pickle) o estado...") · (5) "Dedup" = termo técnico em comentários aprovados no D1/D2, não italiano
- **Divergências não-aprovadas: 0**

**STATUS: dorkeye.py 100% TRADUZIDO (D1–D5). Italiano: zero. Resta: correção coordenada do colorLine (dorkeye_web.py) e teste visual do Console Web.**

### KEYWORDS colorLine ACUMULADAS (correção coordenada — dorkeye_web.py L932-941)
- Emitidas PT-BR (D1/D2): `pulando`, `Buscando`, `Analisando`, `encontrado`, `potencial`, `concluído`, `WAF`
- Emitidas PT-BR (D4): `Iniciando`, `Erro`, `Interrompido`, `salvos`
- Emitidas PT-BR (D5): `salvo`, `Carregando`, `Processando`, `interrompida`
- Regex atuais do colorLine: `/VULNERABLE|error/i` · `/SAFE| saved |done|completed/i` · `/Searching|Analyz/i`
- **Vereditos VULNERABLE/SAFE continuam em inglês (Estratégia B) — as regex DEVEM ser estendidas, não removidas**

---

## 2026-10-15 19:30 — CORREÇÃO COORDENADA DO colorLine (Tools/dorkeye_web.py L932–936)

- **Backup**: `.traducao_backup/dorkeye_web.py.20261015_193044.pre_colorline.bak`
- **Contexto**: pendência crítica registrada desde a tradução do dorkeye_web.py (2026-10-14 16:40) — resolvida agora que dorkeye.py está 100% PT-BR
- **Método**: diff por linha exibido e aprovado antes da aplicação
- **Linhas alteradas**: exatamente 5 (L932–936) — verificado programaticamente
- **Estratégia**: SOMENTE EXTENDER — nenhum padrão EN removido (vereditos VULNERABLE/SAFE e tags EN de analyze/agents/db_portscan continuam casando)
  - L932 t-e: `+Erro` — `[Agents]/[Crawl]/[DBScan]/[Analyzer] Erro: …` (≡ `error`)
  - L933 t-w: `+Pulando|pulad|Interrompid` — `[~] Pulando…`, `Análise pulada.`, `Crawl pulado.`, `Interrompido/interrompida pelo usuário` (≡ `skipping`)
  - L934 t-ok: `+salvo|salvos|Concluíd` — `Resultado(s) salvo(s) →`, `Resultados salvos em:`, `[Crawl] Concluído` (≡ ` saved `/`completed`)
  - L935 t-i: `+Buscando|Analisando|Carregando|Iniciando|Processando` (≡ `Searching`/`Analyz`/`Loading`/`Starting`)
  - L936 t-e: `+potencial|encontrad` — `potencial encontrado`, `Total de resultados encontrados` (≡ `potential`/`found`)
- **Mudanças de comportamento vs. fall-through original (aprovadas pelo aprovador)**: (1) `Análise pulada.`/`Crawl pulado.` agora amarelo (antes default); (2) `[DBScan] Interrompido pelo usuário.` agora amarelo (antes caía em `DBScan`→ciano); (3) `Processando…` agora ciano (antes default)
- **Não tocado (verificado)**: isProgressLine e parseProgress — regexes estruturais (%, box-drawing, tempos), independentes de idioma · demais segmentos do colorLine (Open/Closed, DBScan, box-drawing, blank) · lógica web (subprocess, bind 127.0.0.1, SECRET_KEY, DORKEYE_PY, DUMP_DIR, debug=False)
- **Verificações** (todas PASSARAM): py_compile SINTAXE OK · 5/5 linhas exatas · 17 padrões EN preservados · 5 regex novas presentes · estruturas vizinhas intactas (40 checks)
- **PENDÊNCIA (operador)**: teste visual do Console Web — `pip install flask` → `python Tools/dorkeye_web.py --port 7777` → abrir http://127.0.0.1:7777 → rodar um scan → conferir labels PT-BR e coloração (vermelho em Erro/VULNERABLE, verde em salvo/Concluído, ciano em Buscando/Iniciando, amarelo em WAF/Pulando/Interrompido)

---

## STATUS GERAL — FASE 1 (TRADUÇÃO PT-BR): dorkeye.py 100% CONCLUÍDO

- **dorkeye.py**: D1–D5 aplicados, aprovados e verificados (466/466 linhas vs HEAD; AST mascarado idêntico ao original; italiano zero; vereditos/freeze intactos)
- **colorLine**: correção coordenada aplicada (pendência crítica resolvida)
- **Restam na fase/posteriores**:
  1. **Teste visual do Console Web** (operador) — valida labels + coloração + badge "SQLi VULN" (pendência D3)
  2. **Templates/dorks_templates.yaml** — dorks e modos `soft|medium|aggressive` (Fase 2 — regionalização BR)
  3. **Fase rename** (`dorkeye_*` → `mappingexpo_*`): `dorkeye_local_analysis_<ts>.<fmt>`, `dorkeye_dbscan_<ts>.json/txt`, `dorkeye_crawl_<ts>`, `dorkeye_config.yaml`, `report_` — nomes preservados até lá
  4. **Fase 0 (saneamento ético)**: payloads WAF-bypass, "Cubra seus rastros."/"Permaneça fantasma." (reframe), referências a Sqlmap (db_portscan L773), _SecurityPatternDB (condição documentada acima)
- **Nada commitado** (regra em vigor)

---

# FASE 3 — RENAME (dorkeye → mappingexpo)

## Plano aprovado (decisões do mantenedor, 2026-10-16)
- **Ordem das fases**: Fase 3 (rename) → Fase 2 (regionalização BR) → Fase 0 (saneamento ético)
- **dork_generator.py**: MANTER (dork = termo da técnica, não a marca; classe DorkGenerator, rotas /api/dorkgen e label DorkGen mantidos)
- **Marker XSS**: DEXSS7x → **MEXSS7x** (7 chars — preserva exatamente o comprimento de todos os payloads; leitura: MappingExpo XSS)
- **Identificadores internos c/ marca**: RENOMEAR (DORKEYE_PY→MAPPINGEXPO_PY, var instância dorkeye→mappingexpo, logger dorkeye_web→mappingexpo_web)
- **Linhas de autor** ("Author: xPloits3c … | DorkEye Project", "script by xPloits3c / DorkEye", "created for DorkEyeProject"): MANTER (atribuição de origem)
- **Docs**: bulk programático + arquivo de diff completo p/ auditoria
- **Commits**: um por camada (A–G)
- **Camadas**: A (1+2 atômica: renames físicos + imports) · B (3: classe/identificadores) · C (4: marker MEXSS7x) · D (5: UA) · E (6: paths de saída) · F (7: marca visível + arte MAPPING EXPO) · G (docs/meta bulk)
- **NÃO tocados**: TRADUCAO_LOG.md (histórico) · FUNDING.yml (attribution paypal) · URLs github/t.me (attribution) · LICENSE (zero ocorrências) · nomes sqli.py/xss.py/db_portscan.py (sem prefixo de marca) · termos "dork"/"dorking"/"DorkGen"/"DorkGenerator" (termo da técnica)

## 2026-10-16 — CAMADA A: renames físicos + imports (commit fase-3a)
- **Renames** (git mv): dorkeye.py→mappingexpo.py · Tools/dorkeye_{agents,analyze,web,patterns}.py→Tools/mappingexpo_*.py
- **Diff aprovado**: 52 linhas (mappingexpo.py 7 · agents 20 · analyze 14 · web 8 · patterns 2 · sqli 1) — imports, refs de módulo em docstrings/exemplos/mensagens de erro, `python dorkeye.py`→`python mappingexpo.py` em exemplos, `MAPPINGEXPO_PY` (def+3 usos), logger `mappingexpo_web`, `mappingexpo_llm_plugin` (plugin opcional), fix extra aprovado: `analisi.json`→`analise.json` (resíduo italiano da Fase 1)
- Linhas c/ marca+módulo na mesma linha (mappingexpo.py L2607, patterns L4) transformadas integralmente aqui (antecipação parcial da camada F)
- **Verificações** (todas PASSARAM): py_compile ×9 (SyntaxWarning preexistente `\s` xss.py L1270 — conhecida da Fase 1) · resolução estática de imports: todos os módulos locais resolvem em disco (llm_plugin permitido ausente) · zero imports dorkeye* restantes · residual dorkeye no código = 169 refs (aguardam E/F/G)
- **Pendências da camada A**: Docs/README ainda referenciam nomes antigos (corrigidos na camada G)

## 2026-10-16 — CAMADA B: classe MappingExpo + identificadores (commit fase-3b)
- **Backups**: `.traducao_backup/mappingexpo.py.20261016_132046.pre_f3_b.bak`, `db_portscan.py.20261016_132046.pre_f3_b.bak`
- **Diff aprovado**: 61 linhas — `class DorkEyeEnhanced` → `class MappingExpo` (5×: comentário de seção L524, def L527, 3 instanciações) · variável de instância `dorkeye` → `mappingexpo` (57×, regex `\bdorkeye\b` case-sensitive — preserva `dorkeye_crawl_`/`dorkeye_dbscan.json` p/ camada E) · `dorkeye_results` → `mappingexpo_results` (2 docstrings, db_portscan L464/466)
- **Verificações** (todas PASSARAM, 15 checks):
  - py_compile ×2 — SINTAXE OK
  - **Prova AST-rename**: AST do backup com NodeTransformer (DorkEyeEnhanced→MappingExpo, dorkeye→mappingexpo) == AST do arquivo atual — dumps idênticos (360.046 chars) — nada além dos renomes mudou
  - Contagens: DorkEyeEnhanced==0 · `\bdorkeye\b`==0 · `\bMappingExpo\b`==6 (5 renames + L2607 marca camada A) · `\bmappingexpo\b`==57 · total case-insensitive==63
  - Integridade das 6 linhas comprimidas na exibição (L2913/2920/2922/2926/3006/3019) — completas no arquivo real, sem "..." literal; contagem total de "..." idêntica ao backup (27)

## 2026-10-16 — CAMADA C: marker MPXSS7x (commit fase-3c)
- **Backups**: `.traducao_backup/xss.py.20261016_133309.pre_f3_c.bak`, `xss.md.20261016_133309.pre_f3_c.bak`
- **Decisão do mantenedor**: marker **MPXSS7x** (supersede o MEXSS7x proposto — "MP" = MappingExpo explícito; evita leitura "MEX = México"); 7 chars = DEXSS7x
- **Diff aprovado**: xss.py 79 linhas / 83 ocorrências (L550 e L1398 com 3 markers cada) + Docs/xss.md 84 linhas — substituição uniforme, zero variantes de caixa (verificado antes)
- **Verificações** (todas PASSARAM):
  - py_compile SINTAXE OK (SyntaxWarning `\s` L1270 preexistente)
  - **Prova byte-identity**: `backup.replace('DEXSS7x','MPXSS7x')` == arquivo atual — xss.py e xss.md — nada além do marker mudou
  - **Comprimentos de payloads preservados** (multiset via AST, corrigido para AnnAssign após falso vazio): _REFLECTED 44 (Σ2057), _BYPASS 26 (Σ1133), _STORED 5 (Σ180), _HEADER 4 (Σ136) — idênticos
  - Refs `self._MARKER` intocadas (OOB L614-616, detecção L830/837/842/905) · `_ENCODED_MARKERS` sem o marker
  - Contagens: MPXSS7x==83 (xss.py)/84 (xss.md); DEXSS7x==0 em ambos; marker ausente nos demais 7 arquivos de código

## 2026-10-16 — CAMADA D: user-agent (commit fase-3d 6f67373)
- **Backup**: `db_portscan.py.20261016_134016.pre_f3_d.bak`
- **Diff**: L355 `"Mozilla/5.0 DorkEye DBScan/1.0"` → `"Mozilla/5.0 MappingExpo DBScan/1.0"` (única UA com marca no repo)
- **Verificação**: DorkEye DBScan/1.0==0 · MappingExpo DBScan/1.0==1 · py_compile OK

## 2026-10-16 — CAMADA E: paths de saída (commit fase-3e e0fcbf2)
- **Backups**: `mappingexpo.py`, `mappingexpo_agents.py`, `mappingexpo_analyze.py`, `mappingexpo_web.py`, `.gitignore` — `.20261016_134128.pre_f3_e.bak`
- **Diff aprovado**: 22 substituições — mappingexpo_config.yaml ×4 (mappingexpo.py) + ×1 web + ×1 .gitignore · mappingexpo_crawl_{ts} ×1 + mappingexpo_crawl_<timestamp>.html help ×1 + mappingexpo_crawl_{ts}.{fmt} ×1 (agents) · mappingexpo_dbscan.json ×4 · mappingexpo_quarantine ×2 · mappingexpo_analysis_{ts} ×1 (agents) + ×1 (analyze) · mappingexpo_local_analysis_ ×2 (analyze) · mappingexpo_dorks_{ts}.txt + mappingexpo_dorks.txt (web) · .gitignore: mappingexpo_env/, run_mappingexpo.sh/bat
- **Correção incluída (resíduos da Camada A em docstrings, pegados pela verificação E)**: agents L175 `dorkeye_llm_plugin`, L180 `dorkeye_patterns.label_from_score()`, L1436 `de dorkeye_patterns — alias local` → mappingexpo_*
- **Verificações** (todas PASSARAM): py_compile ×4 · **grep `dorkeye_` em TODO o código == ZERO** · contagens dos novos paths idênticas ao aprovado · residual dorkeye no código = só marca "DorkEye" (camada F pendente: mappingexpo.py 15 · agents 21 · analyze 22 · web 5 · patterns 1 · dork_generator 1 · db_portscan 7 · sqli 3 · xss 6)

## 2026-10-16 — CAMADA F: marca visível MappingExpo + arte (commit fase-3f)
- **Backups**: 9 arquivos `.20261016_135806.pre_f3_f.bak`
- **Diff aprovado**: 73 renomes (`DorkEye`→`MappingExpo`, `DORKEYE`→`MAPPINGEXPO`, `dorkeye.py`→`mappingexpo.py`) em 9 arquivos (mappingexpo.py 11 · agents 20 · analyze 22 · web 5 · patterns 1 · dork_generator 1 · db_portscan 6 · sqli 2 · xss 5) + **arte ASCII do launcher (web L1159–1164): "DORK EYE" → "MAPPING EXPO"** (mesma fonte ANSI Shadow, 94 col, 5 linhas de glifos + 1 sombra, CRLF preservado)
- **Casos especiais**: mappingexpo.py L3 uniformizada para "Ferramenta de Dorking (OSINT)" (consistente com description) · agents L1644/L1741 mantêm o "v4.8" pré-existente (só a marca muda) · analyze L722/723/728/765 + agents L1419 = 5 refs de módulo `dorkeye.py` residuais da Camada A (incluídas aqui com nota) · dork_generator L2 `# DorkEye Project` → `# MappingExpo Project` (header sem autor)
- **8 linhas de atribuição INTACTAS (decisão aprovada)**: mappingexpo.py L4 (Author+URL), L201 (github), L202 (t.me), L1404 (github.io) · agents L40 · db_portscan L21 · sqli L18 · xss L12 (Author | DorkEye Project)
- **Verificações** (todas PASSARAM):
  - py_compile ×9 exit 0 (SyntaxWarning `\s` xss.py L1270 preexistente; nota: `2>$null` no PS 5.1 marca `$?=false` com warning no stderr — usar `$LASTEXITCODE`)
  - **Prova transformacional**: backup + transformação idêntica (skip das 8 linhas + arte) == arquivo atual, byte a byte, nos 9 arquivos
  - Marca fora das 8 linhas de atribuição == 0 · `\bdorkeye\b` em código == 0 · URLs de atribuição intactas (github ×2 — L4 docstring + L201 banner —, t.me ×1, github.io ×1) · autores ×4 intactos
  - **colorLine: nenhuma regex contém a marca; zero mudanças necessárias** (verificado contra as 5 regex estendidas da Fase 1)
  - Arte: 5 linhas de blocos + 1 sombra; contagem de linhas do web inalterada (1203); charset matrix e estruturas vizinhas intactos
- **Residual dorkeye em código após F: ZERO** (só as 8 linhas de atribuição). Restam: Docs/README/Templates/meta (camada G)

## 2026-10-16 — CAMADA G: docs/meta bulk (commit fase-3g)
- **Backups**: 30 arquivos `.20261016_142459.pre_f3_g.bak` (+ limpeza de 1 arquivo-lixão de regex mangled do PS)
- **Regras aprovadas**: linha de atribuição (xPloits3c, t.me/DorkEye, paypal.me/DorkEyeProject, created for DorkEye) → intacta; senão `DORK EYE`→`MAPPING EXPO`, `DORKEYE`→`MAPPINGEXPO`, `Dorkeye`→`Mappingexpo`, `DorkEye`→`MappingExpo`, `dorkeye`→`mappingexpo`
- **Diff**: 382 linhas em 30 arquivos (INSTALL 44 · USAGE 79 · cli 40 · termux 36 · webconsole 23 · agents 19 · http_fingerprints 19 · dork_generator 15 · dbscan 13 · output_formats 12 · sqli 12 · file_categories 11 · xss 11 · crawler 8 · workflow 8 · REPORT_HTML 6 · fingerprinting 6 · wizard 4 · requirements 3 · README 2 · bug_report 2 · dorks_templates 5 · restantes 1-2) — **diff completo (765 linhas) salvo em `.traducao_backup/f3_g_diff.txt` para auditoria**
- **git mv**: `.github/workflows/claude-dorkeye.yml` → `claude-mappingexpo.yml` (conteúdo: name `🦅 MappingExpo AI Agent`, group `mappingexpo-ai-`, prompts com refs renomeadas — italiano mantido)
- **23 linhas de atribuição preservadas** (badges "Baseado em DorkEye" do README, URLs git clone ×6, autores, created-for) · arquivos 100% atribuição intocados (example.yaml, sql.yaml, 2 dorks.txt)
- **Correções de verificação (2 itens)**: (1) fix da ocorrência **DEXSS7x perdida da Camada C** em Docs/USAGE.md L402 (inventário inicial a listava; não fora atribuída ao lote C) → MPXSS7x; (2) padrão de atribuição estendido com `xploits3c.github.io/DorkEye` (linha L1404 de mappingexpo.py, preservada pela F) · citações bare `python3 mappingexpo_analyze.py` = convenção pré-existente do original (`python3 dorkeye_analyze.py` no backup) — fiel, não regressão
- **Verificações** (todas PASSARAM): residual dorkeye no repo == apenas TRADUCAO_LOG (histórico) + FUNDING (attribution) + 32 linhas de atribuição em 15 arquivos — **ZERO fora de atribuição/histórico** · DEXSS7x == 0 no repo inteiro (exceto log) · arquivos 0-alteração byte-identical aos backups

**STATUS: FASE 3 (RENAME) — CAMADAS A–G CONCLUÍDAS.** Verificação final pós-G executada (abaixo).

### VERIFICAÇÃO FINAL DA FASE 3 (pós-G)
- Repositório: única marca DorkEye restante = **linhas de atribuição intencional** (URLs do autor original, linhas "Author/Autor: xPloits3c", "created for DorkEye Project", badges "Baseado em") + TRADUCAO_LOG.md (registro histórico da Fase 1) + FUNDING.yml
- py_compile ×9 exit 0 · smoke tests funcionais: `--help` dos 4 CLIs
- Marker MPXSS7x: 83 (xss.py) + 84 (xss.md) + 1 (USAGE.md) = 168; DEXSS7x: 0
- **Pendência (operador)**: teste visual do Console Web pós-rename — `python Tools/mappingexpo_web.py --port 7777` → conferir arte MAPPING EXPO no launcher, título, labels e coloração (colorLine verificada como não-afetada)









