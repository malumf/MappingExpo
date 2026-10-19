# MappingExpo no Termux

> Rode o pipeline completo do MappingExpo direto do seu aparelho Android.
> O Termux é auto-detectado — sem flags extras. O tuning de economia de bateria ativa sozinho.

-----

## Requisitos

- Android 7.0 ou superior
- [Termux](https://f-droid.org/packages/com.termux/) instalado via **F-Droid** (a versão da Play Store está deprecada e sem suporte)
- Conexão com a internet

> **Não use a versão da Play Store do Termux.** Está desatualizada e causará erros de dependência.

-----

## Instalação

### Passo 1 — Atualizar os pacotes do Termux

```bash
pkg update && pkg upgrade -y
```

Rode isto primeiro, sempre, numa instalação limpa do Termux.

-----

### Passo 2 — Instalar as dependências do sistema

```bash
pkg install -y python git libxml2 libxslt
```

|Pacote   |Por que é necessário                           |
|---------|----------------------------------------------|
|`python` |Runtime do MappingExpo                           |
|`git`    |Clonar o repositório                          |
|`libxml2`|Exigido pelo `lxml` (parser HTML) — extensão C|
|`libxslt`|Exigido pelo `lxml` — extensão C              |


> **Importante:** `libxml2` e `libxslt` devem ser instalados via `pkg` **antes** do `pip install`.
> Pular este passo faz o build do `lxml` falhar com um `fatal error` durante a instalação dos requirements.

-----

### Passo 3 — Clonar o MappingExpo

```bash
git clone https://github.com/malumf/MappingExpo.git
cd MappingExpo
```

-----

### Passo 4 — Instalar as dependências Python

```bash
pip install -r requirements.txt
```

Isto instala todas as bibliotecas exigidas:

|Biblioteca               |Finalidade                     |
|-------------------------|-------------------------------|
|`requests` / `urllib3`   |Motor HTTP                     |
|`PyYAML`                 |Parsing de config e template   |
|`beautifulsoup4` / `lxml`|Parsing HTML                   |
|`rich`                   |UI de terminal e formatação    |
|`colorama`               |Suporte a cores                |
|`ddgs`                   |Integração de busca DuckDuckGo |
|`flask`                  |Console Web (`--ui`) — opcional |

-----

### Passo 5 — Verificar a instalação

```bash
python mappingexpo.py -h
```

Saída esperada: o banner de ajuda completo com todas as flags disponíveis.
Se você o vir, o MappingExpo está pronto.

-----

## Auto-Detecção do Termux

Quando o MappingExpo detecta que está rodando dentro do Termux, o banner exibe:

```
Android / Termux | economia de bateria ativa
```

Os parâmetros a seguir são reduzidos automaticamente para poupar bateria e evitar timeouts em conexões móveis:

|Parâmetro                |Desktop|Termux|
|------------------------|-------|------|
|Timeout de conexão       |4 s    |3 s   |
|Amostras de baseline SQLi|2      |1     |
|Amostras de probe        |3      |2     |
|Amostras booleanas blind |3      |2     |
|Confirmações time-based  |2      |1     |

Nenhuma flag exigida — este tuning é aplicado automaticamente.

-----

## Uso Básico

### Wizard interativo (recomendado para iniciantes)

```bash
python mappingexpo.py --wizard
```

Menus guiados para cada opção. O jeito mais fácil de começar.

-----

### Busca com dork único

```bash
python mappingexpo.py -d "inurl:login.php" -o results.html
```

Busca no DuckDuckGo pelo dork e salva um relatório HTML interativo em `Dump/`.

-----

### Carregar dorks de um arquivo

```bash
python mappingexpo.py -d dorks.txt -c 100 -o results.json
```

`dorks.txt` — um dork por linha; linhas começando com `#` são ignoradas.
`-c 100` — busca até 100 resultados por dork (default: 50).

-----

### Teste direto de URL (SQLi + XSS, sem busca)

```bash
python mappingexpo.py -u "https://target.com/page.php?id=1"
```

Roda o pipeline completo de vulnerabilidades direto contra uma URL única.
`--sqli` e `--xss` são auto-habilitados neste modo.

-----

## Varredura de Vulnerabilidades

### SQL Injection

```bash
python mappingexpo.py -d "inurl:.php?id=" --sqli -o results.json
```

### XSS

```bash
python mappingexpo.py -d "inurl:search.php?q=" --xss -o results.json
```

### SQLi + XSS combinados

```bash
python mappingexpo.py -d "inurl:.php?id=" --sqli --xss -o results.json
```

### Com modo stealth

```bash
python mappingexpo.py -d "inurl:.php?id=" --sqli --xss --stealth -o results.json
```

`--stealth` adiciona delays mais longos entre requisições (1,4×–1,8×) para reduzir detecção e rate limit.
Recomendado em conexões móveis, onde reconexões custam caro.

-----

## Formatos de Saída

Todos os arquivos de saída são salvos dentro da pasta `Dump/` (criada automaticamente).

|Extensão|Formato                                                            |
|--------|-------------------------------------------------------------------|
|`.html` |Relatório interativo com tema escuro — filtrável, pesquisável, exportável|
|`.json` |Dados estruturados completos + estatísticas — dispara o prompt de análise|
|`.csv`  |Compatível com planilha, todas as colunas incluídas               |
|`.txt`  |Texto puro, um resultado por bloco                                 |

```bash
# Relatório HTML (default, recomendado para leitura)
python mappingexpo.py -d "inurl:config.php" -o report.html

# JSON (exigido para reprocessar com --analyze, --crawl, --dbscan)
python mappingexpo.py -d "inurl:config.php" -o results.json
```

Se nenhuma extensão for informada, `.json` é anexado automaticamente.

-----

## Reprocessando Resultados Salvos

```bash
# Adicionar scan SQLi a resultados existentes
python mappingexpo.py -f Dump/results.json --sqli -o retest.json

# Adicionar scan XSS
python mappingexpo.py -f Dump/results.json --xss -o retest.json

# Rodar análise completa em resultados salvos
python mappingexpo.py -f Dump/results.json --analyze --analyze-fetch -o analysis.json
```

Útil para não repetir a busca — reutilize os resultados e adicione novas camadas de scan.

-----

## Gerador de Dorks

Gere dorks a partir dos templates embutidos e busque imediatamente.

```bash
# Gerar todas as categorias, buscar, detectar SQLi
python mappingexpo.py --dg=all --sqli -o results.json

# Gerar dorks focados em SQLi, intensidade média
python mappingexpo.py --dg=sqli --mode=medium --sqli -o results.json
```

|Valor de `--mode`|Comportamento                               |
|--------------|-------------------------------------------|
|`soft`        |Dorks de baixo risco, expansão mínima (default)|
|`medium`      |Padrões de cobertura mais amplos            |
|`aggressive`  |Máximo de combinações — alto volume de resultados|


> No celular, `soft` ou `medium` é o recomendado. `aggressive` pode gerar milhares de requisições.

-----

## Pipeline de Análise

Requer `Tools/mappingexpo_agents.py`. Pulado automaticamente se o arquivo estiver ausente.

```bash
python mappingexpo.py -d dorks.txt --analyze -o results.json
python mappingexpo.py -d dorks.txt --analyze --analyze-fetch -o results.json
```

`--analyze` — roda triage, detecção de segredos e gera um relatório após a busca.
`--analyze-fetch` — também baixa o conteúdo das páginas dos resultados HIGH / CRITICAL.

Opções de formato de saída: `html` (default), `md`, `json`, `txt`.

```bash
python mappingexpo.py -d dorks.txt --analyze --analyze-fmt md -o results.json
```

-----

## Varredura de Portas DB

Requer `Tools/db_portscan.py`. Escaneia hosts extraídos dos resultados procurando portas de banco expostas.

```bash
# Integrado — roda depois da busca
python mappingexpo.py -d dorks.txt --dbscan -o results.json

# Standalone — em resultados salvos
python Tools/db_portscan.py Dump/results.json
python Tools/db_portscan.py Dump/results.json --timeout 3 --threads 40
```

> **Nota Termux:** O default `--dbscan-threads 60` pode ser alto para alguns aparelhos Android.
> Se houver instabilidade, reduza: `--dbscan-threads 30` ou `--dbscan-threads 40`.
> IPs privados e de loopback são excluídos do scan automaticamente.

-----

## Console Web (`--ui`)

Abre um dashboard local baseado em Flask no seu navegador.

```bash
python mappingexpo.py --ui
```

> **Nota Termux:** O navegador não abre automaticamente no Android.
> Depois de iniciar, abra o navegador manualmente e acesse:
>
> ```
> http://127.0.0.1:8080
> ```
>
> Se a porta 8080 estiver ocupada, o MappingExpo auto-incrementa. Confira a saída do terminal para a porta real.

`--ui` não pode ser combinado com nenhuma outra flag de entrada (`-d`, `-u`, `-f`, `--dg`) no mesmo comando.

-----

## Controle de Interrupção

|Ação                                                |Efeito                                  |
|----------------------------------------------------|----------------------------------------|
|**Ctrl+C** único (ou **Vol Down + C** no Termux)   |Pula a tarefa atual → continua para a próxima|
|**Ctrl+C** duplo em até 1,5 s                       |Sai imediatamente → salva resultados parciais|

-----

## Combinações Comuns para Termux

```bash
# Começo mais rápido — wizard guiado
python mappingexpo.py --wizard

# Busca + SQLi + relatório HTML
python mappingexpo.py -d "inurl:.php?id=" --sqli -o results.html

# Busca + SQLi + XSS + stealth
python mappingexpo.py -d dorks.txt --sqli --xss --stealth -o results.json

# Teste direto de vulnerabilidade em URL
python mappingexpo.py -u "https://target.com/page.php?id=1"

# Gerar dorks + scan + analisar
python mappingexpo.py --dg=sqli --mode=medium --sqli --analyze -o results.json

# Reprocessar resultados salvos — adicionar análise
python mappingexpo.py -f Dump/results.json --analyze --analyze-fetch -o analysis.json

# Varredura de portas DB em resultados salvos (threads reduzidas para celular)
python Tools/db_portscan.py Dump/results.json --threads 40 --timeout 3
```

-----

## Solução de Problemas

**Build do `lxml` falha durante o `pip install`**

```bash
pkg install libxml2 libxslt
pip install -r requirements.txt
```

**`ModuleNotFoundError` de qualquer pacote**

```bash
pip install -r requirements.txt --force-reinstall
```

**`git clone` lento ou falha**

Verifique a conexão ou tente:

```bash
pkg install wget
```

e baixe o ZIP do GitHub manualmente.

**`--ui` — navegador não abre**

Esperado no Android. Abra `http://127.0.0.1:8080` manualmente em qualquer navegador.

**Ctrl+C duplo não funciona**

No Termux, use o atalho de teclado **Vol Down + C** como equivalente da tecla Ctrl.

-----

## Próximos Passos

Para a lista completa das 38 flags, combinações avançadas e documentação detalhada de módulos:

- [`Docs/cli.md`](cli.md) — referência completa da CLI
- [`Docs/xss.md`](xss.md) — engine de detecção XSS
- [`Docs/sqli.md`](sqli.md) — engine de SQL injection
- [`Docs/dbscan.md`](dbscan.md) — varredura de portas DB
- [`Docs/agents.md`](agents.md) — pipeline de análise
- [`Docs/webconsole.md`](webconsole.md) — Console Web (`--ui`)

-----

## Comunidade & Suporte

- **GitHub:** [github.com/xPloits3c/DorkEye](https://github.com/xPloits3c/DorkEye)
- **Telegram:** [t.me/DorkEye](https://t.me/DorkEye)
