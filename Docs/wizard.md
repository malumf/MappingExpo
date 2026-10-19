

# Wizard — Projeto MappingExpo

O wizard é uma sessão interativa guiada que percorre todas as opções sem exigir conhecimento de CLI. Recomendado para primeiro uso ou sessões exploratórias.

---

## Iniciar

```bash
python mappingexpo.py --wizard
```

Nenhuma outra flag é necessária — o wizard ignora todas.

---

## Menu Principal

```
┌─[ MENU PRINCIPAL ]
│  1) Busca de Google Dorks      Buscar no DuckDuckGo com dork(s)
│  2) Gerador de Dorks          Gerar dorks automaticamente a partir de templates
│  3) Criar config de exemplo   Gravar mappingexpo_config.yaml em disco
│  4) Sair
└─>
```

---

## Opção 1 — Busca de Google Dorks

O wizard pergunta cada opção em sequência:

| Pergunta | O que informar | Exemplo |
|--------|--------------|---------|
| String de dork ou arquivo | Um dork ou caminho para arquivo `.txt` | `site:example.com filetype:pdf` |
| Quantidade de resultados | Número de resultados por dork | `50` |
| Habilitar SQLi? | `y` / `n` | `y` |
| Habilitar stealth? | `y` / `n` | `n` |
| Arquivo de saída | Nome com extensão | `results.json` |
| Executar análise? | `y` / `n` (exibida se a saída for `.json`) | `y` |
| Executar crawl? | `y` / `n` | `n` |

Todos os prompts têm defaults sensatos — pressione Enter para aceitar.

---

## Opção 2 — Gerador de Dorks

| Pergunta | Opções |
|--------|---------|
| Origem dos templates | Padrão / Todos os templates / Arquivo específico |
| Categoria | Todas as categorias, ou escolha uma por número |
| Modo de geração | `soft` / `medium` / `aggressive` |
| Arquivo de saída | Nome com extensão |
| Executar análise? | `y` / `n` |
| Executar crawl? | `y` / `n` |

---

## Atalhos de Teclado Durante a Busca

| Tecla | Ação |
|-----|--------|
| `Ctrl+C` (uma vez) | Pula o dork atual e vai para o próximo |
| `Ctrl+C` (duas vezes, em até 1,5s) | Encerra a sessão completamente |

Funcionam em qualquer ponto da busca — no meio de um delay, de um dork ou de um teste SQLi.

---

## Quando Usar o Wizard vs CLI

| Situação | Use |
|-----------|-----|
| Primeira execução do MappingExpo | Wizard |
| Explorar opções interativamente | Wizard |
| Tarefas repetíveis / scriptáveis | Flags CLI |
| CI/CD ou automação | Flags CLI |
| Todas as opções conhecidas de antemão | Flags CLI |
