<img width="1264" height="843" alt="image" src="https://github.com/user-attachments/assets/6f4db1bb-6d7b-4225-af92-31060c14989d" />

# 📦 MappingExpo — Guia de Instalação

-----

## 🔗 Download (código-fonte)

Clone o repositório:

```
git clone https://github.com/malumf/MappingExpo.git
```

Ou baixe a última release:
👉 [github.com/malumf/MappingExpo/releases](https://github.com/malumf/MappingExpo/releases)

-----

## 📋 Sumário

1. [Pré-requisitos](#-pré-requisitos)
1. [Instalação Rápida (Recomendada)](#-instalação-rápida-recomendada)
1. [Instalação Termux / Android](#-instalação-termux--android)
1. [Verificação](#-verificação)
1. [Estrutura do Projeto](#-estrutura-do-projeto)
1. [Solução de Problemas](#-solução-de-problemas)
1. [Atualizando o MappingExpo](#-atualizando-o-mappingexpo)
1. [Desinstalação](#-desinstalação)
1. [Suporte](#-suporte)

-----

## 🔧 Pré-requisitos

|Software necessário|Comando de verificação|
|-----------------|-------------------|
|Python 3.9+      |`python3 --version`|
|pip (mais recente)|`pip3 --version`   |
|git              |`git --version`    |


> **Nota:** o `git` só é necessário para instalação via código-fonte. Para instalar via `requirements.txt`, você precisa apenas de Python e pip.

**Requisitos de sistema:**

- Linux / Windows 10+ / macOS 10.14+ / Android (Termux)
- 512 MB de RAM no mínimo
- 100 MB de espaço livre em disco
- Conexão com a internet

**Principais dependências Python** (instaladas automaticamente via `requirements.txt`):

- `ddgs` — motor de busca DuckDuckGo
- `requests` — cliente HTTP
- `rich` — formatação de terminal e barras de progresso
- `pyyaml` — parsing de configuração e templates
- `urllib3` — HTTP de baixo nível

**Dependências opcionais** (para suporte completo aos recursos):

- `mappingexpo_agents.py` em `Tools/` — habilita `--analyze` e `--crawl`
- `dork_generator.py` em `Tools/` — habilita o gerador de dorks `--dg`
- `http_fingerprints.json` — habilita a rotação de fingerprint HTTP

-----

## 🐧 Instalação Rápida
Este método funciona em **Linux**, **macOS** e **Windows**.

```
# Clone o repositório
git clone https://github.com/malumf/MappingExpo.git
cd MappingExpo

# Crie o ambiente virtual
python3 -m venv mappingexpo_env

# Ative o ambiente virtual
# Linux / macOS:
source mappingexpo_env/bin/activate

# Windows:
# mappingexpo_env\Scripts\activate

# Atualize o pip
pip install --upgrade pip

# Instale as dependências
pip install -r requirements.txt

# Verifique a instalação
python mappingexpo.py -h
```

-----

## 📱 Instalação Termux / Android

O MappingExpo detecta o Termux automaticamente e ativa o modo economia de bateria (timeouts reduzidos, menos amostras de probe). Nenhuma flag adicional é necessária.

### Via código-fonte

```
# Instale Python e git
pkg update && pkg upgrade
pkg install python git

# Clone e instale
git clone https://github.com/malumf/MappingExpo.git
cd MappingExpo

# Crie o ambiente virtual (recomendado para evitar conflitos de pacotes no Termux)
python -m venv mappingexpo_env
source mappingexpo_env/bin/activate

# Instale as dependências
pip install --upgrade pip
pip install -r requirements.txt

# Execute
python mappingexpo.py --wizard
```

💡 No Termux, o MappingExpo automaticamente:

- Reduz os timeouts de conexão (3s vs 4s)
- Reduz a contagem de amostras de probe SQLi (booleanas/time-based)
- Exibe no banner um badge de plataforma indicando Android / Termux com economia de bateria ativa

-----

## ✅ Verificação

### Via código-fonte:

```
# Exibe a ajuda e todas as flags
python mappingexpo.py -h

# Cria um arquivo de config de exemplo
python mappingexpo.py --create-config

# Busca de teste rápida
python mappingexpo.py -d "python programming" -c 5 -o test.html

# Testa o gerador de dorks (se houver templates)
python mappingexpo.py --dg=all --mode=soft -c 5 -o dg_test.html

# Abre o wizard interativo
python mappingexpo.py --wizard
```
-----

## 📁 Estrutura do Projeto

```
MappingExpo/
├── mappingexpo.py                  # Script principal
├── requirements.txt            # Dependências Python
├── mappingexpo_config.yaml         # Config (gerada com --create-config)
├── http_fingerprints.json      # Perfis de fingerprint de navegador
├── Tools/
│   ├── dork_generator.py       # Motor do Gerador de Dorks (--dg)
│   ├── mappingexpo_agents.py       # Agents de análise + crawl (--analyze, --crawl)
│   ├── mappingexpo_analyze.py      # Script de análise standalone (executável diretamente)
│   └── mappingexpo_patterns.py     # Utilitários de pattern matching
├── Templates/
│   ├── dorks_templates.yaml    # Templates de dorks padrão
│   └── *.yaml                  # Arquivos de template adicionais
└── Dump/                       # Pasta de saída (criada automaticamente)
    ├── results.json
    ├── report.html
    └── ...
```

-----

## 🐛 Solução de Problemas

### `ModuleNotFoundError: ddgs`

O módulo do motor de busca foi renomeado. Correção:

```
pip uninstall duckduckgo-search -y
pip install ddgs
```

### `Externally Managed Environment` (Kali Linux / Debian 12+)

Sistemas modernos baseados em Debian bloqueiam instalações globais do pip. Use um ambiente virtual:

```
python3 -m venv mappingexpo_env
source mappingexpo_env/bin/activate
pip install -r requirements.txt
```


### Erro de sintaxe com `--templates=arquivo.yaml`

A flag `--templates` exige a sintaxe com `=` (sem espaço):

```
# ✅ Correto
python mappingexpo.py --dg=sqli --templates=dorks_templates.yaml

# ❌ Errado
python mappingexpo.py --dg=sqli --templates dorks_templates.yaml
```

### Aviso `mappingexpo_agents.py not found`

Os recursos `--analyze` e `--crawl` exigem `mappingexpo_agents.py` no diretório `Tools/`. Se estiver ausente, o MappingExpo roda normalmente, mas esses recursos ficam desabilitados. Certifique-se de que seu clone está atualizado:

```
git pull origin master
```

> **Nota:** para suporte completo aos recursos (agents, gerador de dorks), use a instalação via código-fonte — é ela que garante o diretório `Tools/` completo.

### Aviso de fingerprint HTTP desabilitado

Se `http_fingerprints.json` estiver ausente ou malformado, o MappingExpo faz fallback para a rotação básica de User-Agent. Baixe o arquivo novamente do repositório.

### Avisos de SSL/TLS

O MappingExpo desabilita a verificação de SSL para máxima compatibilidade durante varreduras OSINT. Mensagens de `InsecureRequestWarning` são suprimidas automaticamente.

-----

## 🔄 Atualizando o MappingExpo

### Instalação via código-fonte:

```
cd MappingExpo
git pull origin master
pip install --upgrade -r requirements.txt
```
-----

## 🗑️ Desinstalação

```
rm -rf MappingExpo
```

**Windows:**

```
rmdir /s /q MappingExpo
```

**Remover apenas o ambiente virtual:**

```
rm -rf mappingexpo_env
```

**Se instalado no modo CLI (código-fonte):**

```
pip uninstall mappingexpo
```

-----

## 📞 Suporte

Se encontrar problemas, abra uma issue no GitHub:
👉 [github.com/malumf/MappingExpo/issues](https://github.com/malumf/MappingExpo/issues)

Inclua, por favor:

- Sistema operacional + versão
- Versão do Python (`python3 --version`)
- Método de instalação (código-fonte)
- Mensagem de erro completa / traceback
- Passos para reproduzir o problema
- Se você está usando um ambiente virtual

-----

## ✅ Checklist Pós-Instalação

**Instalação via código-fonte:**

- ✔ Python 3.9+
- ✔ Ambiente virtual ativo
- ✔ Dependências instaladas (`pip install -r requirements.txt`)
- ✔ `python mappingexpo.py -h` exibe a ajuda
- ✔ `python mappingexpo.py --create-config` cria a config
- ✔ Busca de teste funciona (`-d "test" -c 5 -o test.html`)
- ✔ Gerador de dorks funciona (`--dg=all -c 5 -o dg_test.html`)
- ✔ Wizard abre (`--wizard`)

-----

## 🎯 Instalação Concluída

O MappingExpo está pronto! Boa caçada. 🔍
