
<!-- ── Row 1: Identidade do projeto ── -->
![Python](https://img.shields.io/badge/Python-3.9%2B-3670A0?style=flat-square&logo=python&logoColor=ffdd54)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen?style=flat-square)
![Language](https://img.shields.io/badge/Idioma-PT--BR-blue?style=flat-square)
![Version](https://img.shields.io/badge/Version-5.0--BR-brightgreen?style=flat-square)

<!-- ── Row 2: Baseado em ── -->
[![Baseado em](https://img.shields.io/badge/Baseado%20em-DorkEye-555?style=flat-square)](https://github.com/xPloits3c/DorkEye)
[![License original](https://img.shields.io/badge/Licen%C3%A7a%20original-MIT-green?style=flat-square)](https://github.com/xPloits3c/DorkEye/blob/main/LICENSE)

---

> ⚠️ **USO AUTORIZADO APENAS**
>
> Esta ferramenta realiza consultas a motores de busca e a alvos externos.
> Use **somente** em ativos que você possui ou para os quais tem **autorização
> escrita explícita**. O autor deste fork não se responsabiliza por uso
> indevido. Consulte a legislação aplicável (**LGPD**, **Marco Civil da
> Internet**, **CFAA**) antes de qualquer operação.
>
> Baseado em [DorkEye](https://github.com/xPloits3c/DorkEye), © I.C.W.T / xPloits3c, sob licença MIT.
> Fork PT-BR mantido por **Malu F.**, sob licença MIT.

---

## 📌 O que é o MappingExpo?

**MappingExpo** é uma ferramenta de **Gerenciamento de Superfície de Ataque (ASM)** que automatiza a descoberta de ativos expostos na internet, seja por diretórios indexados, arquivos sensíveis, painéis administrativos, dumps de configuração e outros artefatos publicamente acessíveis que representam **risco real** para organizações.

Este projeto é uma versão abrasileirada do [DorkEye](https://github.com/xPloits3c/DorkEye)**, reenquadrado para uso **defensivo** em:

- 🛡️ **CTI (Cyber Threat Intelligence)**
- 🔍 **ASM (Attack Surface Management)**
- 📊 **SOC (Security Operations Center)**
- 🕵️ **DFIR (Digital Forensics and Incident Response)**

> 📎 **Licença MIT preservada. Créditos ao autor original mantidos.**

---

<!-- BANNER 2 — DIVISOR — 1280x200 px -->
<!-- Substitua abaixo -->

<div align="center">
<img src="https://via.placeholder.com/1280x200/0D1117/39FF14?text=Recursos+de+ASM+Defensivo" width="1280" height="200" alt="Divisor" />
</div>

---


| Recurso | Descrição |
|---|---|
| **Foco defensivo** | Reenquadrado para ASM, CTI e SOC — não para offensive-first |
| 🇧🇷 **100% em PT-BR** | CLI, mensagens, documentação e relatórios traduzidos |
|**Documentação clara** | Cada módulo tem doc dedicada (`/Docs/`) |
|**OPSEC explícito** | Avisos de uso responsável em cada etapa |
| **Conformidade legal** | Alinhado com LGPD, Marco Civil e boas práticas |
| **Base sólida** | Herda maturidade técnica do MappingExpo original |
| **MIT License** | Livre para uso, modificação e redistribuição |

---

<!-- BANNER 3 — DEMO (wizard/CLI) — 1280x720 px -->
<!-- Substitua abaixo com print do seu terminal rodando o wizard -->

<div align="center">
<img src="https://via.placeholder.com/1280x720/0D1117/39FF14?text=Print+do+Wizard+MappingExpo+em+PT-BR" width="1280" height="720" alt="Wizard MappingExpo PT-BR" />
</div>

---

## Recursos Principais

| Recurso | Detalhes |
|---|---|
| **Assistente interativo** | [Sessão guiada com todas as opções](Docs/wizard.md) |
| **Gerador de dorks** | [Templates YAML: `soft` / `medium` / `aggressive`](Docs/dork_generator.md) |
| **Teste direto SQLi/XSS** | [Testa uma URL diretamente com `-u`](Docs/sqli.md) |
| **Reprocessamento** | [Reexecuta análise em arquivos salvos com `-f`](Docs/cli.md) |
| **Detecção de SQL Injection** | [5 métodos: 105 payloads](Docs/sqli.md) |
| **Detecção de XSS** | [4 métodos: 111 payloads](Docs/xss.md) |
| **Console Web** | [Dashboard local estilo Matrix via browser `--ui`](Docs/webconsole.md) |
| **Scan de portas de BD** | [15 serviços, probes sem auth, 3 níveis de severidade `--dbscan`](Docs/dbscan.md) |
| **Pipeline de Agentes** | [Análise autônoma em 13 etapas](Docs/agents.md) |
| **HeaderIntelAgent** | [Vazamento de info, headers faltando, servidor desatualizado](Docs/agents.md#headerintelagent) |
| **TechFingerprintAgent** | [35 tecnologias detectadas, dorks de CVE gerados](Docs/agents.md#techfingerprintagent) |
| **EmailHarvesterAgent** | [Coleta e categoriza emails: admin / security / info...](Docs/agents.md#emailharvesteragent) |
| **PiiDetectorAgent** | [Telefone, IBAN, CPF, cartão de crédito, SSN, DOB](Docs/agents.md#piidetectoragent) |
| **SubdomainAgent** | [Extrai subdomínios e gera `queries`](Docs/agents.md#subdomainharvesteragent) |
| **Crawl adaptativo** | [Dorking recursivo multi-round](Docs/crawler.md) |
| **HTTP Fingerprinting** | [22 perfis browser/OS — Chrome, Firefox, Safari, mobile, etc.](Docs/fingerprinting.md) |
| **Formatos de saída** | [Relatório HTML interativo — tudo salvo em `Dump/`](Docs/output_formats.md) |
| **Categorias de arquivo** | [7 categorias auto-detectadas — filtro whitelist/blacklist](Docs/file_categories.md) |
| **CLI completo** | [Todas as 38 flags e combinações possíveis](Docs/cli.md) |

---

## 📦 Instalação Rápida

```bash
# ── Atualizar sistema ──
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git

# ── Clonar o repositório ──
git clone https://github.com/SEU-USUARIO/MappingExpo-BR.git
cd MappingExpo-BR

# ── Criar ambiente virtual ──
python3 -m venv mappingexpo_env

# ── Ativar ambiente ──
source mappingexpo_env/bin/activate

# ── Instalar dependências ──
pip install -r requirements.txt

# ── Modo Assistente ──
python3 mappingexpo.py --wizard
```

<!-- BANNER 3B — PRINT DO WIZARD — 1280x720 px -->
<!-- Substitua abaixo com print do wizard em execução -->

<div align="center">
<img src="https://via.placeholder.com/1280x720/0D1117/39FF14?text=Wizard+MappingExpo+em+a%C3%A7%C3%A3o" width="1280" height="720" alt="Wizard em execução" />
</div>

---

```bash
# ── Ajuda ──
python3 mappingexpo.py -h

# ── Desativar ambiente ──
deactivate

# ── Remover ambiente ──
rm -rf mappingexpo_env
```

---

<!-- BANNER 3C — PRINT DA CLI — 1280x720 px -->
<!-- Substitua abaixo com print da CLI com --help -->

<div align="center">
<img src="https://via.placeholder.com/1280x720/0D1117/39FF14?text=CLI+MappingExpo+%28--help%29" width="1280" height="720" alt="CLI --help" />
</div>

---

## Uso

### 🔹 Modo Assistente

```bash
python3 mappingexpo.py --wizard
```

### 🔹 Busca básica

```bash
python3 mappingexpo.py -d "inurl:admin" -o resultados.txt
```

### 🔹 Gerador de dorks + Detecção

```bash
python3 mappingexpo.py --dg=sqli --mode=aggressive --sqli -o relatorio.json
```

### 🔹 Teste direto de SQLi em URL

```bash
python3 mappingexpo.py -u "https://alvo.com/pagina.php?id=1" --sqli -o resultado.json
```

### 🔹 Scan rápido

```bash
python3 mappingexpo.py -d dorks.txt --no-analyze -c 200 -o rapido.csv
```

### 🔹 Reprocessar resultado salvo

```bash
python3 mappingexpo.py -f Dump/resultados.json --sqli --xss --dbscan --analyze -o reavaliacao.html
```

### 🔹 Console Web

```bash
python3 mappingexpo.py --ui
```

<!-- BANNER 3D — PRINT DO CONSOLE WEB — 1280x720 px -->
<!-- Substitua abaixo com print do dashboard web -->

<div align="center">
<img src="https://via.placeholder.com/1280x720/0D1117/39FF14?text=Console+Web+MappingExpo" width="1280" height="720" alt="Console Web" />
</div>

## 🇧🇷 LGPD — Regionalização BR e Tratamento de Dados Pessoais

O MappingExpo inclui recursos específicos para a realidade brasileira:

| Recurso | O que faz | Doc |
|---|---|---|
| **Validadores BR** | CPF e CNPJ validados por dígito verificador (Módulo 11), CEP, telefone +55 e chave Pix — detecção de PII brasileira com ~99% de precisão matemática, sem falso positivo em datas/protocolos | [Docs/validators_br.md](Docs/validators_br.md) |
| **Categorias BR de dorks** | 7 categorias para .gov.br, .edu.br, .org.br/.com.br, Pix, WhatsApp, documentos LGPD e documentos corporativos | [Docs/dorks_br.md](Docs/dorks_br.md) |

> ⚠️ **Responsabilidade com resultados sensíveis**
>
> Ao rodar o MappingExpo em ativos brasileiros, os resultados **podem conter
> dados pessoais reais** — CPFs, CNPJs, contracheques, chaves Pix e
> comprovantes. Sob a **LGPD (Lei 13.709/2018)**, esses dados são **dados
> pessoais** (e alguns, **dados sensíveis**):
>
> - Colete apenas o mínimo necessário para a finalidade autorizada (art. 6º, III);
> - **Não reposte**, copie ou armazene dados pessoais fora do escopo da
>   autorização escrita;
> - Trate relatórios contendo PII como ativos protegidos — limite o acesso;
> - Dorks das categorias `pix_br` e `documentos_br` são **especialmente
>   sensíveis**: prefira o modo `soft` e restrinja ao seu próprio domínio;
> - Ao encontrar exposição de dados pessoais de terceiros em um ativo seu,
>   o caminho defensivo correto é **corrigir a exposição** e avaliar
>   notificação à ANPD/titulares, se aplicável — não reutilizar os dados.
>
> O ponto de partida defensivo é a categoria `lgpd_br`: verifique se a sua
> própria organização publica política de privacidade, aviso de privacidade
> e canal do encarregado (DPO) conforme exige a Lei.

<!-- BANNER 5 — LEGAL — 1280x300 px -->
<!-- Substitua abaixo se quiser um aviso legal visual -->

<div align="center">
<img src="https://via.placeholder.com/1280x300/8B0000/FFFFFF?text=USO+AUTORIZADO+APENAS" width="1280" height="300" alt="Aviso Legal" />
</div>

## Aviso Legal

**MappingExpo PT-BR é fornecido apenas para fins educacionais e de teste de segurança autorizado.**

Você é o **único responsável** por cumprir todas as leis aplicáveis e por obter **autorização escrita explícita** antes de escanear, testar ou sondar qualquer sistema, domínio ou rede que não seja de sua propriedade.

Os autores e contribuidores **não aceitam qualquer responsabilidade** por uso indevido ou por danos resultantes do uso desta ferramenta.

**Legislação aplicável no Brasil:**
- **LGPD** — Lei Geral de Proteção de Dados (Lei 13.709/2018)
- **Marco Civil da Internet** (Lei 12.965/2014)
- **Lei de Crimes Cibernéticos** (Lei 12.737/2012)

**Uso pretendido:**
- Descoberta autorizada de superfície de ataque
- Monitoramento de exposição em ativos próprios
- Enriquecimento de CTI e apoio a SOC
- Pesquisa acadêmica em ambiente controlado

**Uso proibido:**
- Escaneamento de alvos sem autorização
- Coleta não autorizada de dados pessoais (viola LGPD)
- Uso em atividades ilegais de qualquer natureza

---

## Licença e Créditos

### Licença MIT

Este projeto é distribuído sob a **MIT License**.

```
MIT License

Copyright (c) 2026 I.C.W.T / xPloits3c (projeto original: DorkEye)
Copyright (c) 2026 [Seu Nome] (fork PT-BR: MappingExpo)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Créditos

- **Projeto original:** [DorkEye](https://github.com/xPloits3c/DorkEye) — © I.C.W.T / xPloits3c
- **Licença original:** MIT
- **Este fork:** MappingExpo PT-BR — © [Malu F.]
- **Licença deste fork:** MIT
- **Tradução, reframe defensivo e revisão crítica:** [Seu Nome]
