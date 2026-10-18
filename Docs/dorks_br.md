# Dorks BR — Regionalização Brasileira

> 📦 **Fase 2 (regionalização BR) — Sublote F2.2**
> Categorias de dorks específicas para a realidade brasileira de OSINT defensivo.
> Detectores de PII brasileira (CPF/CNPJ/CEP/telefone/Pix) na pipeline: ver
> [validators_br.md](validators_br.md).

---

## Visão geral

O arquivo `Templates/dorks_templates.yaml` ganhou **7 categorias brasileiras**
e a variável `br_doc`. Elas seguem o mesmo schema das categorias existentes
(`soft` / `medium` / `aggressive`) e são descobertas **dinamicamente** — já
aparecem no CLI, no Console Web (dropdowns de categoria) e no wizard, sem
nenhuma configuração extra.

```bash
# Listar implicitamente — gerar dorks de uma categoria:
python3 mappingexpo.py --dg=gov_br --mode=soft
python3 mappingexpo.py --dg=documentos_br --mode=soft
python3 mappingexpo.py --dg=all --mode=aggressive --stealth   # todas + BR
```

> ⚠️ **Regra crítica**: as categorias BR **não são testadas contra alvos
> reais**. Os dorks são validados apenas por sintaxe, schema e composição
> (expansão de placeholders). O uso contra domínios reais é responsabilidade
> do operador, dentro da autorização escrita descrita no README.

---

## Categorias

| Categoria | Alvo | Dorks (S/M/A) | Sensibilidade LGPD |
|---|---|---|---|
| `gov_br` | Portais governamentais (.gov.br federal e estaduais) | 4/5/6 | Baixa–média |
| `edu_br` | Universidades, IFs e escolas (.edu.br) | 4/4/4 | Baixa–média |
| `br_domains` | Organizações e empresas (.org.br / .com.br) | 4/4/4 | Baixa–média |
| `pix_br` | Chaves Pix, comprovantes e QR codes expostos | 3/3/4 | **ALTA** |
| `whatsapp_br` | Links wa.me, grupos e integrações API expostos | 3/3/3 | Média |
| `lgpd_br` | Políticas de privacidade, avisos e DPO publicados | 3/3/4 | Baixa |
| `documentos_br` | Documentos corporativos BR (via `{br_doc}`) | 3/3/4 | **ALTA** |

### `gov_br` — Portais governamentais

Superfície exposta em portais federais e estaduais: logins administrativos,
arquivos indexados, listagens de diretório. Uso típico: ASM de órgão próprio
ou de órgão parceiro com autorização.

```text
site:gov.br inurl:login                      (soft)
site:gov.br filetype:pdf intitle:"index of"  (medium)
site:*.gov.br filetype:xls intext:"secret"   (aggressive)
```

### `edu_br` — Instituições de ensino

Universidades federais, institutos federais e escolas. Dumps de extensão
acadêmica (`.edu`, `.edu.br`) costumam expor listas, repositórios e painéis
de administração desatualizados.

```text
site:edu.br intitle:"index of"               (soft)
site:edu.br filetype:pdf "edital"            (medium — via br_doc)
site:*.edu.br filetype:sql intext:"password"  (aggressive)
```

### `br_domains` — Organizações e empresas (.org.br / .com.br)

Contraparte BR das categorias genéricas (admin/backups/databases) focada
nos TLDs nacionais.

```text
site:com.br intitle:"login"                  (soft)
site:org.br filetype:sql intitle:"index of"  (medium)
site:*.com.br intext:"secret" filetype:env   (aggressive)
```

### `pix_br` — Pix ⚠️

> ⚠️ **AVISO LGPD**: estes dorks podem retornar **dados pessoais reais** —
> comprovantes com nome/CPF, chaves Pix (que podem ser o CPF, o telefone ou
> o e-mail da vítima). Restrinja ao seu próprio domínio sempre que possível,
> prefira o modo `soft`, e trate todo resultado como **dado sensível**
> (art. 5º, II e III, LGPD).

```text
site:{domain} "chave pix"                    (soft)
site:{domain} intitle:"comprovante pix"      (medium)
site:com.br "chave pix" filetype:pdf         (aggressive)
```

### `whatsapp_br` — WhatsApp

Links de contato e grupos (`wa.me`, `api.whatsapp.com`) expostos — indicativo
de superfície de engenharia social e de integrações API mal protegidas.

```text
site:{domain} wa.me                          (soft)
site:com.br api.whatsapp.com inurl:send      (medium)
site:com.br intext:"api.whatsapp.com/send"   (aggressive)
```

### `lgpd_br` — Conformidade LGPD

Uso **defensivo por excelência**: verificar se a própria organização publica
política de privacidade, aviso de privacidade e canal do DPO/encarregado,
como exigido pela LGPD.

```text
site:{domain} "política de privacidade"       (soft)
site:{domain} "encarregado de dados"         (medium)
site:gov.br "política de privacidade" filetype:pdf  (aggressive)
```

### `documentos_br` — Documentos corporativos ⚠️

> ⚠️ **AVISO LGPD**: usa a variável `{br_doc}` (contracheque, holerite,
> "nota fiscal", boleto, edital, "licitação", portaria, "folha de pagamento").
> Contracheques e folhas de pagamento contêm **nome, CPF e salário** de
> pessoas reais. Use apenas em ativos próprios ou com autorização escrita
> explícita, preferencialmente em modo `soft`.

```text
site:{domain} filetype:pdf "licitação"       (soft)
site:gov.br filetype:pdf "contracheque"      (medium)
site:com.br filetype:xls "folha de pagamento"  (aggressive)
```

---

## Variável `br_doc`

Termos de documentos administrativos/corporativos brasileiros, definida em
`Templates/dorks_templates.yaml` e consumida pela categoria `documentos_br`:

| Termo | Contexto típico de exposição |
|---|---|
| `contracheque`, `holerite` | Pastas públicas de RH — **dado sensível** |
| `"nota fiscal"` | Portais de compras públicas e ERPs expostos |
| `boleto` | Diretórios de cobrança, backups de sistemas financeiros |
| `edital`, `"licitação"` | Portais de transparência (geralmente públicos por design) |
| `portaria` | Intranets expostas, repositórios de normas internas |
| `"folha de pagamento"` | Planilhas públicas — **dado sensível** |

---

## Modos

Mesma semântica do restante do projeto:

- **soft** — consultas seguras, pouco ruído; use em varreduras periódicas.
- **medium** — avaliação equilibrada; use com `--stealth` em superfícies grandes.
- **aggressive** — cobertura máxima; **sempre** combine com `--stealth` e
  revise os avisos LGPD acima antes de rodar em TLDs amplos (`site:com.br`).

---

## Integração com os agentes

Resultados encontrados com essas categorias entram na pipeline de análise
normalmente. O `PiiDetectorAgent` aplica os **validadores BR** (CPF/CNPJ por
dígito verificador, telefone por DDD) sobre o conteúdo das páginas baixadas —
detalhes, algoritmos e taxas de falso positivo em
[validators_br.md](validators_br.md).
