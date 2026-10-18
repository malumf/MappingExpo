# Validadores BR — CPF, CNPJ, CEP, Telefone e Pix

> 📦 **Fase 2 (regionalização BR) — Sublote F2.1**
> Documentação dos validadores de PII brasileira implementados em
> `Tools/mappingexpo_patterns.py` e integrados ao `PiiDetectorAgent`
> (`Tools/mappingexpo_agents.py`).

---

## Por que regex puro não basta

Uma regex casa **forma**, não **validade**. Qualquer sequência de 11 dígitos
casa com um "CPF" em regex puro — incluindo datas (`20240115000`), protocolos
de atendimento e IDs internos de sistema. Para CPF e CNPJ, o Brasil usa
**dígitos verificadores** (Módulo 11): é possível calcular, a partir dos
dígitos base, quais os dois últimos dígitos *deveriam* ser e rejeitar o caso
se não baterem. A detecção do MappingExpo funciona em duas fases:

1. **Regex** — match do formato (ex.: `XXX.XXX.XXX-XX` ou 11 dígitos após a
   palavra-chave `cpf`);
2. **Validador pós-match** — `cpf_is_valid()` recalcula os dígitos
   verificadores e descarta o match se estiverem errados.

O mesmo padrão já era usado pelo projeto original para cartões de crédito
(`luhn_check`), e agora se estende à PII brasileira através do mapa
`PII_VALIDATORS`.

---

## CPF — `cpf_is_valid()`

**Formato detectado**: `XXX.XXX.XXX-XX` (sempre) · 11 dígitos "soltos"
(somente ancorado pela palavra-chave `cpf`/`cpf nº`, para evitar falso
positivo em massa).

**Algoritmo (Módulo 11 — Receita Federal):**

```text
dígitos:        d1 d2 d3 d4 d5 d6 d7 d8 d9 | DV1 DV2

DV1: soma   = d1×10 + d2×9 + d3×8 + ... + d9×2     (pesos 10..2)
     resto  = soma % 11
     DV1    = 0        se resto < 2
              11-resto caso contrário

DV2: soma   = d1×11 + d2×10 + ... + d9×3 + DV1×2    (pesos 11..2)
     resto  = soma % 11
     DV2    = 0        se resto < 2
              11-resto caso contrário

válido  ⟺  DV1 e DV2 calculados == DV1 e DV2 informados
           E não são todos os dígitos iguais
```

**Rejeição de sequências repetidas**: `111.111.111-11`, `000.000.000-00` etc.
satisfazem o Módulo 11 matematicamente, mas **não existem** como CPF reais —
o validador os rejeita explicitamente.

**Casos de teste (vetores usados na suíte de verificação):**

| Entrada | Resultado esperado |
|---|---|
| `529.982.247-25` (exemplo oficial da Receita) | ✅ válido |
| `52998224725` (bare, com keyword `cpf:`) | ✅ válido |
| `111.111.111-11` | ❌ rejeitado (repetido) |
| `000.000.000-00` | ❌ rejeitado (repetido) |
| `529.982.247-35` | ❌ rejeitado (DV1 errado) |
| `529.982.247-22` | ❌ rejeitado (DV2 errado) |
| `20240115000` (data-like) | ❌ rejeitado (DV) |

---

## CNPJ — `cnpj_is_valid()`

**Formato detectado**: `XX.XXX.XXX/XXXX-XX` (sempre) · 14 dígitos "soltos"
(somente ancorado por `cnpj`/`cnpj nº`).

**Algoritmo (Módulo 11):** a diferença do CPF são os pesos, que "retrocedem"
da posição 9 e voltam a cair:

```text
DV1: pesos  5 4 3 2 9 8 7 6 5 4 3 2   sobre d1..d12
DV2: pesos  6 5 4 3 2 9 8 7 6 5 4 3 2 sobre d1..d13 (inclui DV1)
resto < 2 → DV = 0; senão DV = 11 - resto
Rejeita também todos os dígitos iguais (00.000.000/0000-00).
```

**Casos de teste:**

| Entrada | Resultado esperado |
|---|---|
| `11.222.333/0001-81` | ✅ válido |
| `11222333000181` (bare, com keyword) | ✅ válido |
| `11.222.333/0002-81` | ❌ rejeitado (DV1 errado) |
| `11.222.333/0001-80` | ❌ rejeitado (DV2 errado) |
| `00.000.000/0000-00` | ❌ rejeitado (repetido) |

---

## CEP — sem validador (formato é a validação)

**Formato detectado**: `XXXXX-XXX` (sempre) · 8 dígitos (keyword `cep`).
CEP **não possui dígito verificador** — qualquer combinação de 5+3 dígitos
é formalmente plausível. A validação adicional (faixa de CEP por UF) exigiria
tabela de faixas dos Correios, fora do escopo. Interprete matches de CEP como
"possível CEP", não como "CEP existente".

---

## Telefone BR — `phone_br_is_valid()`

**Formatos detectados (regex)**:

- Móvel: `(11) 91234-5678` · `+55 11 91234-5678` · `11 91234-5678` ·
  `11912345678` (bare) — o `9` inicial do móvel é exigido pela própria regex;
- Fixo: `(11) 3234-5678` — apenas com parênteses (forma canônica), prefixo
  `2`–`5`.

**Validador (estrutural):**

```text
1. extrai só dígitos;
2. se total = 12 ou 13 dígitos e começa com "55", remove o +55;
   (se total = 10/11, NÃO remove — preserva DDD 55 = Rio Grande do Sul)
3. exige 10 dígitos (fixo) ou 11 (móvel);
4. exige DDD entre 11 e 99 (10 não existe);
5. 11 dígitos ⟹ 3º dígito obrigatoriamente '9' (nono dígito, pós-2012).
```

**Casos de teste:** `+55 11 91234-5678` ✅ · `(55) 3222-1234` ✅ (DDD real,
sem strip indevido) · `+55 55 3222-1234` ✅ · `(10) 91234-5678` ❌ (DDD 10) ·
`11 81234-5678` ❌ (móvel sem 9).

---

## Chave Pix — sem validador (multi-tipo)

Detectada apenas com ancoragem por palavra-chave (`chave pix`,
`chave-pix`, `chave_pix`). A chave pode ser **e-mail**, **telefone** (+55…),
**CPF**, **CNPJ** ou **aleatória** (UUID-like) — por isso não há um validador
único. Quando o valor for CPF/CNPJ, os validadores correspondentes podem ser
aplicados manualmente com `cpf_is_valid()`/`cnpj_is_valid()` se necessário.

---

## Taxas esperadas de falso positivo

Interpretação prática para quem analisa relatórios:

| Regra | Falso positivo estimado | Motivo |
|---|---|---|
| `CPF_BR` formatado | ~0,8% dos matches | Sequência aleatória de 11 dígitos passa nos 2 DVs com p ≈ (1/11)² ≈ 0,83% |
| `CPF_BR` bare (keyword) | ~0,8% **após** a keyword | Mesmo cálculo, mas a âncora `cpf` já elimina quase todo o ruído |
| `CNPJ_BR` formatado/bare | ~0,8% | Mesma matemática dos 2 DVs |
| `CEP_BR` formatado | moderado | Sem DV; qualquer 5+3 dígitos com hífen casa |
| `PHONE_BR` móvel bare | ~9% de 11 dígitos quaisquer | A regex exige `9` na 3ª posição (corta 90%) e o validador corta DDD ≥ 11 (cerca de 88% do restante) — sobram ~9% de coincidência estrutural em texto não-telefone |
| `PIX_BR` | baixo | Ancoragem por palavra-chave explícita |

**Conclusão prática**: um `CPF_BR` reportado tem ~99,2% de chance de ser um
CPF matematicamente plausível. Em relatórios de auditoria, matches de CPF/CNPJ
justificam verificação manual; matches de CEP/telefone devem ser tratados
como **pistas**, não como confirmação.

---

## Como o pipeline usa tudo isso

`PiiDetectorAgent._scan()` (executado em cada resultado com conteúdo baixado)
itera `PII_RULES`; para cada categoria presente em `PII_VALIDATORS`, o
validador roda **antes** de o achado ser reportado — mesmo padrão do
`CREDIT_CARD → luhn_check`. Valores reportados são **censurados**
(`censor()`, 3 caracteres visíveis em cada ponta) e deduplicados por valor
normalizado.

**Ordem de reivindicação (dedup)**: o bloco BR fica **antes** das regras
asiáticas em `PII_RULES` — assim `cpf: <11 dígitos>` é reportado como
`CPF_BR`, e não como `TAX_ID_AS` (regra `\d{11}` do ABN australiano, que
casaria qualquer 11 dígitos).

## Uso programático

```python
from Tools.mappingexpo_patterns import (
    cpf_is_valid, cnpj_is_valid, phone_br_is_valid, PII_VALIDATORS,
)

cpf_is_valid("529.982.247-25")     # True
cnpj_is_valid("11.222.333/0001-81") # True
phone_br_is_valid("(55) 3222-1234") # True — DDD 55 preservado

# mapa usado pelo pipeline:
PII_VALIDATORS["CPF_BR"] is cpf_is_valid  # True
```
