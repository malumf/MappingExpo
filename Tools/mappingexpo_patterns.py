"""
MappingExpo Patterns
======================
mappingexpo_patterns.py — Shared pattern library for MappingExpo Project
===============================================================
Centraliza padrões, constantes e auxiliares que estavam duplicados entre
mappingexpo_agents.py e mappingexpo_analyze.py:

  - TRIAGE_RULES       — pontuação por regex para classificação de prioridade OSINT
  - SECRET_RULES       — padrões de detecção de credenciais/segredos (+ hashes)
  - SECRET_SEVERITY    — mapa tipo → severidade (CRITICAL/HIGH/MEDIUM/LOW)
  - PII_RULES          — padrões de PII organizados por geografia:
                           · EMAIL           (global)
                            · PHONE_US        (Estados Unidos e Canadá)
                            · PHONE_EU        (União Europeia + Reino Unido + CH + NO)
                            · PHONE_ME        (Oriente Médio)
                            · PHONE_AS        (Ásia-Pacífico)
                           · IBAN            (global)
                           · TAX_ID_US       (SSN, EIN)
                            · TAX_ID_EU       (VAT da UE / códigos fiscais nacionais)
                            · TAX_ID_ME       (identidades nacionais do Oriente Médio)
                            · TAX_ID_AS       (identidades nacionais / tax IDs asiáticos)
                            · CREDIT_CARD     (global, validado por Luhn)
                            · NIN_EU          (números de identidade nacional da UE)
                            · NID_ME          (números de identidade nacional do Oriente Médio)
                            · NID_AS          (números de identidade nacional da Ásia)
                           · PASSPORT        (global)
                           · DOB             (global)
                            · PUBLIC_IP       (global)
                            · CPF_BR          (Brasil — validação Módulo 11)
                            · CNPJ_BR         (Brasil — validação Módulo 11)
                            · CEP_BR          (Brasil)
                            · PHONE_BR        (Brasil, +55)
                            · PIX_BR          (Brasil — chave Pix)
   - SCORE_TO_LABEL     — limiares de pontuação → label (CRITICAL/HIGH/MEDIUM/LOW/SKIP)
   - FETCH_UA           — User-Agent compartilhado para fetch de páginas
   - FETCH_UA_POOL      — pool de UAs para rotação
   - SKIP_EXTENSIONS    — extensões binárias a pular durante o fetch
   - label_from_score() — função de conversão pontuação → label
   - censor()           — mascaramento parcial de valores sensíveis
    - luhn_check()       — validação de número de cartão de crédito (algoritmo de Luhn)
    - cpf_is_valid()     — validação de CPF pelo algoritmo oficial (Módulo 11)
    - cnpj_is_valid()    — validação de CNPJ pelo algoritmo oficial (Módulo 11)
    - phone_br_is_valid()— validação de telefone BR (DDD 11–99, 8/9 dígitos)
    - PII_VALIDATORS     — mapa categoria BR → validador pós-match

Changelog v2.0
--------------
  - PHONE_IT removido; substituído por PHONE_ME (Oriente Médio) e PHONE_AS (Ásia-Pacífico)
  - CF_IT (código fiscal italiano) removido
  - PII_RULES totalmente reorganizado por área geográfica (US / EU / ME / AS)
  - TAX_ID adicionado para as quatro áreas geográficas
  - NIN/NID (números de identidade nacional) adicionados para EU, ME, AS
  - Sem alvos diretos; todos os padrões são de nível OSINT genérico

  Fase 2 (regionalização BR):
  - CPF/CNPJ/CEP/telefone +55/chave Pix + validadores de dígito
    verificador (Módulo 11) — PII brasileira com validação obrigatória
"""

from __future__ import annotations

import re, io
from typing import List, Tuple

# ── Aliases de tipo ──────────────────────────────────────────────────────────────
# (categoria, padrão compilado, descrição, tem_grupo_de_captura)
SecretRule = Tuple[str, re.Pattern, str, bool]
PiiRule    = Tuple[str, re.Pattern, str, bool]

# ══════════════════════════════════════════════════════════════════════════════
#  SCORE → LABEL
# ══════════════════════════════════════════════════════════════════════════════

SCORE_TO_LABEL: List[Tuple[int, str]] = [
    (90, "CRITICAL"),
    (70, "HIGH"),
    (50, "MEDIUM"),
    (20, "LOW"),
    (0,  "SKIP"),
]


def label_from_score(score: int) -> str:
    """Converte uma pontuação de 0 a 100 no label de prioridade correspondente."""
    for threshold, lbl in SCORE_TO_LABEL:
        if score >= threshold:
            return lbl
    return "SKIP"


# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTES DE FETCH
# ══════════════════════════════════════════════════════════════════════════════

# User-Agent compartilhado para download de páginas.
FETCH_UA: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Pool de UAs para rotação (PageFetchAgent+)
FETCH_UA_POOL: list = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

# Extensões binárias/não-texto: estas URLs são puladas durante o fetch.
SKIP_EXTENSIONS: frozenset = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods",
    ".zip", ".rar", ".tar", ".gz", ".7z", ".bz2",
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
    ".mp4", ".mp3", ".avi", ".mov", ".wmv",
    ".exe", ".dll", ".so", ".bin", ".apk",
})


# ══════════════════════════════════════════════════════════════════════════════
#  AUXILIARES
# ══════════════════════════════════════════════════════════════════════════════

def censor(value: str, show: int = 4) -> str:
    """Mascara parcialmente um valor sensível, deixando 'show' caracteres
    visíveis no início e no fim.

    Exemplos:
        censor("sk-abc123xyz456")  → "sk-a…x456"
        censor("ab12")             → "****"
    """
    v = value.strip()
    if len(v) <= show * 2:
        return "*" * len(v)
    return v[:show] + "…" + v[-show:]


# ══════════════════════════════════════════════════════════════════════════════
#  PADRÕES DE TRIAGE
# ══════════════════════════════════════════════════════════════════════════════
# Cada entrada: (padrão, bônus de pontuação, descrição)

TRIAGE_RULES: List[Tuple[re.Pattern, int, str]] = [
    (re.compile(r"\.(env|git|svn|htpasswd|bak|backup|sql|db|sqlite|dump)(\b|$)", re.I), 38, "config/backup exposto"),
    (re.compile(r"phpmyadmin|adminer|pgadmin|webmin|dbadmin",                     re.I), 35, "painel admin de banco de dados"),
    (re.compile(r"wp-config\.php|configuration\.php|config\.inc\.php",            re.I), 34, "arquivo de config de CMS"),
    (re.compile(r"(?:^|/)\.env(?:\.|$)",                                          re.I), 38, "arquivo .env"),
    (re.compile(r"/admin/|/administrator/|/wp-admin/|/panel/|/cpanel/|/plesk/",   re.I), 22, "painel admin"),
    (re.compile(r"api[_\-]?key|api[_\-]?secret|access[_\-]?token",               re.I), 28, "credencial de API"),
    (re.compile(r"password|passwd|credentials|credential",                        re.I), 24, "credenciais"),
    (re.compile(r"directory\s+listing|index\s+of\s+/",                           re.I), 22, "listagem de diretório"),
    (re.compile(r"config\.php|config\.yml|settings\.py|web\.config|appsettings",  re.I), 28, "arquivo de config"),
    (re.compile(r"\.php\?id=\d|\.asp\?id=\d|select\s.+from\s|union\s.+select",   re.I), 26, "candidato a SQLi"),
    (re.compile(r"wp-content|wordpress",                                          re.I), 12, "wordpress"),
    (re.compile(r"joomla|drupal|magento|prestashop",                              re.I), 14, "cms"),
    (re.compile(r"amazonaws\.com|storage\.googleapis|digitalocean\s*spaces",      re.I), 18, "armazenamento em cloud"),
    (re.compile(r"error|exception|stack\s*trace|debug\s*mode|traceback",          re.I), 14, "vazamento de erro/debug"),
    (re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY",                         re.I), 45, "chave privada exposta"),
    (re.compile(r"AKIA[0-9A-Z]{16}",                                                  ), 42, "AWS Access Key ID"),
    (re.compile(r"(?:ssh|ftp|sftp|telnet)://[^\s]{6,}",                          re.I), 30, "protocolo com credenciais"),
    (re.compile(r"phpinfo|server-status|server-info",                             re.I), 20, "informações de servidor expostas"),
    (re.compile(r"swagger|openapi|api-docs|redoc",                                re.I), 16, "documentação de API exposta"),
    (re.compile(r"login|signin|logon",                                            re.I),  8, "página de login"),
    # v4.8+
    (re.compile(r"jenkins|gitlab|github|bitbucket|sonarqube",                    re.I), 18, "painel DevOps"),
    (re.compile(r"kibana|grafana|prometheus|splunk|elasticsearch",                re.I), 22, "painel de monitoramento/logs"),
    (re.compile(r"docker|kubernetes|k8s|helm|rancher",                            re.I), 16, "infra de containers"),
    (re.compile(r"\.log$|error\.log|access\.log|debug\.log",                     re.I), 20, "arquivo de log"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",                       ), 36, "token JWT"),
    (re.compile(r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}",                         ), 42, "chave de API de cloud"),
    (re.compile(r"inurl:upload|inurl:shell|inurl:cmd|inurl:exec",                re.I), 30, "candidato a RCE"),
    (re.compile(r"xmlrpc\.php|eval\(|base64_decode\(",                           re.I), 24, "indício de injeção de código"),
]


# ══════════════════════════════════════════════════════════════════════════════
#  PADRÕES DE SEGREDOS
# ══════════════════════════════════════════════════════════════════════════════
# Cada entrada: (categoria, padrão compilado, descrição, tem_grupo_de_captura)
# tem_grupo_de_captura=True  → usar match.group(1) para o valor
# tem_grupo_de_captura=False → usar match.group(0) para o valor

SECRET_RULES: List[SecretRule] = [
    # ── API Keys ──────────────────────────────────────────────────────────────
    ("API_KEY",    re.compile(r"api[_\-]?key\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?",          re.I), "Chave de API genérica",        True),
    ("API_KEY",    re.compile(r"api[_\-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?",       re.I), "Segredo de API",             True),
    ("API_KEY",    re.compile(r"x[_\-]?api[_\-]?key\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?",  re.I), "Valor do header X-API-Key", True),

    # ── Tokens ────────────────────────────────────────────────────────────────
    ("TOKEN",      re.compile(r"(?:access|auth)[_\-]?token\s*[=:]\s*['\"]?([A-Za-z0-9\-_.]{20,})['\"]?",    re.I), "Token de acesso/autenticação",     True),
    ("TOKEN",      re.compile(r"bearer\s+([A-Za-z0-9\-_.]{20,})",                                            re.I), "Bearer token",          True),
    ("TOKEN",      re.compile(r"(?:secret|private)[_\-]?token\s*[=:]\s*['\"]?([A-Za-z0-9\-_.]{16,})['\"]?", re.I), "Token secreto",          True),
    ("TOKEN",      re.compile(r"(?:refresh|session)[_\-]?token\s*[=:]\s*['\"]?([A-Za-z0-9\-_.]{20,})['\"]?",re.I), "Token de sessão/refresh", True),

    # ── Senhas ─────────────────────────────────────────────────────────────
    ("PASSWORD",   re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"<>{}\[\]]{6,})['\"]?",        re.I), "Senha",              True),
    ("PASSWORD",   re.compile(r"DB_PASS(?:WORD)?\s*[=:]\s*['\"]?([^\s'\"]{4,})['\"]?",                       re.I), "Senha de banco de dados",           True),
    ("PASSWORD",   re.compile(r"(?:admin|root|user)[_\-]?pass(?:word)?\s*[=:]\s*['\"]?([^\s'\"]{4,})['\"]?", re.I), "Senha de admin/root",   True),

    # ── Conexões de banco de dados ──────────────────────────────────────────────────
    ("DB_CONN",    re.compile(r"(mysql|postgresql|postgres|mongodb|redis|mssql|mariadb|sqlite)://[^\s'\"<>]+", re.I), "URI de conexão de banco de dados",    False),
    ("DB_CONN",    re.compile(r"(?:DATABASE_URL|MONGO_URI|REDIS_URL|DB_HOST)\s*[=:]\s*['\"]?([^\s'\"]{4,})['\"]?", re.I), "Variável de ambiente com URI/host de banco de dados", True),
    ("DB_CONN",    re.compile(r"(?:DB_NAME|DB_USER)\s*[=:]\s*['\"]?([^\s'\"]{2,})['\"]?",                     re.I), "Nome/usuário de banco de dados",          True),

    # ── JWT ───────────────────────────────────────────────────────────────────
    ("JWT",        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),                   "JWT token",             False),

    # ── AWS ───────────────────────────────────────────────────────────────────
    ("AWS_KEY",    re.compile(r"AKIA[0-9A-Z]{16}"),                                                                  "AWS Access Key ID",     False),
    ("AWS_KEY",    re.compile(r"aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.I), "AWS Secret Key", True),
    ("AWS_KEY",    re.compile(r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{16,})['\"]?", re.I), "Variável de ambiente AWS",  True),

    # ── Google / GCP ──────────────────────────────────────────────────────────
    ("GCP_KEY",    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                                                            "Google API Key",        False),
    ("GCP_KEY",    re.compile(r"\"type\"\s*:\s*\"service_account\""),                                                 "GCP Service Account",   False),
    ("GCP_KEY",    re.compile(r"(?:GOOGLE_API_KEY|FIREBASE_TOKEN)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?", re.I), "Variável de ambiente Google",       True),

    # ── Azure ─────────────────────────────────────────────────────────────────
    ("AZURE_KEY",  re.compile(r"AccountKey=([A-Za-z0-9+/=]{60,})",                                            re.I), "Azure Storage Key",     True),
    ("AZURE_KEY",  re.compile(r"(?:AZURE_CLIENT_SECRET|AZURE_TENANT_ID)\s*[=:]\s*['\"]?([A-Za-z0-9\-]{8,})['\"]?", re.I), "Segredo Azure",    True),

    # ── Chaves privadas ──────────────────────────────────────────────────────────
    ("PRIVATE_KEY",re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"),                "Chave privada",           False),
    ("PRIVATE_KEY",re.compile(r"-----BEGIN\s+CERTIFICATE-----"),                                                      "Certificado",           False),

    # ── Stripe ────────────────────────────────────────────────────────────────
    ("STRIPE_KEY", re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{24,}"),                                                 "Stripe Secret Key",     False),
    ("STRIPE_KEY", re.compile(r"pk_(?:live|test)_[A-Za-z0-9]{24,}"),                                                 "Stripe Public Key",     False),

    # ── GitHub ────────────────────────────────────────────────────────────────
    ("GITHUB_KEY", re.compile(r"ghp_[A-Za-z0-9]{36}"),                                                               "GitHub Personal Token", False),
    ("GITHUB_KEY", re.compile(r"github[_\-]?(?:token|secret)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?", re.I),   "Token GitHub",          True),

    # ── Slack ─────────────────────────────────────────────────────────────────
    ("SLACK_KEY",  re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),                                                     "Slack token",           False),
    ("WEBHOOK",    re.compile(r"https://hooks\.(slack|discord|teams)\.com/[^\s'\"<>]+",                       re.I),  "Webhook URL",           False),

    # ── Segredos genéricos ───────────────────────────────────────────────────────
    ("SECRET",     re.compile(r"(?:client_secret|app_secret|app_key)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{16,})['\"]?",   re.I), "Client secret",   True),
    ("SECRET",     re.compile(r"(?:encryption_key|signing_key|hmac_key)\s*[=:]\s*['\"]?([A-Za-z0-9\-_+/=]{16,})['\"]?", re.I), "Chave criptográfica",  True),

    # ── Credenciais SSH / FTP ─────────────────────────────────────────────────
    ("SSH_CRED",   re.compile(r"(?:ssh|ftp|sftp)://[^:@\s]{2,}:[^@\s]{4,}@[^\s'\"<>]{4,}",                  re.I),  "Protocolo com credenciais", False),

    # ── Variáveis .env ────────────────────────────────────────────────────────
    ("ENV_VAR",    re.compile(r"^(?:SECRET|KEY|PASS|TOKEN|AUTH|CRED)[A-Z0-9_]*\s*=\s*.{6,}$",            re.M | re.I), "Variável secreta de .env", False),

    # ── IPs internos ──────────────────────────────────────────────────────────
    ("INTERNAL",   re.compile(r"(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)"), "Endereço IP interno", False),

    # ── Hash / Digest ─────────────────────────────────────────────────────────
    ("HASH_BCRYPT", re.compile(r"\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}"),                                              "Bcrypt hash",           False),
    ("HASH_MD5",    re.compile(r"\b([a-fA-F0-9]{32})\b"),                                                            "MD5 hash",              False),
    ("HASH_SHA1",   re.compile(r"\b([a-fA-F0-9]{40})\b"),                                                            "SHA-1 hash",            False),
    ("HASH_SHA256", re.compile(r"\b([a-fA-F0-9]{64})\b"),                                                            "SHA-256 hash",          False),
    ("HASH_SHA512", re.compile(r"\b([a-fA-F0-9]{128})\b"),                                                           "SHA-512 hash",          False),
    ("HASH_NTLM",   re.compile(r"\b([a-fA-F0-9]{32}):[a-fA-F0-9]{32}\b"),                                           "NTLM hash pair",        False),

    # ── Cloud / SaaS adicionais ───────────────────────────────────────────────
    ("TWILIO_KEY",  re.compile(r"SK[a-zA-Z0-9]{32}"),                                                                "Twilio API Key",        False),
    ("SENDGRID",    re.compile(r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}"),                                      "SendGrid API Key",      False),
    ("MAILGUN",     re.compile(r"key-[a-zA-Z0-9]{32}"),                                                              "Mailgun API Key",       False),
    ("HEROKU_KEY",  re.compile(r"heroku[_\-]?(?:api[_\-]?)?key\s*[=:]\s*['\"]?([a-f0-9\-]{36})['\"]?",    re.I),   "Chave de API Heroku",        True),
    ("DOCKER_PAT",  re.compile(r"dckr_pat_[A-Za-z0-9_\-]{20,}"),                                                    "Docker PAT",            False),
    ("NPM_TOKEN",   re.compile(r"npm_[A-Za-z0-9]{36}"),                                                              "NPM token",             False),
    ("GITLAB_PAT",  re.compile(r"glpat-[A-Za-z0-9_\-]{20}"),                                                        "GitLab PAT",            False),
]


# ══════════════════════════════════════════════════════════════════════════════
#  MAPA DE SEVERIDADE DOS SEGREDOS
# ══════════════════════════════════════════════════════════════════════════════

SECRET_SEVERITY: dict = {
    "PRIVATE_KEY":  "CRITICAL",
    "AWS_KEY":      "CRITICAL",
    "HASH_BCRYPT":  "CRITICAL",
    "HASH_NTLM":    "CRITICAL",
    "STRIPE_KEY":   "CRITICAL",
    "DB_CONN":      "HIGH",
    "JWT":          "HIGH",
    "GCP_KEY":      "HIGH",
    "AZURE_KEY":    "HIGH",
    "GITHUB_KEY":   "HIGH",
    "SENDGRID":     "HIGH",
    "PASSWORD":     "HIGH",
    "TWILIO_KEY":   "HIGH",
    "GITLAB_PAT":   "HIGH",
    "DOCKER_PAT":   "HIGH",
    "NPM_TOKEN":    "HIGH",
    "API_KEY":      "MEDIUM",
    "TOKEN":        "MEDIUM",
    "SECRET":       "MEDIUM",
    "SLACK_KEY":    "MEDIUM",
    "WEBHOOK":      "MEDIUM",
    "MAILGUN":      "MEDIUM",
    "HEROKU_KEY":   "MEDIUM",
    "SSH_CRED":     "MEDIUM",
    "ENV_VAR":      "MEDIUM",
    "HASH_MD5":     "LOW",
    "HASH_SHA1":    "LOW",
    "HASH_SHA256":  "LOW",
    "HASH_SHA512":  "LOW",
    "INTERNAL":     "LOW",
}


# ══════════════════════════════════════════════════════════════════════════════
#  PADRÕES DE PII v2.0 — Organização geográfica
#  Áreas cobertas: US · UE · Oriente Médio (ME) · Ásia-Pacífico (AS)
# ══════════════════════════════════════════════════════════════════════════════
#
#  Estrutura por categoria:
#  ┌─────────────────┬──────────────────────────────────────────────────────┐
#  │ Categoria       │ Variações geográficas                                │
#  ├─────────────────┼──────────────────────────────────────────────────────┤
#  │ EMAIL           │ global (regra única)                                 │
#  │ PHONE           │ PHONE_US · PHONE_EU · PHONE_ME · PHONE_AS           │
#  │ IBAN            │ global (cobre UE + ME + parte da AS)                 │
#  │ TAX_ID          │ TAX_ID_US · TAX_ID_EU · TAX_ID_ME · TAX_ID_AS       │
#  │ NIN / NID       │ NIN_EU · NID_ME · NID_AS                            │
#  │ CREDIT_CARD     │ global (validado por Luhn via luhn_check())          │
#  │ SSN_US          │ SSN dos EUA                            │
#  │ DOB             │ global                                               │
#  │ PASSPORT        │ global                                               │
#  │ PUBLIC_IP       │ global                                               │
#  └─────────────────┴──────────────────────────────────────────────────────┘

PII_RULES: List[PiiRule] = [

    # ══════════════════════════════════════════════════════════════════════════
    #  EMAIL — global
    # ══════════════════════════════════════════════════════════════════════════
    ("EMAIL",
     re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
     "Endereço de e-mail (global)", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  PHONE — Estados Unidos e Canadá
    #  Formatos: (NXX) NXX-XXXX · NXX-NXX-XXXX · +1 NXX NXX XXXX
    # ══════════════════════════════════════════════════════════════════════════
    ("PHONE_US",
     re.compile(r"\b(?:\+1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b"),
     "Número de telefone — EUA/Canadá (+1)", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  PHONE — União Europeia + Reino Unido + CH + NO
    #  Códigos de país: +30 GR · +31 NL · +32 BE · +33 FR · +34 ES · +39 IT
    #                 +40 RO · +41 CH · +43 AT · +44 UK · +45 DK · +46 SE
    #                 +47 NO · +48 PL · +49 DE · +351 PT · +353 IE · +358 FI
    #                 +370 LT · +371 LV · +372 EE · +420 CZ · +421 SK
    # ══════════════════════════════════════════════════════════════════════════
    ("PHONE_EU",
     re.compile(
         r"\+(?:3[0-49]|4[1-9]|35[138]|37[012]|42[01])"
         r"[\s\-.]?[\d][\d\s\-\.]{6,13}\b",
         re.I),
     "Número de telefone — UE/Reino Unido/CH/NO", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  PHONE — Oriente Médio
    #  Códigos de país: +20 EG · +90 TR · +92 PK* · +93 AF · +98 IR
    #                 +961 LB · +962 JO · +963 SY · +964 IQ · +965 KW
    #                 +966 SA · +967 YE · +968 OM · +970 PS · +971 AE
    #                 +972 IL · +973 BH · +974 QA · +975* · +976* · +977 NP*
    #  (* prefixo compartilhado — padrões limitados por quantidade de dígitos)
    # ══════════════════════════════════════════════════════════════════════════
    ("PHONE_ME",
     re.compile(
         r"\+(?:20|90|93|98|96[1-8]|97[012])"
         r"[\s\-.]?[\d][\d\s\-\.]{6,12}\b",
         re.I),
     "Número de telefone — Oriente Médio", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  PHONE — Ásia-Pacífico
    #  Códigos de país: +60 MY · +61 AU · +62 ID · +63 PH · +64 NZ · +65 SG
    #                 +66 TH · +81 JP · +82 KR · +84 VN · +86 CN · +852 HK
    #                 +853 MO · +855 KH · +856 LA · +880 BD · +886 TW
    #                 +91 IN · +92 PK · +94 LK · +95 MM
    # ══════════════════════════════════════════════════════════════════════════
    ("PHONE_AS",
     re.compile(
         r"\+(?:6[0-6]|8[124689]|85[2-6]|88[06])"
         r"[\s\-.]?[\d][\d\s\-\.]{6,13}\b",
         re.I),
     "Número de telefone — Ásia-Pacífico", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  IBAN — global
    #  Cobre UE, Reino Unido, Oriente Médio (AE, SA, QA, KW, BH) e outros.
    # ══════════════════════════════════════════════════════════════════════════
    ("IBAN",
     re.compile(r"\b[A-Z]{2}\d{2}[\s]?(?:[A-Z0-9]{4}[\s]?){3,7}[A-Z0-9]{1,4}\b"),
     "IBAN (global)", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  TAX ID — Estados Unidos
    #  Padrões: SSN (NNN-NN-NNNN), EIN (NN-NNNNNNN)
    # ══════════════════════════════════════════════════════════════════════════
    ("TAX_ID_US",
     re.compile(r"\b(?!000|666|9\d{2})\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b"),
     "Tax ID — SSN dos EUA", False),

    ("TAX_ID_US",
     re.compile(r"\b\d{2}\-\d{7}\b"),
     "Tax ID — EIN dos EUA (Employer Identification Number)", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  TAX ID — União Europeia
    #  Número de VAT genérico da UE: código de país de 2 letras + 8–12 caracteres alfanuméricos.
    #  Cobre: DE · FR · GB · IT · ES · NL · PL · PT · SE · BE · AT · DK · FI
    # ══════════════════════════════════════════════════════════════════════════
    ("TAX_ID_EU",
     re.compile(
         r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|GB|HR|HU|IE|IT"
         r"|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)"
         r"[0-9A-Z]{8,12}\b",
         re.I),
     "Tax ID — VAT da UE", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  TAX ID — Oriente Médio
    #  Padrões: números nacionais de registro fiscal/comercial de 10–15 dígitos
    #  usados em SA (VAT: 15 dígitos), AE (TRN: 15 dígitos), EG (9 dígitos), TR (10 dígitos)
    # ══════════════════════════════════════════════════════════════════════════
    ("TAX_ID_ME",
     re.compile(
         r"(?:"
         r"(?:tax[_\s\-]?(?:id|number|no)|vat[_\s\-]?(?:id|number|no)|trn|crn)"
         r"\s*[=:\"']?\s*"
         r")"
         r"([0-9]{9,15})\b",
         re.I),
      "Tax ID — Oriente Médio (SA/AE/EG/TR/IR)", True),

    # ════════════════════════════════════════════════════════════════════════════
    #  BRASIL — CPF (Cadastro de Pessoas Físicas)
    #  Formato: XXX.XXX.XXX-XX · bare 11 dígitos (ancorado por palavra-chave)
    #  Validação pós-match OBRIGATÓRIA: cpf_is_valid() — Módulo 11 (Receita
    #  Federal). Regex puro casa datas/protocolos/IDs de 11 dígitos.
    #  Posicionado ANTES das regras AS: números de 11 dígitos com keyword
    #  "cpf" devem ser reivindicados por CPF_BR, não por TAX_ID_AS (dedup).
    # ════════════════════════════════════════════════════════════════════════════
    ("CPF_BR",
     re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
     "CPF — Brasil (XXX.XXX.XXX-XX, validação Módulo 11)", False),

    ("CPF_BR",
     re.compile(r"\bcpf\b(?:\s+n[ºo°]\.?)?\s*[=:\"'-]?\s*(\d{11})\b", re.I),
     "CPF — Brasil (11 dígitos, ancorado por palavra-chave)", True),

    # ════════════════════════════════════════════════════════════════════════════
    #  BRASIL — CNPJ (Cadastro Nacional da Pessoa Jurídica)
    #  Formato: XX.XXX.XXX/XXXX-XX · bare 14 dígitos (ancorado por palavra-chave)
    #  Validação pós-match OBRIGATÓRIA: cnpj_is_valid() — Módulo 11.
    # ════════════════════════════════════════════════════════════════════════════
    ("CNPJ_BR",
     re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b"),
     "CNPJ — Brasil (XX.XXX.XXX/XXXX-XX, validação Módulo 11)", False),

    ("CNPJ_BR",
     re.compile(r"\bcnpj\b(?:\s+n[ºo°]\.?)?\s*[=:\"'-]?\s*(\d{14})\b", re.I),
     "CNPJ — Brasil (14 dígitos, ancorado por palavra-chave)", True),

    # ════════════════════════════════════════════════════════════════════════════
    #  BRASIL — CEP (Código de Endereçamento Postal)
    #  Formato: XXXXX-XXX · bare 8 dígitos (ancorado por palavra-chave)
    #  CEP não tem dígito verificador — o formato É a validação (sem validador).
    # ════════════════════════════════════════════════════════════════════════════
    ("CEP_BR",
     re.compile(r"\b\d{5}-\d{3}\b"),
     "CEP — Brasil (XXXXX-XXX)", False),

    ("CEP_BR",
     re.compile(r"\bcep\b(?:\s+n[ºo°]\.?)?\s*[=:\"'-]?\s*(\d{8})\b", re.I),
     "CEP — Brasil (8 dígitos, ancorado por palavra-chave)", True),

    # ════════════════════════════════════════════════════════════════════════════
    #  BRASIL — Telefone (+55)
    #  Móvel: (11) 9XXXX-XXXX · +55 11 9XXXX-XXXX · 11 9XXXX-XXXX · bare 11 dígitos
    #  Fixo:   (11) 2XXX-XXXX a (11) 5XXX-XXXX (com parênteses — forma canônica)
    #  Validação pós-match: phone_br_is_valid() — DDD 11–99 + 8/9 dígitos.
    # ════════════════════════════════════════════════════════════════════════════
    ("PHONE_BR",
     re.compile(r"\b(?:\+55[\s\-.]?)?\(?\d{2}\)?[\s\-.]?9\d{4}[\s\-.]?\d{4}\b"),
     "Telefone móvel — Brasil (+55)", False),

    ("PHONE_BR",
     re.compile(r"\b(?:\+55[\s\-.]?)?\(\d{2}\)[\s\-.]?[2-5]\d{3}[\s\-.]?\d{4}\b"),
     "Telefone fixo — Brasil (+55)", False),

    # ════════════════════════════════════════════════════════════════════════════
    #  BRASIL — Chave Pix (ancorada por palavra-chave; sem validador — a chave
    #  pode ser e-mail, telefone (+55...), CPF, CNPJ ou aleatória (UUID-like))
    # ════════════════════════════════════════════════════════════════════════════
    ("PIX_BR",
     re.compile(r"\bchave[\s_\-]?pix\b\s*[=:\"'-]?\s*([A-Za-z0-9@._+\-]{4,64})", re.I),
     "Chave Pix — Brasil (e-mail, telefone, CPF, CNPJ ou aleatória)", True),

    # ══════════════════════════════════════════════════════════════════════════
    #  TAX ID — Ásia-Pacífico
    #  Padrões: CN (USC de 18 chars), IN (PAN: 10 alfanuméricos), JP (12 dígitos),
    #            KR (10 dígitos), SG (UEN: 9-10 chars), AU (ABN: 11 dígitos)
    # ══════════════════════════════════════════════════════════════════════════
    ("TAX_ID_AS",
     re.compile(
         r"\b(?:"
         r"[A-Z]{5}\d{4}[A-Z]"                        # IN PAN card
         r"|\d{18}"                                    # CN Unified Social Credit Code
         r"|\d{12}"                                    # JP My Number / KR TRN
         r"|[0-9A-Z]{9,10}"                            # SG UEN
         r"|\d{11}"                                    # AU ABN
         r")\b",
         re.I),
     "Tax ID — Ásia-Pacífico (IN/CN/JP/KR/SG/AU)", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  NÚMERO DE IDENTIDADE NACIONAL — União Europeia
    #  Detecção genérica ancorada por palavra-chave NIN; evita hardcode específico por país.
    #  Cobre: NL BSN (9 dígitos), SE personnummer (10/12 dígitos + separador),
    #          DE SVNR (12 dígitos), FR NIR (15 dígitos), PL PESEL (11 dígitos)
    # ══════════════════════════════════════════════════════════════════════════
    ("NIN_EU",
     re.compile(
         r"(?:national[_\s]?id(?:entity)?[_\s]?(?:number|no|code)?|"
         r"social[_\s]?security[_\s]?(?:number|no)|"
         r"bsn|pesel|personnummer|svnr|nir|codice[_\s]?fiscale)"
         r"\s*[=:\"']?\s*"
         r"([A-Z0-9\-]{6,20})\b",
         re.I),
     "Número de identidade nacional — UE", True),

    # ══════════════════════════════════════════════════════════════════════════
    #  NÚMERO DE IDENTIDADE NACIONAL — Oriente Médio
    #  SA National ID (10 dígitos começando com 1 ou 2),
    #  AE Emirates ID (784-YYYY-NNNNNNN-C), EG National ID (14 dígitos),
    #  TR TC Kimlik (11 dígitos), IR National Code (10 dígitos),
    #  IL Teudat Zehut (9 dígitos)
    # ══════════════════════════════════════════════════════════════════════════
    ("NID_ME",
     re.compile(
         r"(?:national[_\s]?id(?:entity)?[_\s]?(?:number|no|card)?|"
         r"emirates[_\s]?id|kimlik|iqama|civil[_\s]?id|"
         r"nid|nin)"
         r"\s*[=:\"']?\s*"
         r"([0-9\-]{9,18})\b",
         re.I),
     "Número de identidade nacional — Oriente Médio", True),

    ("NID_ME",
     re.compile(r"\b784[\-]?\d{4}[\-]?\d{7}[\-]?\d\b"),
     "Emirates ID — AE (784-YYYY-NNNNNNN-C)", False),

    ("NID_ME",
     re.compile(r"\b[12]\d{9}\b"),
     "National ID — SA (10 dígitos, começa com 1 ou 2)", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  NÚMERO DE IDENTIDADE NACIONAL — Ásia-Pacífico
    #  IN Aadhaar (12 dígitos), CN Resident ID (18 chars), KR RRN (13 dígitos),
    #  SG NRIC (S/T/F/G + 7 dígitos + 1 char), HK HKID (7–8 dígitos + char verificador),
    #  JP My Number (12 dígitos, ancorado por palavra-chave), AU TFN (8–9 dígitos)
    # ══════════════════════════════════════════════════════════════════════════
    ("NID_AS",
     re.compile(
         r"(?:aadhaar|aadhar|uid|my[_\s]?number|resident[_\s]?(?:registration[_\s]?)?number|"
         r"nric|hkid|tfn|tax[_\s]?file[_\s]?number)"
         r"\s*[=:\"']?\s*"
         r"([A-Z0-9\-]{8,18})\b",
         re.I),
     "Número de identidade nacional — Ásia-Pacífico", True),

    ("NID_AS",
     re.compile(r"\b[STFG]\d{7}[A-Z]\b"),
     "NRIC — Singapura", False),

    ("NID_AS",
     re.compile(r"\b\d{6}[\-]?\d{7}\b"),
     "Resident Registration Number — Coreia do Sul (YYMMDD-NNNNNNN)", False),

    ("NID_AS",
     re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"),
     "Número Aadhaar — Índia (XXXX XXXX XXXX)", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  CREDIT CARD — global
    #  Visa · Mastercard · Amex · Discover
    #  Validação pós-match: use luhn_check() para filtrar falsos positivos.
    # ══════════════════════════════════════════════════════════════════════════
    ("CREDIT_CARD",
     re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
     "Número de cartão de crédito (global)", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  SSN — Estados Unidos (standalone, sem ancoragem por palavra-chave do TAX_ID_US)
    # ══════════════════════════════════════════════════════════════════════════
    ("SSN_US",
     re.compile(r"\b(?!000|666|9\d{2})\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b"),
     "SSN — Social Security Number dos EUA", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  DATA DE NASCIMENTO — global (ancorado por palavra-chave)
    # ══════════════════════════════════════════════════════════════════════════
    ("DOB",
     re.compile(
         r"\b(?:birth[_\s]?date|date[_\s]?of[_\s]?birth|dob|born[_\s]?on|"
         r"fecha[_\s]?nac|data[_\s]?nasc|geburts(?:datum|tag)|"
         r"تاريخ[_\s]?الميلاد|出生[日期年月]|생년월일)"
         r"\s*[=:\"']?\s*"
         r"(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})",
         re.I),
     "Data de nascimento (global)", True),

    # ══════════════════════════════════════════════════════════════════════════
    #  PASSPORT — global (formato genérico de leitura por máquina)
    # ══════════════════════════════════════════════════════════════════════════
    ("PASSPORT",
     re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
     "Possível número de passaporte (global)", False),

    # ══════════════════════════════════════════════════════════════════════════
    #  IP PÚBLICO — global
    # ══════════════════════════════════════════════════════════════════════════
    ("PUBLIC_IP",
     re.compile(
         r"\b(?!10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?!127\.)(?!0\.)"
         r"(?:\d{1,3}\.){3}\d{1,3}\b"),
     "Endereço IP público (global)", False),
]


# ══════════════════════════════════════════════════════════════════════════════
#  AUXILIARES
# ══════════════════════════════════════════════════════════════════════════════

def luhn_check(number: str) -> bool:
    """Valida um número de cartão de crédito usando o algoritmo de Luhn.

    Retorna True se o número passa na verificação de Luhn; False caso contrário.
    Caracteres não numéricos (espaços, hífens) são removidos antes da validação.
    """
    import re as _re
    digits = [int(d) for d in _re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ══════════════════════════════════════════════════════════════════════════════
#  VALIDADORES DE PII BRASILEIRA — Fase 2 (regionalização BR)
#  Pós-match: filtram falsos positivos que o regex puro não consegue eliminar
#  (datas, protocolos, IDs internos com a mesma contagem de dígitos).
# ══════════════════════════════════════════════════════════════════════════════

def cpf_is_valid(value: str) -> bool:
    """Valida CPF pelo algoritmo oficial (Módulo 11, Receita Federal).

    Formatação (pontos/hífen) é ignorada — só os 11 dígitos importam.
    Rejeita sequências com todos os dígitos iguais (111.111.111-11 etc.),
    que satisfazem o Módulo 11 matematicamente mas não existem como CPF.

    Algoritmo: 2 dígitos verificadores calculados sobre os 9 anteriores
    com pesos decrescentes (10..2 e 11..2); resto < 2 → DV = 0.
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for n in (9, 10):
        s = sum(int(digits[i]) * (n + 1 - i) for i in range(n))
        r = s % 11
        if (0 if r < 2 else 11 - r) != int(digits[n]):
            return False
    return True


def cnpj_is_valid(value: str) -> bool:
    """Valida CNPJ pelo algoritmo oficial (Módulo 11, Receita Federal).

    Formatação é ignorada — só os 14 dígitos importam. Pesos oficiais:
    5,4,3,2,9,8,7,6,5,4,3,2 (DV1) e 6,5,4,3,2,9,8,7,6,5,4,3,2 (DV2);
    resto < 2 → DV = 0.
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 14 or len(set(digits)) == 1:
        return False
    for n, weights in ((12, (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)),
                       (13, (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2))):
        s = sum(int(digits[i]) * weights[i] for i in range(n))
        r = s % 11
        if (0 if r < 2 else 11 - r) != int(digits[n]):
            return False
    return True


def phone_br_is_valid(value: str) -> bool:
    """Valida telefone brasileiro: DDD 11–99 + 8 dígitos (fixo) ou 9 (móvel).

    Remove o prefixo +55 somente quando o total de dígitos indica país
    (12/13) — preserva DDDs reais que começam com 55 (Rio Grande do Sul).
    Números móveis de 11 dígitos exigem o nono dígito '9'.
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) in (12, 13) and digits.startswith("55"):
        digits = digits[2:]
    if len(digits) not in (10, 11):
        return False
    if not (11 <= int(digits[:2]) <= 99):
        return False
    if len(digits) == 11 and digits[2] != "9":
        return False
    return True


# Mapa categoria BR → validador pós-match (consumido pelo PiiDetectorAgent,
# mesmo padrão do CREDIT_CARD → luhn_check). CEP_BR não tem entrada — o
# formato é a validação; PIX_BR não tem entrada — chave é multi-tipo.
PII_VALIDATORS: dict = {
    "CPF_BR":     cpf_is_valid,
    "CNPJ_BR":    cnpj_is_valid,
    "PHONE_BR":   phone_br_is_valid,
}
