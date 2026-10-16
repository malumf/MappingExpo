#!/usr/bin/env python3
"""
MappingExpo v5.0 | Ferramenta de Dorking (OSINT)
Author: xPloits3c I.C.W.T| https://github.com/xPloits3c/DorkEye
"""

import os
import sys
import time
import json
import yaml
import random
import argparse
import hashlib
import csv
import re
import signal
import queue
import threading
import pickle
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urlparse, unquote, parse_qs, urlencode, quote
from collections import defaultdict

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ── Injeção do path do sub-pacote Tools ─────────────────────────────────────────
_TOOLS_DIR = Path(__file__).parent / "Tools"
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))
# ─────────────────────────────────────────────────────────────────────────────

from dork_generator import DorkGenerator

# ── Engine SQLi ───────────────────────────────────────────────────────────────
from sqli import (
    SQLiDetector,
    SQLiConfidence,
    HTTPFingerprint,
    HTTPFingerprintRotator,
    USER_AGENTS,
)
# ─────────────────────────────────────────────────────────────────────────────

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Agents ────────────────────────────────────────────────────────────────────
try:
    from mappingexpo_agents import (
        run_analysis_pipeline as _run_agents_pipeline,
        add_crawler_args,
        run_crawl,
        TriageAgent,
        PageFetchAgent,
        SecretsAgent,
        ReportAgent,
        DorkCrawlerAgent,
    )
    _ANALYZE_AVAILABLE = True
except ImportError:
    _ANALYZE_AVAILABLE = False
    def _run_agents_pipeline(*a, **kw):
        """Stub de fallback."""
        return {"triaged": None, "all_secrets": [], "report_path": None}
    def add_crawler_args(parser):
        """Stub de fallback."""
        return parser
    def run_crawl(*a, **kw):
        """Stub de fallback."""
        return {"results": [], "rounds": 0, "stop_reason": "unavailable"}

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape as _rich_escape
from ddgs import DDGS
import socket
import getpass

console = Console()

# ── Scanner de Portas DB ───────────────────────────────────────────────────────────
# Importado DEPOIS do console para poder imprimir avisos de dentro do stub.
# except Exception (não apenas ImportError) captura também SyntaxError /
# AttributeError que ocorreriam se db_portscan.py estivesse corrompido.
try:
    from db_portscan import DBPortScanAgent, save_dbscan_report
    _DBSCAN_AVAILABLE = True
except Exception:
    _DBSCAN_AVAILABLE = False
    class DBPortScanAgent:              # type: ignore[no-redef]
        """Stub: db_portscan.py ausente ou não importável."""
        def __init__(self, **kw): pass
        def run(self, *a, **kw): return None
    def save_dbscan_report(*a, **kw):   # type: ignore[no-redef]
        return ""
# ─────────────────────────────────────────────────────────────────────────────

VALID_MODES = ["soft", "medium", "aggressive"]

# ══════════════════════════════════════════════════════════════
#  [7] Auto-detecção Termux / Android
# ══════════════════════════════════════════════════════════════

def _detect_termux_android() -> bool:
    """Retorna True quando executando dentro do Termux no Android."""
    return (
        "TERMUX_VERSION" in os.environ
        or os.environ.get("PREFIX", "").startswith("/data/data/com.termux")
        or os.path.isdir("/data/data/com.termux")
    )

TERMUX_IS_ANDROID: bool = _detect_termux_android()

# ══════════════════════════════════════════════════════════════
#  Estado de interrupção Ctrl+C
# ══════════════════════════════════════════════════════════════

_last_interrupt_time: float = 0.0
_skip_current: bool         = False
_exit_requested: bool       = False


def _sigint_handler(signum, frame):
    """Trata SIGINT (Ctrl+C). Pressão única pula; pressão dupla em até 1,5 s encerra."""
    global _last_interrupt_time, _skip_current, _exit_requested
    now = time.monotonic()
    if now - _last_interrupt_time < 1.5:
        _exit_requested = True
        sys.stderr.write("\n[!!] Ctrl+C duplo detectado — encerrando...\n")
        sys.stderr.flush()
    else:
        _skip_current = True
        sys.stderr.write("\n[~] Ctrl+C — pulando tarefa atual...\n")
        sys.stderr.flush()
    _last_interrupt_time = now

    import sqli as _sqli_mod
    _sqli_mod._exit_requested = _exit_requested
    _sqli_mod._skip_current   = _skip_current
    try:
        import xss as _xss_mod
        _xss_mod._exit_requested = _exit_requested
        _xss_mod._skip_current   = _skip_current
    except ImportError:
        pass


signal.signal(signal.SIGINT, _sigint_handler)


def _interruptible_sleep(seconds: float, step: float = 0.25) -> None:
    """Dorme em passos pequenos; retorna imediatamente se skip/exit estiver sinalizado."""
    elapsed = 0.0
    while elapsed < seconds:
        if _exit_requested or _skip_current:
            return
        time.sleep(min(step, seconds - elapsed))
        elapsed += step


def print_banner():
    """Imprime o banner ASCII."""
    TITLE_ROWS = [
        ("bold bright_blue", "╔╦╗╔═╗╦═╗╦╔═  ╔═╗╦ ╦╔═╗"),
        ("bold blue",        " ║║║ ║╠╦╝╠╩╗  ║╣ ╚╦╝║╣"),
        ("bold blue",        "═╩╝╚═╝╩╚═╩ ╩  ╚═╝ ╩ ╚═╝"),
    ]
    for style, row in TITLE_ROWS:
        console.print(f"[{style}]{row}[/{style}]")
    console.print()

    SYRINGE = (
        "\n\n\n\n"
        "[bold yellow] ___[/bold yellow]\n"
        "[bold yellow]__H__[/bold yellow]\n"
        "[bold yellow] [[/bold yellow][bold red]d[/bold red][bold yellow]][/bold yellow]\n"
        "[bold yellow] [[/bold yellow][bold red]e[/bold red][bold yellow]][/bold yellow]\n"
        "[bold yellow] [[/bold yellow][bold red];[/bold red][bold yellow]][/bold yellow]\n"
        "[bold yellow] |_|[/bold yellow]\n"
        "[bold yellow]  V[/bold yellow]"
    )

    android_badge = (
        "\n[bold yellow]▸ Plataforma[/bold yellow] [dim]│[/dim]  "
        "[bold green]Android / Termux | economia de bateria ativa[/bold green]"
        if TERMUX_IS_ANDROID else ""
    )

    INFO = (
        "[bold white]FERRAMENTA DE DORKING ([/bold white][bold red]OSINT[/bold red][bold white])[/bold white]\n"
        "[bold green]v5.0[/bold green]  [dim]estável[/dim]\n"
        "\n"
        "[dim]▸ Autor   │[/dim]  [yellow]xPloits3c I.C.W.T[/yellow]\n"
        "[dim]▸ GitHub  │[/dim]  [cyan]github.com/xPloits3c/DorkEye[/cyan]\n"
        "[dim]▸ Telegram│[/dim]  [cyan]t.me/DorkEye[/cyan]\n"
        "\n"
        "[dim]▸ XSS     │[/dim]  [green]111[/green][red] payloads[/red]\n"
        "[dim]▸ SQLi    │[/dim]  [green]105[/green][red] payloads[/red]\n"
        "[dim]▸ Engine  │[/dim]  [green]DuckDuckGo[/green]\n"
        "[dim]▸ Crawler │[/dim]  [red]Intel[/red]\n"
        "[dim]▸ Stealth │[/dim]  [green]Mais lento, mais seguro[/green]\n"
        "[dim]▸ DorkGen │[/dim]  [green]Máx:[/green][red] 10.000[/red]\n"
        "[dim]▸ Analyzer│[/dim]  [green]Extrai metadados[/green]"
        + android_badge
    )

    grid = Table.grid(padding=(0, 1))
    grid.add_column(min_width=8)
    grid.add_column()
    grid.add_row(SYRINGE, INFO)
    console.print(grid)
    console.print()

    console.print(Panel(
        "[bold red]⚠  Aviso legal[/bold red]\n"
        "[dim]Atacar alvos sem consentimento mútuo prévio é ilegal.[/dim]\n"
        "[dim]É responsabilidade do usuário final obedecer a todas as leis locais, estaduais e federais aplicáveis.[/dim]",
        border_style="red",
        padding=(0, 2),
    ))
    console.print()


WELCOME_MESSAGES = [
    "Fique seguro, {name}.",
    "Sessão inicializada, {name}.",
    "Conectado. Bem-vindo de volta, {name}.",
    "Terminal pronto, {name}.",
    "Modo OSINT ativo, {name}.",
    "Pronto para começar, {name}?",
    "Vamos ao trabalho.",
    "Saudações, {name}. Podemos começar?",
    "A curiosidade deixa rastros.",
    "VPN não é anonimato.",
    "Eles registram mais do que você imagina.",
    "Silêncio. Só dados, {name}.",
    "De volta online, {name}.",
    "Ambiente carregado, {name}.",
    "Use ambientes isolados.",
    "Alvos na fila, {name}.",
    "Filtre o ruído, {name}.",
    "Registre suas ações para auditoria.",
    "Sua atividade é visível.",
    "Sem conversa fiada. Só resultados, {name}.",
    "Não quebramos nada. Observamos, {name}.",
    "A informação quer ser encontrada, {name}.",
    "Confie em nada. Verifique tudo, {name}.",
    "Opere de forma discreta e responsável, {name}.",
    "Vamos ver o que foi exposto por descuido, {name}.",
]

WELCOME_COLORS = [
    "green", "bright_green", "yellow", "bright_yellow",
    "magenta", "bright_magenta", "blue", "bright_blue",
    "red", "bright_red", "white",
]


def get_user_name() -> str:
    """Retorna o nome de usuário do SO atual; fallback para hostname, depois 'amigo'."""
    try:
        return getpass.getuser()
    except Exception:
        try:
            return socket.gethostname()
        except Exception:
            return "amigo"


def greet_user():
    """Imprime uma mensagem de boas-vindas aleatória com uma cor aleatória."""
    name    = _rich_escape(get_user_name())
    message = random.choice(WELCOME_MESSAGES).format(name=name)
    color   = random.choice(WELCOME_COLORS)
    console.print(f"[bold {color}]{message}[/bold {color}]\n")


DEFAULT_CONFIG = {
    "extensions": {
        "documents":   [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods"],
        "archives":    [".zip", ".rar", ".tar", ".gz", ".7z", ".bz2"],
        "databases":   [".sql", ".db", ".sqlite", ".mdb"],
        "backups":     [".bak", ".backup", ".old", ".tmp"],
        "configs":     [".conf", ".config", ".ini", ".yaml", ".yml", ".json", ".xml"],
        "scripts":     [".php", ".asp", ".aspx", ".jsp", ".sh", ".bat", ".ps1"],
        "credentials": [".env", ".git", ".svn", ".htpasswd"]
    },
    "blacklist":            [],
    "whitelist":            [],
    "analyze_files":        True,
    "max_file_size_check":  52428800,
    "sqli_detection":       False,
    "xss_detection":        False,
    "xss_type":             "all",
    "stealth_mode":         False,
    "user_agent_rotation":  True,
    "http_fingerprinting":  True,
    "request_timeout":      10,
    "max_retries":          3,
    "extended_delay_every_n_results": 100,
}


class UserAgentRotator:
    """Rotaciona strings de User-Agent entre perfis Chrome, Firefox, Safari e Edge."""
    def __init__(self):
        self.agents        = [a for lst in USER_AGENTS.values() for a in lst]
        self.current_index = 0

    def get_random(self) -> str:
        return random.choice(self.agents)

    def get_next(self) -> str:
        agent              = self.agents[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.agents)
        return agent


# ══════════════════════════════════════════════════════════════
#  SessionCheckpoint  ← NOVO (ponto 3)
# ══════════════════════════════════════════════════════════════

class SessionCheckpoint:
    """
    Salva e restaura o estado de uma sessão de busca em disco.

    O arquivo de checkpoint é gravado na pasta Dump/.checkpoints/
    e removido automaticamente quando a sessão é concluída.
    Se ocorrer um erro de E/S durante o salvamento, um aviso é impresso
    mas a sessão continua sem interrupção.
    """

    CHECKPOINT_DIR = Path(__file__).parent / "Dump" / ".checkpoints"

    def __init__(self, session_id: str):
        """Cria o diretório de checkpoint e define o path do arquivo."""
        try:
            self.CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            console.print(f"[yellow][~] Não foi possível criar o diretório de checkpoint: {e}[/yellow]")
        self.path       = self.CHECKPOINT_DIR / f"{session_id}.pkl"
        self.session_id = session_id

    def save(
        self,
        completed_dorks: List[str],
        results:         List[Dict],
        stats:           dict,
    ) -> None:
        """Serializa (pickle) o estado atual da sessão em disco."""
        try:
            with open(self.path, "wb") as f:
                pickle.dump(
                    {
                        "completed_dorks": completed_dorks,
                        "results":         results,
                        "stats":           dict(stats),
                        "saved_at":        datetime.now().isoformat(),
                    },
                    f,
                    protocol=pickle.HIGHEST_PROTOCOL,
                )
        except Exception as e:
            # Não fatal: a sessão continua mesmo sem checkpoint
            console.print(f"[yellow][~] Falha ao salvar checkpoint: {e}[/yellow]")

    def load(self) -> Optional[dict]:
        """
        Carrega o checkpoint do disco.

        Retorna None se o arquivo não existir ou estiver corrompido.
        """
        if not self.path.exists():
            return None
        try:
            with open(self.path, "rb") as f:
                return pickle.load(f)
        except Exception as e:
            console.print(f"[yellow][~] Checkpoint corrompido, ignorado: {e}[/yellow]")
            return None

    def delete(self) -> None:
        """Remove o arquivo de checkpoint ao concluir a sessão."""
        try:
            self.path.unlink(missing_ok=True)
        except Exception:
            pass  # Não crítico


# ══════════════════════════════════════════════════════════════
#  FileAnalyzer
# ══════════════════════════════════════════════════════════════

class FileAnalyzer:
    """
    Faz análise de arquivos via requests HEAD e verificação opcional de SQLi/XSS em URLs descobertas.
    """
    def __init__(self, config: Dict, ua_rotator: UserAgentRotator, fp_rotator: HTTPFingerprintRotator):
        self.config        = config
        self.ua_rotator    = ua_rotator
        self.fp_rotator    = fp_rotator
        self.extension_map = self._flatten_extensions()
        self.sqli_detector = SQLiDetector(
            stealth = config.get("stealth_mode", False),
            timeout = config.get("request_timeout", 10)
        )
        self.xss_detector = None
        if config.get("xss_detection", False):
            try:
                from xss import XSSDetector
                self.xss_detector = XSSDetector(
                    stealth  = config.get("stealth_mode", False),
                    timeout  = config.get("request_timeout", 10),
                    xss_type = config.get("xss_type", "all"),
                )
            except ImportError:
                pass
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry   = Retry(
            total            = self.config.get("max_retries", 3),
            backoff_factor   = 1,
            status_forcelist = [429, 500, 502, 503, 504],
            allowed_methods  = ["GET", "HEAD"]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://",  adapter)
        session.mount("https://", adapter)
        return session

    def _flatten_extensions(self) -> Dict[str, str]:
        ext_map = {}
        for category, extensions in self.config["extensions"].items():
            for ext in extensions:
                ext_map[ext.lower()] = category
        return ext_map

    def get_file_extension(self, url: str) -> str:
        try:
            path = unquote(urlparse(url).path)
            ext  = os.path.splitext(path)[1].lower()
            return ext if ext else ""
        except Exception:
            return ""

    def categorize_url(self, url: str) -> str:
        ext = self.get_file_extension(url)
        if not ext:
            return "webpage"
        return self.extension_map.get(ext, "other")

    def is_blacklisted(self, url: str) -> bool:
        if not self.config["blacklist"]:
            return False
        return self.get_file_extension(url) in self.config["blacklist"]

    def is_whitelisted(self, url: str) -> bool:
        if not self.config["whitelist"]:
            return True
        return self.get_file_extension(url) in self.config["whitelist"]

    def analyze_file(self, url: str) -> Dict:
        result = {
            "url":          url,
            "extension":    self.get_file_extension(url),
            "category":     self.categorize_url(url),
            "size":         None,
            "content_type": None,
            "accessible":   False,
            "status_code":  None,
        }
        try:
            if self.config.get("http_fingerprinting", True):
                self.fp_rotator.get_random()
                headers = self.fp_rotator.build_headers()
            elif self.config.get("user_agent_rotation", True):
                headers = {"User-Agent": self.ua_rotator.get_random()}
            else:
                headers = {"User-Agent": self.ua_rotator.agents[0]}

            response              = self.session.head(
                url,
                timeout         = (4, self.config.get("request_timeout", 10)),
                allow_redirects = True,
                headers         = headers,
                verify          = False,
            )
            result["status_code"] = response.status_code
            result["accessible"]  = response.status_code == 200

            if "content-length" in response.headers:
                try:
                    result["size"] = int(response.headers["content-length"])
                except Exception:
                    pass
            if "content-type" in response.headers:
                result["content_type"] = response.headers["content-type"]

        except Exception as e:
            result["error"] = str(e)
        return result

    def check_sqli(self, url: str) -> Dict:
        if not self.config.get("sqli_detection", False):
            return {"tested": False}
        return self.sqli_detector.test_sqli(url)

    def check_xss(self, url: str) -> Dict:
        if not self.config.get("xss_detection", False) or self.xss_detector is None:
            return {"tested": False}
        return self.xss_detector.test_xss(url)


# ══════════════════════════════════════════════════════════════
#  MappingExpo
# ══════════════════════════════════════════════════════════════

class MappingExpo:
    """Orquestrador principal: buscas de dorks, análise de arquivos, testes SQLi/XSS, persistência de resultados."""

    def __init__(self, config: Dict, output_file: str = None):
        self.config      = config
        self.output_file = output_file
        self.ua_rotator  = UserAgentRotator()
        self.fp_rotator  = HTTPFingerprintRotator()
        self.analyzer    = FileAnalyzer(config, self.ua_rotator, self.fp_rotator)
        self.results:    List[Dict] = []
        self.stats       = defaultdict(int)
        self.url_hashes: Set[str]  = set()
        self.start_time  = time.time()
        self._total_results_at_last_extended_delay: int = 0
        # ── Dedup terminal SQLi / XSS ──────────────────────────────────────
        # Evita reimprimir a mesma vulnerabilidade se a mesma URL
        # reaparecer em um dork posterior ou em modo -f / resume.
        self._reported_sqli_urls: Set[str] = set()
        self._reported_xss_urls:  Set[str] = set()

    def _hash_url(self, url: str) -> str:
        return hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()

    def is_duplicate(self, url: str) -> bool:
        h = self._hash_url(url)
        if h in self.url_hashes:
            return True
        self.url_hashes.add(h)
        return False

    def process_dorks(self, dork_input: str) -> List[str]:
        if os.path.isfile(dork_input):
            try:
                with open(dork_input, 'r', encoding='utf-8') as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except Exception as e:
                console.print(f"[red][!] Could not read dork file '{dork_input}': {e}[/red]")
                return []
        return [dork_input]

    def _compute_base_delay(self, results_found: int, stealth: bool) -> float:
        if results_found < 10:
            low, high = 8, 14
        else:
            low, high = 18, 28
        delay = random.uniform(low, high)
        if stealth:
            delay *= random.uniform(1.4, 1.8)
        return round(delay, 2)

    def _should_trigger_extended_delay(self) -> bool:
        threshold = self.config.get("extended_delay_every_n_results", 100)
        collected_since_last = len(self.results) - self._total_results_at_last_extended_delay
        return collected_since_last >= threshold

    def search_dork(self, dork: str, count: int,
                    dork_index: int = 1, total_dorks: int = 1) -> List[Dict]:
        """Busca no DuckDuckGo por um dork via thread produtora daemon."""
        global _skip_current, _exit_requested

        _ts = datetime.now().strftime("%H:%M:%S")
        console.print(
            f"\n[bold cyan][ Dork {dork_index}/{total_dorks} ][/bold cyan]"
            f"  [dim]{_ts}[/dim]"
            f"  [dim]Ctrl+C → pular  │  ×2 → sair[/dim]"
        )
        console.print(f"[bold green][*] Buscando dork:[/bold green] {_rich_escape(dork)}")

        _skip_current = False

        results       = []
        total_fetched = 0
        max_attempts  = 4

        _DONE = object()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Buscando no DuckDuckGo...", total=count)

            for attempt in range(max_attempts):
                if _exit_requested or _skip_current:
                    break
                try:
                    batch_size = min(50, count - total_fetched)
                    if batch_size <= 0:
                        break

                    result_queue: queue.Queue = queue.Queue()
                    stop_event = threading.Event()

                    def _producer(dork=dork, batch_size=batch_size,
                                  q=result_queue, stop=stop_event):
                        try:
                            for item in DDGS().text(dork, max_results=batch_size):
                                if stop.is_set():
                                    break
                                q.put(item)
                        except Exception:
                            pass
                        finally:
                            q.put(_DONE)

                    threading.Thread(target=_producer, daemon=True).start()

                    while True:
                        if _exit_requested or _skip_current:
                            stop_event.set()
                            break
                        try:
                            r = result_queue.get(timeout=0.25)
                        except queue.Empty:
                            continue

                        if r is _DONE:
                            break

                        url = r.get("href") or r.get("url")
                        if not url:
                            continue
                        if self.analyzer.is_blacklisted(url):
                            self.stats["blacklisted"] += 1
                            continue
                        if not self.analyzer.is_whitelisted(url):
                            self.stats["not_whitelisted"] += 1
                            continue
                        if self.is_duplicate(url):
                            self.stats["duplicates"] += 1
                            continue

                        entry = {
                            "url":       url,
                            "title":     r.get("title", ""),
                            "snippet":   r.get("body", ""),
                            "dork":      dork,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "extension": self.analyzer.get_file_extension(url),
                            "category":  self.analyzer.categorize_url(url)
                        }
                        results.append(entry)
                        total_fetched += 1
                        self.stats["total_found"] += 1
                        self.stats[f"category_{entry['category']}"] += 1
                        progress.update(task, completed=min(total_fetched, count))
                        if total_fetched >= count:
                            stop_event.set()
                            break

                    if total_fetched >= count:
                        break

                    if attempt < max_attempts - 1 and total_fetched < count:
                        if _exit_requested or _skip_current:
                            break
                        backoff = (2 ** attempt) + random.uniform(0, 3)
                        console.print(
                            f"[yellow][~] Tentativa {attempt + 1}/{max_attempts - 1} — "
                            f"backoff de {backoff:.1f}s[/yellow]"
                        )
                        _interruptible_sleep(backoff)

                except Exception as e:
                    console.print(f"[yellow][!] Tentativa {attempt + 1} falhou: {str(e)}[/yellow]")
                    if attempt < max_attempts - 1 and not _exit_requested and not _skip_current:
                        backoff = (2 ** attempt) + random.uniform(0, 3)
                        console.print(
                            f"[yellow][~] Aguardando {backoff:.1f}s antes da próxima tentativa...[/yellow]"
                        )
                        _interruptible_sleep(backoff)
                    continue

        if _skip_current:
            console.print(f"[yellow][~] Dork {dork_index}/{total_dorks} pulado.[/yellow]")
            _skip_current = False

        console.print(f"[bold blue][+] Encontrados {len(results)} resultados únicos para este dork[/bold blue]")
        return results

    def analyze_results(self, results: List[Dict]) -> List[Dict]:
        """Roda análise de arquivos e/ou testes SQLi/XSS sobre um lote de dicts de resultado."""
        global _skip_current, _exit_requested

        if not self.config.get("analyze_files", True) and not self.config.get("sqli_detection", False):
            return results
        console.print("\n[bold yellow][*] Analisando resultados...[/bold yellow]")
        files_to_analyze  = [r for r in results if r["category"] != "webpage"]
        urls_to_test_sqli = [r for r in results if self.config.get("sqli_detection", False)]

        with Progress(console=console) as progress:
            if self.config.get("analyze_files", True) and files_to_analyze:
                task1 = progress.add_task("[cyan]Analisando [yellow]arquivos[cyan]...", total=len(files_to_analyze))
                for result in files_to_analyze:
                    if _exit_requested or _skip_current:
                        break
                    analysis = self.analyzer.analyze_file(result["url"])
                    result.update({
                        "file_size":    analysis["size"],
                        "content_type": analysis["content_type"],
                        "accessible":   analysis["accessible"],
                        "status_code":  analysis["status_code"],
                    })
                    progress.advance(task1)
                    _interruptible_sleep(random.uniform(1, 2) if self.config.get("stealth_mode", False) else 0.5)

                if _skip_current and not _exit_requested:
                    console.print("[yellow][~] Ctrl+C — análise de arquivos pulada.[/yellow]")
                    _skip_current = False

            if self.config.get("sqli_detection", False) and urls_to_test_sqli:
                task2 = progress.add_task("[cyan]Testando [red]SQLi[cyan]...", total=len(urls_to_test_sqli))
                for result in urls_to_test_sqli:
                    if _exit_requested:
                        break
                    if _skip_current:
                        console.print("[yellow][~] Ctrl+C — pulando os testes SQLi restantes deste dork.[/yellow]")
                        _skip_current = False
                        break

                    sqli_result         = self.analyzer.check_sqli(result["url"])
                    result["sqli_test"] = sqli_result

                    if sqli_result.get("waf_detected"):
                        console.print(
                            f"[yellow][~] WAF detectado "
                            f"({sqli_result['waf_detected']}): {_rich_escape(result['url'])}[/yellow]"
                        )
                        self.stats["waf_detected"] += 1

                    if sqli_result.get("vulnerable", False):
                        _sqli_url = result["url"]
                        # ── Dedup URL-level ──────────────────────────────────
                        if _sqli_url not in self._reported_sqli_urls:
                            self._reported_sqli_urls.add(_sqli_url)
                            self.stats["sqli_vulnerable"] += 1
                            confidence = sqli_result.get("overall_confidence", "?")
                            style = (
                                "[bold magenta]" if confidence == SQLiConfidence.CRITICAL.value
                                else "[bold red]"
                            )
                            console.print(
                                f"{style}[!] SQLi potencial encontrado "
                                f"({confidence}): {_rich_escape(_sqli_url)}[/{style[1:]}"
                            )
                            # ── Dedup de sub-test: um único ↳ por (method, param) ─
                            _seen_sqli: set = set()
                            for _t in sqli_result.get("tests", []):
                                if _t.get("vulnerable"):
                                    _method  = _t.get("method", "unknown")
                                    _param   = _t.get("parameter", "")
                                    _subkey  = f"{_method}|{_param}"
                                    if _subkey in _seen_sqli:
                                        continue
                                    _seen_sqli.add(_subkey)
                                    _ev_list  = _t.get("evidence", [])
                                    _ev_str   = " | ".join(_ev_list[:2]) if _ev_list else ""
                                    _param_str = f" [parâmetro: {_param}]" if _param else ""
                                    console.print(
                                        f"[dim]    ↳ método: [yellow]{_method}[/yellow]"
                                        f"{_param_str}"
                                        + (f"  evidência: [italic]{_rich_escape(_ev_str[:120])}[/italic]" if _ev_str else "")
                                        + "[/dim]"
                                    )
                    progress.advance(task2)
                    if self.config.get("stealth_mode", False):
                        _interruptible_sleep(random.uniform(3, 6))

            # ── Testes XSS ──────────────────────────────────────────────────
            urls_to_test_xss = [r for r in results if self.config.get("xss_detection", False)]
            if self.config.get("xss_detection", False) and urls_to_test_xss:
                task3 = progress.add_task("[cyan]Testando [bold yellow]XSS[cyan]...", total=len(urls_to_test_xss))
                for result in urls_to_test_xss:
                    if _exit_requested:
                        break
                    if _skip_current:
                        console.print("[yellow][~] Ctrl+C — pulando os testes XSS restantes deste dork.[/yellow]")
                        _skip_current = False
                        break

                    xss_result         = self.analyzer.check_xss(result["url"])
                    result["xss_test"] = xss_result

                    if xss_result.get("waf_detected") and not result.get("sqli_test", {}).get("waf_detected"):
                        console.print(
                            f"[yellow][~] WAF detectado "
                            f"({xss_result['waf_detected']}): {_rich_escape(result['url'])}[/yellow]"
                        )
                        self.stats["waf_detected"] += 1

                    if xss_result.get("vulnerable", False):
                        _xss_url = result["url"]
                        # ── Dedup URL-level ──────────────────────────────────
                        if _xss_url not in self._reported_xss_urls:
                            self._reported_xss_urls.add(_xss_url)
                            self.stats["xss_vulnerable"] += 1
                            confidence = xss_result.get("overall_confidence", "?")
                            types_str  = ", ".join(xss_result.get("xss_types_found", []))
                            console.print(
                                f"[bold yellow][!] XSS potencial encontrado "
                                f"({confidence}) [{types_str}]: {_rich_escape(_xss_url)}[/bold yellow]"
                            )
                            # ── Dedup de sub-test: um único ↳ por tipo XSS ───────
                            _seen_xss: set = set()
                            for _xt in xss_result.get("tests", []):
                                if _xt.get("vulnerable"):
                                    _xtype = _xt.get("type", "unknown")
                                    if _xtype in _seen_xss:
                                        continue
                                    _seen_xss.add(_xtype)
                                    _xev   = " | ".join(_xt.get("evidence", [])[:2])
                                    _xpayld = _xt.get("payload", "")
                                    _xpstr  = f" [payload: {_xpayld[:60]}]" if _xpayld else ""
                                    console.print(
                                        f"[dim]    ↳ tipo: [yellow]{_xtype}[/yellow]{_xpstr}"
                                        + (f"  evidência: [italic]{_rich_escape(_xev[:120])}[/italic]" if _xev else "")
                                        + "[/dim]"
                                    )
                    progress.advance(task3)
                    if self.config.get("stealth_mode", False):
                        _interruptible_sleep(random.uniform(2, 5))
        return results

    def run_search(self, dorks: List[str], count: int):
        """
        Itera sobre os dorks, busca cada um, analisa os resultados e aplica delays entre dorks.

        Integra o sistema de Checkpoint/Resume (ponto 3):
        -   Gera um session_id determinístico a partir dos dorks anteriores.
        - Se existir um checkpoint válido, pergunta ao usuário se deseja retomar.
        - Salva o checkpoint em disco após cada dork concluído.
        - Exclui o checkpoint ao final da sessão (concluída ou encerrada via exit).
        """
        global _skip_current, _exit_requested

        # ── Checkpoint setup ──────────────────────────────────────────────────
        _session_seed   = "|".join(dorks[:5]) + str(len(dorks))
        session_id      = hashlib.md5(
            _session_seed.encode(), usedforsecurity=False
        ).hexdigest()[:12]
        checkpoint      = SessionCheckpoint(session_id)
        saved_state     = checkpoint.load()
        completed_dorks: Set[str] = set()

        if saved_state:
            n_done   = len(saved_state.get("completed_dorks", []))
            saved_at = saved_state.get("saved_at", "?")
            console.print(
                f"\n[bold yellow]┌─[ CHECKPOINT ENCONTRADO ][/bold yellow]"
            )
            console.print(
                f"[bold yellow]│[/bold yellow]"
                f"  Salvo: [dim]{saved_at}[/dim]"
                f"  │  Dorks concluídos: [green]{n_done}[/green] / {len(dorks)}"
            )
            console.print(
                "[bold yellow]│  Retomar sessão? [Y/n]:[/bold yellow] ",
                end="",
            )
            try:
                _resume = input("").strip().lower() in ("", "y", "yes")
            except KeyboardInterrupt:
                _resume = False

            if _resume:
                completed_dorks = set(saved_state.get("completed_dorks", []))
                self.results    = saved_state.get("results", [])
                self.stats.update(saved_state.get("stats", {}))
                # Reconstrói url_hashes a partir dos resultados carregados
                # Para garantir que is_duplicate() funcione corretamente
                for r in self.results:
                    _h = self._hash_url(r.get("url", ""))
                    self.url_hashes.add(_h)
                console.print(
                    f"[bold yellow]└─>[/bold yellow] [green]Sessão retomada — "
                    f"{len(self.results)} resultados já coletados.[/green]\n"
                )
            else:
                # Usuário optou por não retomar: exclui o checkpoint antigo
                checkpoint.delete()
                console.print(
                    "[bold yellow]└─>[/bold yellow] [dim]Nova sessão iniciada.[/dim]\n"
                )
        # ── Fim do setup de checkpoint ─────────────────────────────────────────────

        total_dorks = len(dorks)
        console.print(f"[bold cyan][*] Busca com {total_dorks} dork(s)[/bold cyan]\n")
        console.print(
            f"[dim]💡 Ctrl+C durante um dork → pular.  "
            f"Ctrl+C duplo → sair.[/dim]\n"
        )
        if self.config.get("stealth_mode", False):
            console.print("[bold magenta][*] Modo stealth:[/bold magenta][bold green] OK[/bold green]")
        if self.config.get("http_fingerprinting", True):
            console.print("[bold magenta][*] HTTP Fingerprinting:[/bold magenta][bold green] OK[/bold green]")
        if self.config.get("sqli_detection", False):
            console.print("[bold red][*] Detecção de SQL Injection:[/bold red][bold green] OK[/bold green]")
        if self.config.get("xss_detection", False):
            xss_t = self.config.get("xss_type", "all").upper()
            console.print(f"[bold yellow][*] Detecção de XSS:[/bold yellow][bold green] OK[/bold green] [dim](tipo: {xss_t})[/dim]")
        if TERMUX_IS_ANDROID:
            console.print("[bold green][*] Modo Android/Termux: constantes de economia de bateria ativas[/bold green]")

        for index, dork in enumerate(dorks, start=1):
            if _exit_requested:
                console.print("[bold red][!!] Saída solicitada — interrompendo a busca.[/bold red]")
                break

            # ── Pula dorks já concluídos na sessão anterior ─────────
            if dork in completed_dorks:
                console.print(
                    f"[dim][~] Dork {index}/{total_dorks} já concluído — pular.[/dim]"
                )
                continue

            results = self.search_dork(dork, count,
                                       dork_index=index, total_dorks=total_dorks)

            if _exit_requested:
                self.results.extend(results)
                if self.output_file:
                    self.save_results()
                # Salva checkpoint mesmo em saída forçada
                checkpoint.save(list(completed_dorks), self.results, dict(self.stats))
                console.print("[bold red][!!] Saída solicitada — interrompendo a busca.[/bold red]")
                break

            if (
                self.config.get("analyze_files", True)
                or self.config.get("sqli_detection", False)
                or self.config.get("xss_detection", False)
            ):
                results = self.analyze_results(results)

            self.results.extend(results)
            if self.output_file:
                self.save_results()

            # ── Salva checkpoint após cada dork concluído ────────────────────
            completed_dorks.add(dork)
            checkpoint.save(list(completed_dorks), self.results, dict(self.stats))

            if _exit_requested:
                console.print("[bold red][!!] Saída solicitada — interrompendo a busca.[/bold red]")
                break

            if index >= total_dorks:
                break

            stealth = self.config.get("stealth_mode", False)
            delay   = self._compute_base_delay(len(results), stealth)
            console.print(f"[yellow][~] Aguardando {delay}s antes do próximo dork...[/yellow]")

            _interruptible_sleep(delay)

            if _exit_requested:
                console.print("[bold red][!!] Saída solicitada — interrompendo a busca.[/bold red]")
                break
            if _skip_current:
                console.print("[yellow][~] Delay pulado.[/yellow]")
                _skip_current = False

            if self._should_trigger_extended_delay():
                long_delay = round(
                    random.uniform(120, 150) if stealth
                    else random.uniform(85, 110), 2
                )
                console.print(
                    f"[bold magenta][~] Delay estendido: {long_delay}s "
                    f"({len(self.results)} resultados totais coletados — proteção de rate limit)"
                    f"[/bold magenta]"
                )
                _interruptible_sleep(long_delay)

                if _exit_requested:
                    console.print("[bold red][!!] Saída solicitada — interrompendo a busca.[/bold red]")
                    break
                if _skip_current:
                    console.print("[yellow][~] Delay estendido pulado.[/yellow]")
                    _skip_current = False

                self._total_results_at_last_extended_delay = len(self.results)

        #   ──  Sessão concluída: remove checkpoint ────────────────────────
        # Só excluímos se _exit_requested for False (sessão encerrada
        # normalmente ou por esgotamento de dorks). Se for True, o checkpoint já foi
        # salvo no break acima, então a sessão pode ser retomada.
        if not _exit_requested:
            checkpoint.delete()

    def save_results(self):
        """Persiste self.results em disco no formato determinado pela extensão do arquivo de saída."""
        if not self.output_file:
            return
        downloads_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Dump")
        os.makedirs(downloads_folder, exist_ok=True)
        filename = os.path.join(downloads_folder, self.output_file)
        ext      = os.path.splitext(filename)[1].lower()
        if not ext:
            filename += ".json"
            ext       = ".json"
        try:
            if   ext == ".csv":  self._save_csv(filename)
            elif ext == ".json": self._save_json(filename)
            elif ext == ".html": self._save_html(filename)
            elif ext == ".txt":  self._save_txt(filename)
            else:
                console.print(f"[red][!] Formato de saída não suportado: {ext}[/red]")
        except Exception as _save_err:
            import traceback as _tb
            console.print(f"[red][!] Erro ao salvar resultados em {filename}[/red]")
            console.print(f"[red]    {_save_err}[/red]")
            console.print(f"[dim]{_tb.format_exc()}[/dim]")

    def _save_csv(self, filename: str):
        if not self.results:
            return
        fieldnames = [
            "url","title","snippet","dork","timestamp","extension","category",
            "file_size","content_type","accessible","status_code",
            "sqli_vulnerable","sqli_confidence","waf_detected",
            "xss_vulnerable","xss_types","xss_confidence",
        ]
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for result in self.results:
                row = result.copy()
                if "sqli_test" in result:
                    row["sqli_vulnerable"] = result["sqli_test"].get("vulnerable", False)
                    row["sqli_confidence"] = result["sqli_test"].get("overall_confidence", "none")
                    row["waf_detected"]    = result["sqli_test"].get("waf_detected", "")
                if "xss_test" in result:
                    row["xss_vulnerable"] = result["xss_test"].get("vulnerable", False)
                    row["xss_types"]      = ",".join(result["xss_test"].get("xss_types_found", []))
                    row["xss_confidence"] = result["xss_test"].get("overall_confidence", "none")
                writer.writerow(row)

    def _save_json(self, filename: str):
        data = {
            "metadata": {
                "total_results":               len(self.results),
                "generated_at":                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "sqli_detection_enabled":      self.config.get("sqli_detection", False),
                "sqli_vulnerabilities_found":  self.stats.get("sqli_vulnerable", 0),
                "xss_detection_enabled":       self.config.get("xss_detection", False),
                "xss_type":                    self.config.get("xss_type", "all"),
                "xss_vulnerabilities_found":   self.stats.get("xss_vulnerable", 0),
                "waf_blocked_count":           self.stats.get("waf_detected", 0),
                "http_fingerprinting_enabled": self.config.get("http_fingerprinting", True),
                "stealth_mode":                self.config.get("stealth_mode", False),
                "android_mode":                TERMUX_IS_ANDROID,
                "statistics":                  dict(self.stats)
            },
            "results": self.results
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _save_txt(self, filename: str):
        if not self.results:
            return
        with open(filename, "w", encoding="utf-8") as f:
            for idx, result in enumerate(self.results, 1):
                f.write(f"{idx}. {result.get('url')}\n")
                if result.get("title"):
                    f.write(f"   Título: {result.get('title')}\n")
                if result.get("category"):
                    f.write(f"   Categoria: {result.get('category')}\n")
                if "sqli_test" in result:
                    sqli = result["sqli_test"]
                    if sqli.get("tested", False):
                        status = "VULNERABLE" if sqli.get("vulnerable") else "SAFE"
                        f.write(f"   SQLi: {status} ({sqli.get('overall_confidence')})\n")
                    if sqli.get("waf_detected"):
                        f.write(f"   WAF: {sqli.get('waf_detected')}\n")
                if "xss_test" in result:
                    xss = result["xss_test"]
                    if xss.get("tested", False):
                        xss_status = "VULNERABLE" if xss.get("vulnerable") else "SAFE"
                        xss_types  = ",".join(xss.get("xss_types_found", [])) or "—"
                        f.write(f"   XSS: {xss_status} ({xss.get('overall_confidence')}) [{xss_types}]\n")
                f.write("\n")

    def _save_html(self, filename: str):
        """Constrói e grava o relatório HTML interativo completo com tema escuro."""
        sqli_count = self.stats.get("sqli_vulnerable", 0)
        sqli_safe  = sum(
            1 for r in self.results
            if "sqli_test" in r and r["sqli_test"].get("tested") and not r["sqli_test"].get("vulnerable")
        )
        sqli_total = sqli_count + sqli_safe
        xss_count  = self.stats.get("xss_vulnerable", 0)
        xss_safe   = sum(
            1 for r in self.results
            if "xss_test" in r and r["xss_test"].get("tested") and not r["xss_test"].get("vulnerable")
        )
        xss_total  = xss_count + xss_safe
        waf_count  = self.stats.get("waf_detected", 0)
        cnt        = {"all": len(self.results), "doc": 0, "sqli": sqli_total, "xss": xss_total, "scripts": 0, "page": 0}
        for r in self.results:
            cat = r.get("category", "unknown")
            if cat in ("documents", "archives", "backups"):    cnt["doc"]     += 1
            elif cat in ("scripts", "configs", "credentials"): cnt["scripts"] += 1
            elif cat == "webpage":                             cnt["page"]    += 1

        import json as _json
        import html as _html_mod

        export_rows = []
        for r in self.results:
            sqli_t = r.get("sqli_test", {})
            if sqli_t.get("tested"):
                conf   = sqli_t.get("overall_confidence", "")
                sqli_s = ("critical" if conf == "critical" else "vuln") if sqli_t.get("vulnerable") else "safe"
            else:
                sqli_s = "untested"
            xss_t  = r.get("xss_test", {})
            if xss_t.get("tested"):
                xss_s = "vuln" if xss_t.get("vulnerable") else "safe"
            else:
                xss_s = "untested"
            export_rows.append({
                "url":       r.get("url", ""),
                "title":     r.get("title", ""),
                "dork":      r.get("dork", ""),
                "category":  r.get("category", ""),
                "ext":       r.get("extension", ""),
                "timestamp": r.get("timestamp", ""),
                "sqli":      sqli_s,
                "conf":      sqli_t.get("overall_confidence", ""),
                "waf":       sqli_t.get("waf_detected", "") or "",
                "xss":       xss_s,
                "xss_types": ",".join(xss_t.get("xss_types_found", [])),
                "xss_conf":  xss_t.get("overall_confidence", ""),
            })

        file_rows = []
        for r in self.results:
            cat = r.get("category", "webpage")
            if cat == "webpage":
                continue
            file_rows.append({
                "url":         r.get("url", ""),
                "title":       r.get("title", ""),
                "category":    cat,
                "ext":         r.get("extension", ""),
                "size":        r.get("file_size"),
                "size_str":    self._format_size(r.get("file_size")),
                "accessible":  r.get("accessible", False),
                "status_code": r.get("status_code"),
                "timestamp":   r.get("timestamp", ""),
            })

        export_data_js = _json.dumps(export_rows, ensure_ascii=False).replace("</", "<\\/")
        file_data_js   = _json.dumps(file_rows,   ensure_ascii=False).replace("</", "<\\/")
        report_base    = os.path.splitext(os.path.basename(filename))[0]

        parts = []
        parts.append("""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MappingExpo | Relatório</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Courier New', monospace; background: #000; color: #00ff41; min-height: 100vh; overflow-x: hidden; }
        #matrix-canvas { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 0; opacity: 0.32; pointer-events: none; }
        #content { position: relative; z-index: 1; padding: 28px 32px; max-width: 1400px; margin: 0 auto; }
        .header { background: rgba(0,10,0,0.85); border: 1px solid #00ff41; border-left: 4px solid #00ff41;
            padding: 22px 28px; margin-bottom: 24px; box-shadow: 0 0 24px rgba(0,255,65,0.15); }
        .header h1 { font-size: 22px; color: #00ff41; text-shadow: 0 0 10px #00ff41; letter-spacing: 2px; }
        .header .subtitle { margin-top: 6px; font-size: 12px; color: #009922; letter-spacing: 1px; }
        .header .blink { animation: blink 1.1s step-end infinite; }
        @keyframes blink { 50% { opacity: 0; } }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; margin-bottom: 24px; }
        .stat-card { background: rgba(0,10,0,0.82); border: 1px solid #00aa2a; padding: 16px 18px; }
        .stat-card h3 { font-size: 11px; color: #009922; letter-spacing: 1px; text-transform: uppercase; }
        .stat-card p { font-size: 26px; font-weight: bold; color: #00ff41; margin-top: 8px; text-shadow: 0 0 8px rgba(0,255,65,0.5); }
        .sqli-alert { background: rgba(40,0,0,0.88); border: 1px solid #ff2222; border-left: 4px solid #ff2222;
            padding: 14px 20px; margin-bottom: 20px; color: #ff4444; }
        .sqli-alert h2 { font-size: 15px; letter-spacing: 2px; margin-bottom: 6px; }
        .sqli-alert p  { font-size: 13px; color: #ff6666; }
        .waf-alert { background: rgba(30,20,0,0.88); border: 1px solid #ffaa00; border-left: 4px solid #ffaa00;
            padding: 12px 20px; margin-bottom: 14px; color: #ffcc44; font-size: 13px; }
        .toolbar { display: flex; align-items: flex-start; gap: 8px; margin-bottom: 6px; flex-wrap: wrap; }
        .filter-bar { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; flex: 1; position: relative; }
        .filter-label { color: #009922; font-size: 12px; letter-spacing: 1px; margin-right: 4px; white-space: nowrap; }
        .filter-group { position: relative; display: inline-block; }
        .filter-btn { background: rgba(0,10,0,0.7); border: 1px solid #00aa2a; color: #00aa2a; padding: 5px 13px;
            font-family: 'Courier New', monospace; font-size: 11px; cursor: pointer; letter-spacing: 2px;
            text-transform: uppercase; transition: all .15s; white-space: nowrap; display: inline-flex; align-items: center; gap: 5px; }
        .filter-btn:hover { background: rgba(0,255,65,0.12); border-color: #00ff41; color: #00ff41; }
        .filter-btn.active { background: #00ff41; color: #000; border-color: #00ff41; font-weight: bold; }
        .badge { display: inline-block; background: rgba(0,255,65,0.15); border: 1px solid #009922; color: #00ff41;
            font-size: 9px; padding: 1px 5px; border-radius: 2px; min-width: 20px; text-align: center; }
        .filter-btn.active .badge { background: rgba(0,0,0,0.25); color: #000; }
        .has-sub .arrow { font-size: 8px; opacity: 0.7; }
        .sub-menu { display: none; position: absolute; top: calc(100% + 3px); left: 0; z-index: 200;
            background: rgba(0,6,0,0.97); border: 1px solid #00aa2a; border-top: 2px solid #00ff41;
            box-shadow: 0 6px 24px rgba(0,255,65,0.18); min-width: 165px; }
        .sub-menu.open { display: block; }
        .sub-btn { display: flex; align-items: center; justify-content: space-between; width: 100%;
            background: transparent; border: none; border-bottom: 1px solid rgba(0,170,42,0.18);
            color: #009922; padding: 8px 16px; font-family: 'Courier New', monospace; font-size: 11px;
            letter-spacing: 1.5px; text-transform: uppercase; cursor: pointer; text-align: left; transition: all .12s; gap: 8px; }
        .sub-btn:last-child { border-bottom: none; }
        .sub-btn:hover { background: rgba(0,255,65,0.08); color: #00ff41; padding-left: 22px; }
        .sub-btn.active { color: #00ff41; font-weight: bold; background: rgba(0,255,65,0.06); padding-left: 22px; }
        .sub-btn .sub-badge { font-size: 9px; color: #005500; background: rgba(0,255,65,0.08);
            border: 1px solid #003300; padding: 1px 5px; border-radius: 2px; min-width: 22px; text-align: center; }
        .active-sub-info { font-size: 11px; color: #005500; letter-spacing: 1px; margin-bottom: 10px; min-height: 16px; padding-left: 2px; }
        .active-sub-info span { color: #00aa44; }
        .right-btns { display: flex; gap: 6px; flex-shrink: 0; align-items: flex-start; }
        .srch-wrap, .export-wrap, .files-wrap { position: relative; flex-shrink: 0; }
        .rbt { background: rgba(0,10,18,0.85); border: 1px solid #0077bb; color: #00aaff;
            padding: 5px 13px; font-family: 'Courier New', monospace; font-size: 11px; cursor: pointer;
            letter-spacing: 2px; text-transform: uppercase; display: inline-flex; align-items: center;
            gap: 5px; transition: all .15s; white-space: nowrap; }
        .rbt:hover, .rbt.open { background: rgba(0,100,180,0.2); border-color: #00aaff; color: #fff; }
        .rpanel { display: none; position: absolute; top: calc(100% + 4px); right: 0; z-index: 400;
            background: rgba(0,4,12,0.98); border: 1px solid #007acc; border-top: 2px solid #00aaff;
            box-shadow: 0 10px 40px rgba(0,120,200,0.25); min-width: 370px; }
        .rpanel.open { display: block; animation: fadeIn .15s ease; }
        @keyframes fadeIn { from { opacity:0; transform:translateY(-4px); } to { opacity:1; transform:none; } }
        .panel-close { position: absolute; top: 7px; right: 10px; background: transparent; border: none;
            color: #004466; font-size: 14px; cursor: pointer; line-height: 1; padding: 2px 5px;
            font-family: 'Courier New', monospace; transition: color .12s; z-index: 10; }
        .panel-close:hover { color: #00aaff; }
        .ep-section { padding: 10px 16px; border-bottom: 1px solid rgba(0,100,180,0.2); }
        .ep-section:last-child { border-bottom: none; }
        .ep-title { font-size: 10px; color: #005588; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 8px; }
        .ep-row { display: flex; align-items: center; gap: 6px; margin-bottom: 5px; }
        .ep-row:last-child { margin-bottom: 0; }
        .ep-label { font-size: 11px; color: #0088bb; letter-spacing: 1px; min-width: 115px; flex-shrink: 0; }
        .ep-label.warn { color: #ffaa00; }
        .ep-label.danger { color: #ff4444; }
        .ep-label.safe-lbl { color: #00cc55; }
        .ep-label.view-lbl { color: #cc88ff; }
        .exp-btn { background: transparent; border: 1px solid currentColor; padding: 3px 9px;
            font-family: 'Courier New', monospace; font-size: 10px; cursor: pointer; letter-spacing: 1.5px;
            text-transform: uppercase; transition: all .12s; }
        .exp-btn.txt  { color: #00ccff; border-color: #00ccff; } .exp-btn.txt:hover  { background: #00ccff; color: #000; }
        .exp-btn.json { color: #ffcc00; border-color: #ffcc00; } .exp-btn.json:hover { background: #ffcc00; color: #000; }
        .exp-btn.csv  { color: #00ff99; border-color: #00ff99; } .exp-btn.csv:hover  { background: #00ff99; color: #000; }
        .srch-panel { min-width: 320px; }
        .srch-inner { padding: 14px 16px; }
        .srch-title { font-size: 10px; color: #005588; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 10px; }
        .srch-input-wrap { display: flex; gap: 6px; align-items: center; }
        .srch-input { flex: 1; background: rgba(0,10,20,0.9); border: 1px solid #007acc; color: #00aaff;
            font-family: 'Courier New', monospace; font-size: 12px; padding: 6px 10px; outline: none; letter-spacing: 1px; }
        .srch-input:focus { border-color: #00aaff; box-shadow: 0 0 8px rgba(0,170,255,0.2); }
        .srch-input::placeholder { color: #003355; }
        .srch-clear { background: transparent; border: 1px solid #004466; color: #006688; padding: 6px 10px;
            font-family: 'Courier New', monospace; font-size: 10px; cursor: pointer; letter-spacing: 1px; transition: all .12s; }
        .srch-clear:hover { border-color: #00aaff; color: #00aaff; }
        .srch-meta { margin-top: 8px; font-size: 10px; color: #004466; letter-spacing: 1px; }
        .srch-meta span { color: #0088bb; }
        .srch-scope { margin-top: 10px; display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
        .srch-scope-lbl { font-size: 9px; color: #004466; letter-spacing: 1px; }
        .scope-btn { background: transparent; border: 1px solid #004466; color: #006688; padding: 3px 8px;
            font-family: 'Courier New', monospace; font-size: 9px; cursor: pointer; letter-spacing: 1px;
            text-transform: uppercase; transition: all .12s; }
        .scope-btn.active { background: rgba(0,122,204,0.3); border-color: #007acc; color: #00aaff; }
        .scope-btn:hover { border-color: #0099cc; color: #0099cc; }
        .files-panel { min-width: 420px; max-height: 520px; flex-direction: column; }
        .rpanel.open.files-panel { display: flex; }
        .files-hdr { padding: 10px 16px; border-bottom: 1px solid rgba(0,100,180,0.2); flex-shrink: 0; }
        .files-bulk { padding: 8px 16px; border-bottom: 1px solid rgba(0,100,180,0.2); flex-shrink: 0;
            display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
        .bulk-lbl { font-size: 10px; color: #005588; letter-spacing: 1px; flex: 1; }
        .files-list { overflow-y: auto; flex: 1; }
        .file-row { display: flex; align-items: center; gap: 8px; padding: 7px 14px;
            border-bottom: 1px solid rgba(0,100,180,0.1); transition: background .1s; }
        .file-row:hover { background: rgba(0,100,180,0.06); }
        .file-row:last-child { border-bottom: none; }
        .file-chk { accent-color: #007acc; cursor: pointer; flex-shrink: 0; }
        .file-info { flex: 1; min-width: 0; }
        .file-url { font-size: 10px; color: #0088bb; overflow: hidden; text-overflow: ellipsis;
            white-space: nowrap; display: block; text-decoration: none; }
        .file-url:hover { color: #00aaff; }
        .file-cat { font-size: 9px; color: #004466; margin-top: 2px; letter-spacing: 1px; }
        .file-size { font-size: 10px; color: #005588; flex-shrink: 0; min-width: 55px; text-align: right; }
        .file-dl { background: transparent; border: none; color: #005588; font-size: 14px;
            cursor: pointer; text-decoration: none; flex-shrink: 0; transition: color .12s;
            line-height: 1; padding: 0 2px; }
        .file-dl:hover { color: #00aaff; }
        .files-empty { padding: 20px 16px; font-size: 11px; color: #004466; text-align: center; letter-spacing: 1px; }
        .table-wrap { background: rgba(0,8,0,0.82); border: 1px solid #00aa2a; overflow-x: auto; overflow-y: auto; max-height: calc(100vh - 290px); min-height: 200px; }
        thead th { background: rgba(0,10,0,0.97); color: #00ff41; padding: 11px 10px; text-align: left;
            border-bottom: 1px solid #00aa2a; font-size: 11px; letter-spacing: 2px;
            text-transform: uppercase; white-space: nowrap; position: sticky; top: 0; z-index: 5; }
        table { width: 100%; border-collapse: collapse; table-layout: auto; }
        col.c-num   { width: 36px; }
        col.c-url   { min-width: 180px; }
        col.c-title { min-width: 120px; width: 14%; }
        col.c-cat   { min-width: 90px;  width: 9%; }
        col.c-sqli  { min-width: 110px; width: 10%; }
        col.c-xss   { min-width: 110px; width: 10%; }
        col.c-waf   { min-width: 70px;  width: 7%; }
        col.c-size  { min-width: 54px;  width: 6%; }
        td { padding: 9px 10px; border-bottom: 1px solid rgba(0,170,42,0.15); font-size: 12px;
            vertical-align: middle; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        tr:hover td { background: rgba(0,255,65,0.04); }
        tr.hidden { display: none; }
        tr.srch-hidden { display: none; }
        a { color: #00aaff; text-decoration: none; }
        a:hover { color: #00ff41; }
        .category { display: inline-block; padding: 2px 7px; border: 1px solid; font-size: 10px;
            letter-spacing: 1px; text-transform: uppercase; white-space: nowrap; }
        .category-documents   { border-color: #ff6b6b; color: #ff6b6b; }
        .category-archives    { border-color: #ffa500; color: #ffa500; }
        .category-databases   { border-color: #b47fff; color: #b47fff; }
        .category-backups     { border-color: #e67e22; color: #e67e22; }
        .category-configs     { border-color: #1abc9c; color: #1abc9c; }
        .category-scripts     { border-color: #f1c40f; color: #f1c40f; }
        .category-webpage     { border-color: #7f8c8d; color: #7f8c8d; }
        .category-credentials { border-color: #e74c3c; color: #e74c3c; }
        .sqli-critical { color: #ff00ff; font-weight: bold; text-shadow: 0 0 6px #ff00ff; }
        .sqli-vuln     { color: #ff3333; font-weight: bold; }
        .sqli-safe     { color: #00ff41; }
        .sqli-untested { color: #444; }
        .xss-vuln      { color: #ffaa00; font-weight: bold; }
        .xss-safe      { color: #00ff41; }
        .xss-untested  { color: #444; }
        .waf-label     { font-size: 10px; color: #ffaa00; border: 1px solid #ffaa00; padding: 1px 5px; letter-spacing: 1px; white-space: nowrap; }
        .url-cell { display: flex; align-items: center; gap: 6px; overflow: hidden; }
        .url-cell a { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0; }
        .dl-btn { flex-shrink: 0; background: transparent; border: none; color: #005588;
            font-size: 15px; cursor: pointer; text-decoration: none; line-height: 1;
            padding: 0; transition: color .12s; }
        .dl-btn:hover { color: #00aaff; }
        .info-btn { flex-shrink: 0; background: transparent; border: none; color: #004455;
            font-size: 13px; cursor: pointer; line-height: 1; padding: 0 1px;
            transition: color .12s; font-family: 'Courier New', monospace; }
        .info-btn:hover { color: #00ccff; }
        .info-overlay { display: none; position: fixed; inset: 0; z-index: 8900;
            background: rgba(0,0,0,0.72); backdrop-filter: blur(2px); }
        .info-overlay.open { display: block; animation: fadeIn .15s ease; }
        .info-popup { display: none; position: fixed; z-index: 9000;
            top: 50%; left: 50%; transform: translate(-50%,-50%);
            background: rgba(0,4,12,0.98); border: 1px solid #007acc;
            border-top: 3px solid #00aaff;
            box-shadow: 0 0 60px rgba(0,120,200,0.45), 0 0 120px rgba(0,80,160,0.25);
            width: min(560px, 92vw); max-height: 80vh; overflow-y: auto;
            font-size: 11px; padding: 18px 20px; }
        .info-popup.open { display: block; animation: fadeIn .18s ease; }
        .info-popup-title { font-size: 10px; color: #005588; letter-spacing: 2px;
            text-transform: uppercase; margin-bottom: 10px; border-bottom: 1px solid rgba(0,100,180,0.2);
            padding-bottom: 6px; display: flex; justify-content: space-between; align-items: center; }
        .info-close { background: transparent; border: none; color: #004466; cursor: pointer;
            font-size: 14px; font-family: 'Courier New', monospace; padding: 0 3px; transition: color .12s; }
        .info-close:hover { color: #00aaff; }
        .info-row { display: flex; gap: 8px; margin-bottom: 5px; align-items: flex-start; }
        .info-lbl { color: #005588; min-width: 90px; flex-shrink: 0; letter-spacing: 1px; }
        .info-val { color: #00aaff; word-break: break-all; }
        .footer { margin-top: 28px; padding: 14px 0; border-top: 1px solid #002200;
            text-align: center; font-size: 11px; color: #004400; letter-spacing: 2px; }
        #toast { position: fixed; bottom: 28px; right: 28px; z-index: 9999; background: rgba(0,20,0,0.95);
            border: 1px solid #00ff41; color: #00ff41; padding: 10px 20px; font-family: 'Courier New', monospace;
            font-size: 12px; letter-spacing: 1px; opacity: 0; transition: opacity .3s; pointer-events: none; }
        #toast.show { opacity: 1; }
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: #000; }
        ::-webkit-scrollbar-thumb { background: #003300; }
        ::-webkit-scrollbar-thumb:hover { background: #00aa2a; }
    </style>
</head>
<body>
<canvas id="matrix-canvas"></canvas>
<div id="content">
    <div class="header">
        <h1>&#9632; MappingExpo | Relatório <span class="blink">_</span></h1>
""")
        parts.append(f'        <div class="subtitle">&#10132; Gerado: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;|&nbsp; xploits3c.github.io/DorkEye</div>\n')
        parts.append("    </div>\n")

        if sqli_count > 0:
            parts.append(f"""    <div class="sqli-alert">
        <h2>&#9888; ALERTA DE SEGURANÇA &#9888;</h2>
        <p><strong>{sqli_count}</strong> vulnerabilidades potenciais de injeção SQL detectadas!</p>
        <p>Revise abaixo os resultados marcados como VULNERABLE.</p>
    </div>
""")
        if xss_count > 0:
            parts.append(f"""    <div class="xss-alert" style="background:rgba(40,20,0,0.88);border:1px solid #ffaa00;border-left:4px solid #ffaa00;padding:14px 20px;margin-bottom:20px;color:#ffcc44;">
        <h2 style="font-size:15px;letter-spacing:2px;margin-bottom:6px;">&#9888; ALERTA XSS &#9888;</h2>
        <p style="font-size:13px;color:#ffdd88;"><strong>{xss_count}</strong> vulnerabilidades potenciais de Cross-Site Scripting detectadas!</p>
    </div>
""")
        if waf_count > 0:
            parts.append(f"""    <div class="waf-alert">
        &#9888; <strong>{waf_count}</strong> alvo(s) protegido(s) por WAF detectado(s).
    </div>
""")
        parts.append(f"""    <div class="stats">
        <div class="stat-card"><h3>&#9632; TOTAL DE RESULTADOS</h3><p>{len(self.results)}</p></div>
        <div class="stat-card"><h3>&#9632; DUPLICADOS FILTRADOS</h3><p>{self.stats.get("duplicates", 0)}</p></div>
        <div class="stat-card"><h3>&#9632; VULNERABILIDADES SQLI</h3><p style="color:#ff3333;">{sqli_count}</p></div>
        <div class="stat-card"><h3>&#9632; VULNERABILIDADES XSS</h3><p style="color:#ffaa00;">{xss_count}</p></div>
        <div class="stat-card"><h3>&#9632; WAF DETECTADO</h3><p style="color:#ffaa00;">{waf_count}</p></div>
        <div class="stat-card"><h3>&#9632; TEMPO DE EXECUÇÃO</h3><p>{round(time.time() - self.start_time, 2)}s</p></div>
    </div>

    <div class="toolbar">
      <div class="filter-bar">
        <span class="filter-label">[ FILTRO ]</span>
        <button class="filter-btn active" data-group="all" onclick="applyFilter(this)">TODOS <span class="badge" id="badge-all">{cnt["all"]}</span></button>
        <div class="filter-group" id="fg-doc">
            <button class="filter-btn has-sub" data-group="doc" onclick="applyFilter(this)">DOCS <span class="badge" id="badge-doc">{cnt["doc"]}</span><span class="arrow">&#9660;</span></button>
            <div class="sub-menu" id="sub-doc">
                <button class="sub-btn active" data-sub="doc-all"  onclick="applySubFilter(this,'doc')">TODOS    <span class="sub-badge" id="sbadge-doc-all">{cnt["doc"]}</span></button>
                <button class="sub-btn"        data-sub="doc-pdf"  onclick="applySubFilter(this,'doc')">PDF      <span class="sub-badge" id="sbadge-doc-pdf">-</span></button>
                <button class="sub-btn"        data-sub="doc-docx" onclick="applySubFilter(this,'doc')">DOCX     <span class="sub-badge" id="sbadge-doc-docx">-</span></button>
                <button class="sub-btn"        data-sub="doc-xlsx" onclick="applySubFilter(this,'doc')">XLSX     <span class="sub-badge" id="sbadge-doc-xlsx">-</span></button>
                <button class="sub-btn"        data-sub="doc-ppt"  onclick="applySubFilter(this,'doc')">PPT      <span class="sub-badge" id="sbadge-doc-ppt">-</span></button>
                <button class="sub-btn"        data-sub="doc-arc"  onclick="applySubFilter(this,'doc')">ARQUIVOS <span class="sub-badge" id="sbadge-doc-arc">-</span></button>
            </div>
        </div>
        <div class="filter-group" id="fg-sqli">
            <button class="filter-btn has-sub" data-group="sqli" onclick="applyFilter(this)">SQLi <span class="badge" id="badge-sqli">{cnt["sqli"]}</span><span class="arrow">&#9660;</span></button>
            <div class="sub-menu" id="sub-sqli">
                <button class="sub-btn active" data-sub="sqli-all"      onclick="applySubFilter(this,'sqli')">SQLi TODOS    <span class="sub-badge" id="sbadge-sqli-all">{sqli_total}</span></button>
                <button class="sub-btn"        data-sub="sqli-critical" onclick="applySubFilter(this,'sqli')">SQLi CRITICAL <span class="sub-badge sqli-critical" id="sbadge-sqli-critical">-</span></button>
                <button class="sub-btn"        data-sub="sqli-vuln"     onclick="applySubFilter(this,'sqli')">SQLi VULN     <span class="sub-badge sqli-vuln" id="sbadge-sqli-vuln">{sqli_count}</span></button>
                <button class="sub-btn"        data-sub="sqli-safe"     onclick="applySubFilter(this,'sqli')">SQLi SAFE     <span class="sub-badge" id="sbadge-sqli-safe">{sqli_safe}</span></button>
            </div>
        </div>
        <div class="filter-group" id="fg-xss">
            <button class="filter-btn has-sub" data-group="xss" onclick="applyFilter(this)">XSS <span class="badge" id="badge-xss">{cnt["xss"]}</span><span class="arrow">&#9660;</span></button>
            <div class="sub-menu" id="sub-xss">
                <button class="sub-btn active" data-sub="xss-all"  onclick="applySubFilter(this,'xss')">TODOS <span class="sub-badge" id="sbadge-xss-all">{xss_total}</span></button>
                <button class="sub-btn"        data-sub="xss-vuln" onclick="applySubFilter(this,'xss')">VULN <span class="sub-badge xss-vuln" id="sbadge-xss-vuln">{xss_count}</span></button>
                <button class="sub-btn"        data-sub="xss-safe" onclick="applySubFilter(this,'xss')">SAFE <span class="sub-badge" id="sbadge-xss-safe">{xss_safe}</span></button>
            </div>
        </div>
        <div class="filter-group" id="fg-scripts">
            <button class="filter-btn has-sub" data-group="scripts" onclick="applyFilter(this)">SCRIPTS <span class="badge" id="badge-scripts">{cnt["scripts"]}</span><span class="arrow">&#9660;</span></button>
            <div class="sub-menu" id="sub-scripts">
                <button class="sub-btn active" data-sub="scripts-all"    onclick="applySubFilter(this,'scripts')">TODOS   <span class="sub-badge" id="sbadge-scripts-all">{cnt["scripts"]}</span></button>
                <button class="sub-btn"        data-sub="scripts-php"    onclick="applySubFilter(this,'scripts')">PHP     <span class="sub-badge" id="sbadge-scripts-php">-</span></button>
                <button class="sub-btn"        data-sub="scripts-asp"    onclick="applySubFilter(this,'scripts')">ASP     <span class="sub-badge" id="sbadge-scripts-asp">-</span></button>
                <button class="sub-btn"        data-sub="scripts-sh"     onclick="applySubFilter(this,'scripts')">SH/BAT  <span class="sub-badge" id="sbadge-scripts-sh">-</span></button>
                <button class="sub-btn"        data-sub="scripts-config" onclick="applySubFilter(this,'scripts')">CONFIGS <span class="sub-badge" id="sbadge-scripts-config">-</span></button>
                <button class="sub-btn"        data-sub="scripts-creds"  onclick="applySubFilter(this,'scripts')">CREDS   <span class="sub-badge" id="sbadge-scripts-creds">-</span></button>
            </div>
        </div>
        <button class="filter-btn" data-group="page" onclick="applyFilter(this)">PÁGINAS <span class="badge" id="badge-page">{cnt["page"]}</span></button>
      </div>
      <div class="right-btns">
        <div class="srch-wrap" id="srchWrap">
          <button class="rbt" id="srchToggle" onclick="toggleSearch()">&#128269; BUSCAR</button>
          <div class="rpanel srch-panel" id="srchPanel">
            <button class="panel-close" onclick="document.getElementById('srchPanel').classList.remove('open');document.getElementById('srchToggle').classList.remove('open')" title="Fechar">&#10005;</button>
            <div class="srch-inner">
              <div class="srch-title">&#9632; Busca</div>
              <div class="srch-input-wrap">
                <input class="srch-input" id="srchInput" type="text" placeholder="Digite para filtrar resultados..." oninput="doSearch()" autocomplete="off" spellcheck="false">
                <button class="srch-clear" onclick="clearSearch()">LIMPAR</button>
              </div>
              <div class="srch-meta">Correspondências: <span id="srchCount">-</span> de {len(self.results)} resultados</div>
              <div class="srch-scope">
                <span class="srch-scope-lbl">SCOPE:</span>
                <button class="scope-btn active" data-scope="url"      onclick="toggleScope(this)">URL</button>
                <button class="scope-btn active" data-scope="title"    onclick="toggleScope(this)">TÍTULO</button>
                <button class="scope-btn active" data-scope="category" onclick="toggleScope(this)">CATEGORIA</button>
                <button class="scope-btn active" data-scope="dork"     onclick="toggleScope(this)">DORK</button>
              </div>
            </div>
          </div>
        </div>
        <div class="export-wrap" id="exportWrap">
          <button class="rbt" id="exportToggle" onclick="toggleExportPanel()">&#11015; LINKS</button>
          <div class="rpanel" id="exportPanel">
            <button class="panel-close" onclick="document.getElementById('exportPanel').classList.remove('open');document.getElementById('exportToggle').classList.remove('open')" title="Fechar">&#10005;</button>
            <div class="ep-section">
              <div class="ep-title">&#9632; Exportar Links - Todos</div>
              <div class="ep-row">
                <span class="ep-label">Todos ({len(self.results)})</span>
                <button class="exp-btn txt" onclick="doExport('txt','all')">TXT</button>
                <button class="exp-btn json" onclick="doExport('json','all')">JSON</button>
                <button class="exp-btn csv" onclick="doExport('csv','all')">CSV</button>
              </div>
            </div>
            <div class="ep-section">
              <div class="ep-title">&#9632; Exportar Links - SQLi</div>
              <div class="ep-row">
                <span class="ep-label warn">Todos os testados <span id="epCntSqliAll"></span></span>
                <button class="exp-btn txt"  onclick="doExport('txt','sqli-all')">TXT</button>
                <button class="exp-btn json" onclick="doExport('json','sqli-all')">JSON</button>
                <button class="exp-btn csv"  onclick="doExport('csv','sqli-all')">CSV</button>
              </div>
              <div class="ep-row">
                <span class="ep-label danger">VULN <span id="epCntSqliVuln"></span></span>
                <button class="exp-btn txt"  onclick="doExport('txt','sqli-vuln')">TXT</button>
                <button class="exp-btn json" onclick="doExport('json','sqli-vuln')">JSON</button>
                <button class="exp-btn csv"  onclick="doExport('csv','sqli-vuln')">CSV</button>
              </div>
              <div class="ep-row">
                <span class="ep-label safe-lbl">SAFE <span id="epCntSqliSafe"></span></span>
                <button class="exp-btn txt"  onclick="doExport('txt','sqli-safe')">TXT</button>
                <button class="exp-btn json" onclick="doExport('json','sqli-safe')">JSON</button>
                <button class="exp-btn csv"  onclick="doExport('csv','sqli-safe')">CSV</button>
              </div>
            </div>
            <div class="ep-section">
              <div class="ep-title">&#9632; Exportar Links - XSS</div>
              <div class="ep-row">
                <span class="ep-label warn">Todos os testados <span id="epCntXssAll"></span></span>
                <button class="exp-btn txt"  onclick="doExport('txt','xss-all')">TXT</button>
                <button class="exp-btn json" onclick="doExport('json','xss-all')">JSON</button>
                <button class="exp-btn csv"  onclick="doExport('csv','xss-all')">CSV</button>
              </div>
              <div class="ep-row">
                <span class="ep-label" style="color:#ffaa00;">VULN <span id="epCntXssVuln"></span></span>
                <button class="exp-btn txt"  onclick="doExport('txt','xss-vuln')">TXT</button>
                <button class="exp-btn json" onclick="doExport('json','xss-vuln')">JSON</button>
                <button class="exp-btn csv"  onclick="doExport('csv','xss-vuln')">CSV</button>
              </div>
              <div class="ep-row">
                <span class="ep-label safe-lbl">SAFE <span id="epCntXssSafe"></span></span>
                <button class="exp-btn txt"  onclick="doExport('txt','xss-safe')">TXT</button>
                <button class="exp-btn json" onclick="doExport('json','xss-safe')">JSON</button>
                <button class="exp-btn csv"  onclick="doExport('csv','xss-safe')">CSV</button>
              </div>
            </div>
            <div class="ep-section">
              <div class="ep-title">&#9632; Visão Atual</div>
              <div class="ep-row">
                <span class="ep-label view-lbl">Visíveis <span id="epCntView"></span></span>
                <button class="exp-btn txt"  onclick="doExport('txt','view')">TXT</button>
                <button class="exp-btn json" onclick="doExport('json','view')">JSON</button>
                <button class="exp-btn csv"  onclick="doExport('csv','view')">CSV</button>
              </div>
            </div>
          </div>
        </div>
        <div class="files-wrap" id="filesWrap">
          <button class="rbt" id="filesToggle" onclick="toggleFilesPanel()">&#128196; ARQUIVOS</button>
          <div class="rpanel files-panel" id="filesPanel">
            <div class="files-hdr" style="position:relative">
              <div class="ep-title" style="margin-bottom:0">&#9632; Baixar Arquivos</div>
              <button class="panel-close" onclick="document.getElementById('filesPanel').classList.remove('open');document.getElementById('filesToggle').classList.remove('open')" title="Fechar">&#10005;</button>
            </div>
            <div class="files-bulk">
              <span class="bulk-lbl">Selecionados: <span id="selCount">0</span></span>
              <button class="exp-btn txt"  onclick="selectAllFiles(true)"  style="font-size:9px;padding:2px 7px">TODOS</button>
              <button class="exp-btn txt"  onclick="selectAllFiles(false)" style="font-size:9px;padding:2px 7px;color:#555;border-color:#333">NENHUM</button>
              <button class="exp-btn csv"  onclick="exportSelectedFiles('list')" style="font-size:9px;padding:2px 7px">LISTA (TXT)</button>
              <button class="exp-btn json" onclick="exportSelectedFiles('json')" style="font-size:9px;padding:2px 7px">LISTA (JSON)</button>
            </div>
            <div class="files-list" id="filesList">
""")

        if file_rows:
            for idx_f, fr in enumerate(file_rows):
                size_str      = fr.get("size_str", "N/A")
                is_accessible = fr.get("accessible", False)
                opacity_style = "" if is_accessible else ' style="opacity:.45"'
                status_icon   = "✓" if is_accessible else "✗"
                status_color  = "#00aa44" if is_accessible else "#663333"
                status_code   = fr.get("status_code", "?")
                url_raw       = fr.get("url", "")
                url_esc       = _html_mod.escape(url_raw, quote=True)
                url_short     = _html_mod.escape(url_raw[:62] + ("..." if len(url_raw) > 62 else ""), quote=False)
                cat_str       = fr.get("category", "").upper()
                ext_str       = fr.get("ext", "")
                parts.append(f"""              <div class="file-row"{opacity_style}>
                <input class="file-chk" type="checkbox" data-fidx="{idx_f}" onchange="updateSelCount()">
                <span style="font-size:9px;color:{status_color};flex-shrink:0" title="HTTP {status_code}">{status_icon}</span>
                <div class="file-info">
                  <a class="file-url" href="{url_esc}" target="_blank" title="{url_esc}">{url_short}</a>
                  <div class="file-cat">{cat_str} &nbsp;{ext_str}</div>
                </div>
                <span class="file-size">{size_str}</span>
                <a class="file-dl" href="{url_esc}" download>&#8681;</a>
              </div>
""")
        else:
            parts.append('              <div class="files-empty">Nenhum resultado de arquivo neste relatório.</div>\n')

        parts.append(f"""            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="active-sub-info" id="sub-info"></div>
    <div class="table-wrap">
    <table>
        <colgroup>
          <col class="c-num"><col class="c-url"><col class="c-title">
          <col class="c-cat"><col class="c-sqli"><col class="c-xss"><col class="c-waf"><col class="c-size">
        </colgroup>
        <thead><tr>
          <th>#</th><th>URL</th><th>Título</th>
          <th>Categoria</th><th>SQLi</th><th>XSS</th><th>WAF</th><th>Tamanho</th>
        </tr></thead>
        <tbody id="results-tbody">
""")

        for idx, result in enumerate(self.results, 1):
            size        = self._format_size(result.get('file_size'))
            category    = result.get('category', 'unknown')
            ext         = result.get('extension', '').lower()
            url         = result['url']
            url_display = _html_mod.escape(url[:70] + ('...' if len(url) > 70 else ''), quote=False)
            title_disp  = (result.get('title', 'N/A') or 'N/A')[:40]
            dork_val    = _html_mod.escape(result.get('dork', '') or '', quote=True)
            url_esc_td  = _html_mod.escape(url, quote=True)
            title_esc   = _html_mod.escape(title_disp, quote=True)

            sqli_status = "N/A"
            sqli_class  = "sqli-untested"
            sqli_data   = "untested"
            sqli_conf   = ""
            waf_label   = ""
            xss_status  = "N/A"
            xss_class   = "xss-untested"
            xss_data    = "untested"

            _sqli_t      = result.get("sqli_test", {})
            _vuln_str    = ""
            _payload_str = ""
            if _sqli_t.get("tested"):
                _vuln_str = "VULNERABLE" if _sqli_t.get("vulnerable") else "SAFE"
                _conf_str = _sqli_t.get("overall_confidence", "")
                if _conf_str:
                    _vuln_str += f" ({_conf_str})"
                _details = []
                for _tt in _sqli_t.get("tests", []):
                    if _tt.get("vulnerable"):
                        _m   = _tt.get("method", "")
                        _evs = " | ".join(_tt.get("evidence", [])[:2])
                        _param = _tt.get("parameter", "")
                        _details.append(f"{_m}" + (f"[{_param}]" if _param else "") + (f": {_evs[:80]}" if _evs else ""))
                _payload_str = " ↳ ".join(_details[:3])
            _waf_info = _sqli_t.get("waf_detected", "") or ""

            _xss_t       = result.get("xss_test", {})
            _xss_str     = ""
            _xss_det_str = ""
            if _xss_t.get("tested"):
                _xss_str = "VULNERABLE" if _xss_t.get("vulnerable") else "SAFE"
                _xconf   = _xss_t.get("overall_confidence", "")
                _xtypes  = ",".join(_xss_t.get("xss_types_found", []))
                if _xconf:
                    _xss_str += f" ({_xconf})"
                if _xtypes:
                    _xss_str += f" [{_xtypes}]"
                _xdet = []
                for _xt in _xss_t.get("tests", []):
                    if _xt.get("vulnerable"):
                        _xdet.append(_xt.get("type", "") + ": " + " | ".join(_xt.get("evidence", [])[:1]))
                _xss_det_str = " ↳ ".join(_xdet[:3])

            import json as _json_local
            _info_obj = _json_local.dumps({
                "url":       url,
                "title":     result.get("title", "") or "",
                "snippet":   (result.get("snippet", "") or "")[:200],
                "dork":      result.get("dork", "") or "",
                "category":  category,
                "ext":       ext,
                "ts":        result.get("timestamp", "") or "",
                "sqli":      _vuln_str,
                "payload":   _payload_str,
                "waf":       _waf_info,
                "xss":       _xss_str,
                "xss_det":   _xss_det_str,
                "size":      size,
            }, ensure_ascii=False).replace("'", "&#39;").replace("</", "<\\/")

            if "sqli_test" in result and result["sqli_test"].get("tested", False):
                conf      = result["sqli_test"].get("overall_confidence", "none")
                sqli_conf = conf
                if result["sqli_test"].get("vulnerable", False):
                    if conf == SQLiConfidence.CRITICAL.value:
                        sqli_status = "&#9888; CRITICAL"
                        sqli_class  = "sqli-critical"
                        sqli_data   = "critical"
                    else:
                        sqli_status = f"VULN ({conf})"
                        sqli_class  = "sqli-vuln"
                        sqli_data   = "vuln"
                else:
                    sqli_status = "SAFE"
                    sqli_class  = "sqli-safe"
                    sqli_data   = "safe"

                waf = result["sqli_test"].get("waf_detected", "")
                if waf:
                    waf_label = f'<span class="waf-label">{_html_mod.escape(waf)}</span>'

            if "xss_test" in result and result["xss_test"].get("tested", False):
                if result["xss_test"].get("vulnerable", False):
                    _xtypes_short = ",".join(result["xss_test"].get("xss_types_found", []))[:30]
                    xss_status = f"VULN [{_xtypes_short}]"
                    xss_class  = "xss-vuln"
                    xss_data   = "vuln"
                else:
                    xss_status = "SAFE"
                    xss_class  = "xss-safe"
                    xss_data   = "safe"

            parts.append(f"""            <tr data-category="{category}" data-ext="{ext}" data-sqli="{sqli_data}" data-conf="{sqli_conf}" data-xss="{xss_data}"
                data-idx="{idx-1}" data-url="{url_esc_td}" data-title="{title_esc}" data-dork="{dork_val}">
                <td style="color:#444">{idx}</td>
                <td><div class="url-cell"><a href="{url_esc_td}" target="_blank" title="{url_esc_td}">{url_display}</a><a class="dl-btn" href="{url_esc_td}" download>&#8681;</a><button class="info-btn" onclick="showInfo(this)" data-info='{_info_obj}' title="Detalhes">&#9432;</button></div></td>
                <td title="{title_esc}">{_html_mod.escape(title_disp)}</td>
                <td><span class="category category-{category}">{category}</span></td>
                <td class="{sqli_class}">{sqli_status}</td>
                <td class="{xss_class}">{xss_status}</td>
                <td>{waf_label}</td>
                <td>{size}</td>
            </tr>
""")

        parts.append(f"""        </tbody>
    </table>
    </div>
    <div class="footer">MappingExpo v5.0 &nbsp;|&nbsp; xploits3c &nbsp;|&nbsp; Apenas para pesquisa de segurança autorizada</div>
</div>

<div id="toast"></div>
<div class="info-overlay" id="infoOverlay" onclick="closeInfo()"></div>
<div class="info-popup" id="infoPopup">
  <div class="info-popup-title">
    <span>&#9432; DETALHES DO RESULTADO</span>
    <button class="info-close" onclick="closeInfo()">&#10005;</button>
  </div>
  <div id="infoBody"></div>
</div>

<script>
const EXPORT_DATA = {export_data_js};
const FILE_DATA   = {file_data_js};
const REPORT_BASE = "{report_base}";
</script>

<script>
(function(){{
    const c=document.getElementById('matrix-canvas'),ctx=c.getContext('2d');
    const CH='アイウエオカキクケコ0123456789ABCDEF';
    const FS=14;let cols,drops;
    function resize(){{c.width=window.innerWidth;c.height=window.innerHeight;cols=Math.floor(c.width/FS);drops=Array.from({{length:cols}},()=>Math.random()*-100);}}
    function draw(){{ctx.fillStyle='rgba(0,0,0,0.05)';ctx.fillRect(0,0,c.width,c.height);for(let i=0;i<cols;i++){{const ch=CH[Math.floor(Math.random()*CH.length)];ctx.fillStyle=Math.random()>.95?'#fff':'#00ff41';ctx.font=FS+'px monospace';ctx.fillText(ch,i*FS,drops[i]*FS);if(drops[i]*FS>c.height&&Math.random()>.975)drops[i]=0;drops[i]+=.5+Math.random()*.5;}}}}
    resize();window.addEventListener('resize',resize);setInterval(draw,45);
}})();

const GROUP_CATS={{
  "doc":["documents","archives","backups"],
  "scripts":["scripts","configs","credentials"],
  "page":["webpage"]
}};
const SUB_PRED={{
  "doc-all":()=>true,
  "doc-pdf":(r)=>r.dataset.ext===".pdf",
  "doc-docx":(r)=>[".doc",".docx",".odt"].includes(r.dataset.ext),
  "doc-xlsx":(r)=>[".xls",".xlsx",".ods"].includes(r.dataset.ext),
  "doc-ppt":(r)=>[".ppt",".pptx"].includes(r.dataset.ext),
  "doc-arc":(r)=>[".zip",".rar",".tar",".gz",".7z",".bz2"].includes(r.dataset.ext),
  "sqli-all":(r)=>["vuln","safe","critical"].includes(r.dataset.sqli),
  "sqli-critical":(r)=>r.dataset.sqli==="critical",
  "sqli-vuln":(r)=>["vuln","critical"].includes(r.dataset.sqli),
  "sqli-safe":(r)=>r.dataset.sqli==="safe",
  "xss-all":(r)=>["vuln","safe"].includes(r.dataset.xss),
  "xss-vuln":(r)=>r.dataset.xss==="vuln",
  "xss-safe":(r)=>r.dataset.xss==="safe",
  "scripts-all":()=>true,
  "scripts-php":(r)=>r.dataset.ext===".php",
  "scripts-asp":(r)=>[".asp",".aspx"].includes(r.dataset.ext),
  "scripts-sh":(r)=>[".sh",".bat",".ps1"].includes(r.dataset.ext),
  "scripts-config":(r)=>[".conf",".config",".ini",".yaml",".yml",".json",".xml"].includes(r.dataset.ext),
  "scripts-creds":(r)=>[".env",".git",".svn",".htpasswd"].includes(r.dataset.ext)
}};
let activeGroup="all",activeSub=null;
function closeAllSubMenus(){{document.querySelectorAll('.sub-menu.open').forEach(m=>m.classList.remove('open'));}}
function applyFilter(btn){{
  const group=btn.dataset.group;
  if(btn.classList.contains('has-sub')){{
    if(activeGroup===group){{const m=document.getElementById('sub-'+group);if(m)m.classList.contains('open')?m.classList.remove('open'):m.classList.add('open');return;}}
    activeGroup=group;activeSub=group+'-all';
    document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');
    const menu=document.getElementById('sub-'+group);
    if(menu){{menu.querySelectorAll('.sub-btn').forEach(b=>b.classList.remove('active'));menu.querySelector('.sub-btn').classList.add('active');closeAllSubMenus();menu.classList.add('open');}}
  }}else{{
    closeAllSubMenus();document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');activeGroup=group;activeSub=null;
  }}
  renderRows();updateInfoBar();updateExportCounts();
}}
function applySubFilter(btn,groupId){{
  btn.closest('.sub-menu').querySelectorAll('.sub-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');activeSub=btn.dataset.sub;renderRows();updateInfoBar();updateExportCounts();
}}
function renderRows(){{
  const rows=document.querySelectorAll('#results-tbody tr');
  const pred=activeSub?(SUB_PRED[activeSub]||(()=>true)):(()=>true);
  rows.forEach(row=>{{
    let hide=false;
    if(activeGroup!=='all'){{
      if(activeGroup==='sqli'){{hide=!pred(row);}}
      else if(activeGroup==='xss'){{hide=!pred(row);}}
      else{{const cats=GROUP_CATS[activeGroup]||[];hide=!cats.includes(row.dataset.category||'');if(!hide)hide=!pred(row);}}
    }}
    hide?row.classList.add('hidden'):row.classList.remove('hidden');
    if(!hide)applySearchToRow(row);else row.classList.remove('srch-hidden');
  }});
}}
function buildSubBadges(){{
  const rows=Array.from(document.querySelectorAll('#results-tbody tr'));
  const inG=cats=>r=>cats.includes(r.dataset.category||'');
  const docR=rows.filter(inG(GROUP_CATS['doc']));
  const sqliR=rows.filter(r=>["vuln","safe","critical"].includes(r.dataset.sqli));
  const xssR=rows.filter(r=>["vuln","safe"].includes(r.dataset.xss));
  const scR=rows.filter(inG(GROUP_CATS['scripts']));
  const s=(id,n)=>{{const el=document.getElementById(id);if(el)el.textContent=n;}};
  s('sbadge-doc-all',docR.length);
  s('sbadge-doc-pdf',docR.filter(r=>r.dataset.ext==='.pdf').length);
  s('sbadge-doc-docx',docR.filter(r=>['.doc','.docx','.odt'].includes(r.dataset.ext)).length);
  s('sbadge-doc-xlsx',docR.filter(r=>['.xls','.xlsx','.ods'].includes(r.dataset.ext)).length);
  s('sbadge-doc-ppt',docR.filter(r=>['.ppt','.pptx'].includes(r.dataset.ext)).length);
  s('sbadge-doc-arc',docR.filter(r=>['.zip','.rar','.tar','.gz','.7z','.bz2'].includes(r.dataset.ext)).length);
  s('sbadge-sqli-all',sqliR.length);
  s('sbadge-sqli-critical',sqliR.filter(r=>r.dataset.sqli==='critical').length);
  s('sbadge-sqli-vuln',sqliR.filter(r=>['vuln','critical'].includes(r.dataset.sqli)).length);
  s('sbadge-sqli-safe',sqliR.filter(r=>r.dataset.sqli==='safe').length);
  s('sbadge-xss-all',xssR.length);
  s('sbadge-xss-vuln',xssR.filter(r=>r.dataset.xss==='vuln').length);
  s('sbadge-xss-safe',xssR.filter(r=>r.dataset.xss==='safe').length);
  s('sbadge-scripts-all',scR.length);
  s('sbadge-scripts-php',scR.filter(r=>r.dataset.ext==='.php').length);
  s('sbadge-scripts-asp',scR.filter(r=>['.asp','.aspx'].includes(r.dataset.ext)).length);
  s('sbadge-scripts-sh',scR.filter(r=>['.sh','.bat','.ps1'].includes(r.dataset.ext)).length);
  s('sbadge-scripts-config',scR.filter(r=>['.conf','.config','.ini','.yaml','.yml','.json','.xml'].includes(r.dataset.ext)).length);
  s('sbadge-scripts-creds',scR.filter(r=>['.env','.git','.svn','.htpasswd'].includes(r.dataset.ext)).length);
}}
function updateInfoBar(){{
  const bar=document.getElementById('sub-info');if(!bar)return;
  const visible=document.querySelectorAll('#results-tbody tr:not(.hidden):not(.srch-hidden)').length;
  if(activeGroup==='all'&&!activeSub){{bar.innerHTML='&#10142; Exibindo <span>'+visible+'</span> resultado(s)';return;}}
  const subLabel=(activeSub||'').split('-').slice(1).join(' ').toUpperCase();
  bar.innerHTML='&#10142; Filtro: <span>'+activeGroup.toUpperCase()+'</span> &rsaquo; <span>'+subLabel+'</span> &mdash; <span>'+visible+'</span> resultado(s)';
}}
let activeScopes=new Set(['url','title','category','dork']);
function toggleSearch(){{
  const p=document.getElementById('srchPanel'),t=document.getElementById('srchToggle');
  const open=p.classList.contains('open');closeAllPanels();
  if(!open){{p.classList.add('open');t.classList.add('open');setTimeout(()=>document.getElementById('srchInput').focus(),80);}}
}}
function toggleScope(btn){{
  btn.classList.toggle('active');
  const sc=btn.dataset.scope;
  btn.classList.contains('active')?activeScopes.add(sc):activeScopes.delete(sc);
  doSearch();
}}
function doSearch(){{
  const q=document.getElementById('srchInput').value.trim().toLowerCase();
  const rows=document.querySelectorAll('#results-tbody tr');
  let match=0;
  rows.forEach(row=>{{if(!row.classList.contains('hidden')){{const found=applySearchToRow(row,q);if(found)match++;}}else{{row.classList.remove('srch-hidden');}}}});
  const el=document.getElementById('srchCount');if(el)el.textContent=q?match:'-';
  updateInfoBar();updateExportCounts();
}}
function applySearchToRow(row,q){{
  if(q===undefined)q=(document.getElementById('srchInput').value||'').trim().toLowerCase();
  if(!q){{row.classList.remove('srch-hidden');return true;}}
  let hay='';
  if(activeScopes.has('url'))    hay+=' '+(row.dataset.url||'');
  if(activeScopes.has('title'))  hay+=' '+(row.dataset.title||'');
  if(activeScopes.has('category'))hay+=' '+(row.dataset.category||'');
  if(activeScopes.has('dork'))   hay+=' '+(row.dataset.dork||'');
  const found=hay.toLowerCase().includes(q);
  found?row.classList.remove('srch-hidden'):row.classList.add('srch-hidden');
  return found;
}}
function clearSearch(){{
  document.getElementById('srchInput').value='';
  document.querySelectorAll('#results-tbody tr').forEach(r=>r.classList.remove('srch-hidden'));
  const el=document.getElementById('srchCount');if(el)el.textContent='-';
  updateInfoBar();updateExportCounts();
}}
function toggleExportPanel(){{
  const p=document.getElementById('exportPanel'),t=document.getElementById('exportToggle');
  const open=p.classList.contains('open');closeAllPanels();
  if(!open){{p.classList.add('open');t.classList.add('open');updateExportCounts();}}
}}
function updateExportCounts(){{
  const sqliAll=EXPORT_DATA.filter(r=>["vuln","safe","critical"].includes(r.sqli));
  const sqliVuln=EXPORT_DATA.filter(r=>["vuln","critical"].includes(r.sqli));
  const sqliSafe=EXPORT_DATA.filter(r=>r.sqli==="safe");
  const xssAll=EXPORT_DATA.filter(r=>["vuln","safe"].includes(r.xss));
  const xssVuln=EXPORT_DATA.filter(r=>r.xss==="vuln");
  const xssSafe=EXPORT_DATA.filter(r=>r.xss==="safe");
  const viewIdxs=new Set(Array.from(document.querySelectorAll('#results-tbody tr:not(.hidden):not(.srch-hidden)')).map(r=>parseInt(r.dataset.idx)));
  const s=(id,n)=>{{const el=document.getElementById(id);if(el)el.textContent='('+n+')';}}; 
  s('epCntSqliAll',sqliAll.length);s('epCntSqliVuln',sqliVuln.length);s('epCntSqliSafe',sqliSafe.length);
  s('epCntXssAll',xssAll.length);s('epCntXssVuln',xssVuln.length);s('epCntXssSafe',xssSafe.length);
  s('epCntView',EXPORT_DATA.filter((_,i)=>viewIdxs.has(i)).length);
}}
function _getRows(scope){{
  if(scope==='all')return EXPORT_DATA;
  if(scope==='sqli-all')return EXPORT_DATA.filter(r=>["vuln","safe","critical"].includes(r.sqli));
  if(scope==='sqli-vuln')return EXPORT_DATA.filter(r=>["vuln","critical"].includes(r.sqli));
  if(scope==='sqli-safe')return EXPORT_DATA.filter(r=>r.sqli==="safe");
  if(scope==='xss-all')return EXPORT_DATA.filter(r=>["vuln","safe"].includes(r.xss));
  if(scope==='xss-vuln')return EXPORT_DATA.filter(r=>r.xss==="vuln");
  if(scope==='xss-safe')return EXPORT_DATA.filter(r=>r.xss==="safe");
  if(scope==='view'){{const vis=new Set(Array.from(document.querySelectorAll('#results-tbody tr:not(.hidden):not(.srch-hidden)')).map(r=>parseInt(r.dataset.idx)));return EXPORT_DATA.filter((_,i)=>vis.has(i));}}
  return EXPORT_DATA;
}}
function _scopeLabel(scope){{return{{'all':'all','sqli-all':'sqli_tested','sqli-vuln':'sqli_vuln','sqli-safe':'sqli_safe','xss-all':'xss_tested','xss-vuln':'xss_vuln','xss-safe':'xss_safe','view':'view'}}[scope]||scope;}}
function _download(content,filename,mime){{const blob=new Blob([content],{{type:mime}});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=filename;document.body.appendChild(a);a.click();setTimeout(()=>{{URL.revokeObjectURL(a.href);document.body.removeChild(a);}},100);}}
function _showToast(msg){{const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2200);}}
function doExport(fmt,scope){{
  const rows=_getRows(scope);
  if(!rows.length){{_showToast('Nenhum resultado para exportar.');return;}}
  const ts=new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
  const base=REPORT_BASE+'_links_'+_scopeLabel(scope)+'_'+ts;
  if(fmt==='txt'){{
    const lines=rows.map((r,i)=>{{let s=(i+1)+'. '+r.url+'\\n';if(r.title)s+='   Título: '+r.title+'\\n';if(r.sqli&&r.sqli!=='untested')s+='   SQLi: '+r.sqli.toUpperCase()+'\\n';if(r.xss&&r.xss!=='untested')s+='   XSS: '+r.xss.toUpperCase()+'\\n';s+='   Data/Hora: '+r.timestamp+'\\n';return s;}});
    _download('Exportação MappingExpo\\nEscopo: '+scope+'\\nGerado: '+ts+'\\nTotal: '+rows.length+'\\n\\n'+lines.join('\\n'),base+'.txt','text/plain');
    _showToast('Exportados '+rows.length+' links');
  }}else if(fmt==='json'){{
    _download(JSON.stringify({{meta:{{generated:ts,scope:scope,total:rows.length}},results:rows}},null,2),base+'.json','application/json');
    _showToast('Exportados '+rows.length+' links');
  }}else if(fmt==='csv'){{
    const headers=['url','title','dork','category','ext','sqli','conf','waf','xss','xss_conf','xss_types','timestamp'];
    const esc=v=>{{const s=String(v??'');return s.includes(',')||s.includes('"')||s.includes('\\n')?'"'+s.replace(/"/g,'""')+'"':s;}};
    _download([headers.join(','),...rows.map(r=>headers.map(h=>esc(r[h]||'')).join(','))].join('\\r\\n'),base+'.csv','text/csv');
    _showToast('Exportados '+rows.length+' links');
  }}
}}
function toggleFilesPanel(){{
  const p=document.getElementById('filesPanel'),t=document.getElementById('filesToggle');
  const open=p.classList.contains('open');closeAllPanels();
  if(!open){{p.classList.add('open');t.classList.add('open');updateSelCount();}}
}}
function updateSelCount(){{const n=document.querySelectorAll('.file-chk:checked').length;const el=document.getElementById('selCount');if(el)el.textContent=n;}}
function selectAllFiles(val){{document.querySelectorAll('.file-chk').forEach(c=>c.checked=val);updateSelCount();}}
function exportSelectedFiles(fmt){{
  const checked=Array.from(document.querySelectorAll('.file-chk:checked'));
  if(!checked.length){{_showToast('Nenhum arquivo selecionado.');return;}}
  const rows=checked.map(c=>FILE_DATA[parseInt(c.dataset.fidx)]).filter(Boolean);
  const ts=new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
  const base=REPORT_BASE+'_files_selected_'+ts;
  if(fmt==='list'){{
    const lines=rows.map((r,i)=>(i+1)+'. '+r.url+'\\n   Categoria: '+r.category+'\\n   Tamanho: '+r.size_str+'\\n');
    _download('Lista de Arquivos MappingExpo\\nGerado: '+ts+'\\n\\n'+lines.join('\\n'),base+'.txt','text/plain');
    _showToast('Lista de arquivos ('+rows.length+') exportada');
  }}else if(fmt==='json'){{
    _download(JSON.stringify({{meta:{{generated:ts,total:rows.length}},files:rows}},null,2),base+'.json','application/json');
    _showToast('Lista de arquivos ('+rows.length+') exportada');
  }}
}}
function closeAllPanels(){{
  ['srchPanel','exportPanel','filesPanel'].forEach(id=>document.getElementById(id).classList.remove('open'));
  ['srchToggle','exportToggle','filesToggle'].forEach(id=>document.getElementById(id).classList.remove('open'));
}}
document.addEventListener('click',(e)=>{{
  if(!e.target.closest('.filter-group')&&!e.target.closest('.filter-btn[data-group]'))closeAllSubMenus();
  if(!e.target.closest('.srch-wrap')&&!e.target.closest('.export-wrap')&&!e.target.closest('.files-wrap'))closeAllPanels();
}});
buildSubBadges();updateInfoBar();updateExportCounts();updateSelCount();
let _infoOpen=false;
function showInfo(btn){{
  const d=JSON.parse(btn.getAttribute('data-info'));
  const sqliColor=d.sqli&&d.sqli.startsWith('VULN')?'#ff3333':d.sqli==='SAFE'?'#00ff41':d.sqli.startsWith('VULNERABLE')?'#ff00ff':'#444';
  const xssColor=d.xss&&d.xss.startsWith('VULN')?'#ffaa00':d.xss==='SAFE'?'#00ff41':'#444';
  let rows='';
  const row=(lbl,val,color)=>val?`<div class="info-row"><span class="info-lbl">${{lbl}}</span><span class="info-val" style="color:${{color||'#00aaff'}}">${{val}}</span></div>`:'';
  rows+=row('URL',d.url.length>80?d.url.slice(0,80)+'...':d.url);
  rows+=row('Título',d.title);rows+=row('Categoria',d.category,'#00cc88');rows+=row('Extensão',d.ext,'#ffaa00');
  rows+=row('Tamanho',d.size,'#009922');rows+=row('Data/Hora',d.ts,'#666');rows+=row('Dork',d.dork&&d.dork.length>80?d.dork.slice(0,80)+'...':d.dork,'#cc88ff');
  rows+=row('Trecho',d.snippet&&d.snippet.length>120?d.snippet.slice(0,120)+'...':d.snippet,'#777');
  if(d.sqli)rows+=row('SQLi',d.sqli,sqliColor);if(d.payload)rows+=row('Método SQLi',d.payload.length>100?d.payload.slice(0,100)+'...':d.payload,'#ff6666');
  if(d.xss)rows+=row('XSS',d.xss,xssColor);if(d.xss_det)rows+=row('Detalhe XSS',d.xss_det.length>100?d.xss_det.slice(0,100)+'...':d.xss_det,'#ffcc66');
  if(d.waf)rows+=row('WAF','! '+d.waf,'#ffaa00');
  document.getElementById('infoBody').innerHTML=rows||'<span style="color:#444">Sem detalhes.</span>';
  document.getElementById('infoPopup').classList.add('open');
  document.getElementById('infoOverlay').classList.add('open');
  _infoOpen=true;document.body.style.overflow='hidden';
}}
function closeInfo(){{document.getElementById('infoPopup').classList.remove('open');document.getElementById('infoOverlay').classList.remove('open');document.body.style.overflow='';_infoOpen=false;}}
document.addEventListener('keydown',(e)=>{{if(_infoOpen&&e.key==='Escape')closeInfo();}});
</script>
</body>
</html>""")

        html = "".join(parts)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)

    def _format_size(self, size):
        """Formata uma contagem de bytes em string legível."""
        if size is None:
            return "N/A"
        try:
            size = float(size)
        except (TypeError, ValueError):
            return "N/A"
        if size < 0:
            return "N/A"
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def print_statistics(self):
        """Imprime uma tabela de estatísticas formatada com Rich."""
        table = Table(title="", show_header=False, box=None, padding=(0, 2))
        table.add_column("Métrica", style="cyan")
        table.add_column("Valor",  style="green", justify="right")
        console.print("\n[bold yellow]┌─[ Estatísticas de Busca ][/bold yellow]")
        console.print("[bold yellow]│[/bold yellow]")
        table.add_row("├─> Total de resultados encontrados", str(self.stats.get("total_found", 0)))
        table.add_row("├─> Resultados únicos",      str(len(self.results)))
        table.add_row("├─> Duplicados removidos",  str(self.stats.get("duplicates", 0)))
        table.add_row("├─> Na lista negra",         str(self.stats.get("blacklisted", 0)))
        if self.config.get("sqli_detection", False):
            table.add_row("├─> Vulnerabilidades SQLi", f"[bold red]{self.stats.get('sqli_vulnerable', 0)}[/bold red]")
            table.add_row("├─> WAF detectado",          f"[bold yellow]{self.stats.get('waf_detected', 0)}[/bold yellow]")
        if self.config.get("xss_detection", False):
            table.add_row("├─> Vulnerabilidades XSS",  f"[bold yellow]{self.stats.get('xss_vulnerable', 0)}[/bold yellow]")
        table.add_row("└─> Tempo de execução", f"{round(time.time() - self.start_time, 2)}s")
        console.print(table)
        categories = {k.replace("category_", ""): v for k, v in self.stats.items() if k.startswith("category_")}
        if categories:
            cat_table = Table(title="", show_header=False, box=None, padding=(0, 2))
            cat_table.add_column("Categoria", style="cyan")
            cat_table.add_column("Contagem", style="green", justify="right")
            console.print("\n[bold yellow]┌─[ Resultados por Categoria ][/bold yellow]")
            console.print("[bold yellow]│[/bold yellow]")
            sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)
            for i, (category, count) in enumerate(sorted_cats):
                prefix = "└─>" if i == len(sorted_cats) - 1 else "├─>"
                cat_table.add_row(f"{prefix} {category.capitalize()}", str(count))
            console.print(cat_table)


# ══════════════════════════════════════════════════════════════
#  Funções auxiliares
# ══════════════════════════════════════════════════════════════

def _load_results_from_file(path: str) -> List[Dict]:
    """Carrega resultados do MappingExpo de um arquivo .json ou .txt."""
    p = Path(path)
    if not p.exists():
        alt = Path(__file__).parent / "Dump" / path
        if alt.exists():
            p = alt
    if not p.exists():
        console.print(f"[red][!] Arquivo não encontrado: {path}[/red]")
        return []

    ext = p.suffix.lower()
    try:
        if ext == ".json":
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "results" in data:
                return data["results"]
            console.print(f"[red][!] Estrutura JSON não reconhecida em {path}[/red]")
            return []
        elif ext == ".txt":
            results = []
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and line.startswith("http"):
                        results.append({"url": line, "title": "", "snippet": "",
                                        "dork": "", "timestamp": "", "extension": "",
                                        "category": "webpage"})
            return results
        else:
            console.print(f"[red][!] Formato de arquivo não suportado: {ext} (use .json ou .txt)[/red]")
            return []
    except Exception as e:
        console.print(f"[red][!] Erro ao carregar arquivo '{path}': {e}[/red]")
        return []


def load_config(config_file: str = None) -> Dict:
    """Carrega e mescla um arquivo de config YAML ou JSON com o DEFAULT_CONFIG."""
    if not config_file:
        return DEFAULT_CONFIG.copy()
    try:
        with open(config_file, 'r') as f:
            user_config = json.load(f) if config_file.endswith('.json') else yaml.safe_load(f)
        config = DEFAULT_CONFIG.copy()
        config.update(user_config)
        return config
    except Exception as e:
        console.print(f"[red][!] Erro ao carregar config: {e}[/red]")
        console.print("[yellow][!] Usando configuração padrão[/yellow]")
        return DEFAULT_CONFIG.copy()


def create_sample_config():
    """Grava um mappingexpo_config.yaml de exemplo em disco."""
    config_yaml = """# Configuração do MappingExpo

extensions:
  documents: [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"]
  archives: [".zip", ".rar", ".tar", ".gz", ".7z"]
  databases: [".sql", ".db", ".sqlite", ".mdb"]
  backups: [".bak", ".backup", ".old"]
  configs: [".conf", ".config", ".ini", ".yaml", ".yml", ".json", ".xml"]
  scripts: [".php", ".asp", ".jsp", ".sh"]
  credentials: [".env", ".git", ".htpasswd"]

blacklist: []
whitelist: []
analyze_files: true
sqli_detection: false
http_fingerprinting: true
stealth_mode: false
request_timeout: 10
max_retries: 3
user_agent_rotation: true
extended_delay_every_n_results: 100
"""
    with open("mappingexpo_config.yaml", "w") as f:
        f.write(config_yaml)
    console.print("[green][✓] Config de exemplo criada: mappingexpo_config.yaml[/green]")


def resolve_templates_argument(template_arg):
    """Resolve o argumento --templates para uma lista de objetos Path."""
    templates_dir = Path(__file__).parent / "Templates"
    if template_arg is None:
        return [templates_dir / "dorks_templates.yaml"]
    if template_arg.lower() == "all":
        yaml_files = list(templates_dir.glob("*.yaml"))
        if not yaml_files:
            console.print("[red][!] Nenhum arquivo de template encontrado no diretório Templates[/red]")
            sys.exit(1)
        return yaml_files
    specific_path = templates_dir / template_arg
    if not specific_path.exists():
        console.print(f"[red][!] Template não encontrado: {template_arg}[/red]")
        sys.exit(1)
    return [specific_path]


def get_categories_from_templates(template_files) -> List[str]:
    """Retorna uma lista ordenada de nomes de categorias encontradas em todos os arquivos YAML de template fornecidos."""
    categories = set()
    for template_file in template_files:
        try:
            with open(template_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "templates" in data:
                    categories.update(data["templates"].keys())
        except Exception as e:
            console.print(f"[yellow][!] Não foi possível ler categorias de {template_file}: {e}[/yellow]")
    return sorted(categories)


# ══════════════════════════════════════════════════════════════
#  WIZARD
# ══════════════════════════════════════════════════════════════

def run_wizard():
    """Executa a sessão interativa guiada do wizard."""
    print_banner()
    console.print(Panel(
        "[bold green]Wizard interativo[/bold green] — Navegue com números, ENTER para confirmar\n"
        "[dim]Pressione Ctrl+C a qualquer momento para abortar[/dim]",
        border_style="green",
        title="[bold yellow][ MappingExpo Wizard ][/bold yellow]"
    ))

    def ask_yes_no(prompt: str, default_yes: bool = False) -> bool:
        hint = "[Y/n]" if default_yes else "[y/N]"
        console.print(f"[cyan]{prompt} {hint}:[/cyan] ", end="")
        try:
            ans = input("").strip().lower()
        except KeyboardInterrupt:
            return default_yes
        return default_yes if ans == "" else ans in ("y", "yes")

    def ask_choice(prompt: str, options: list, default: int = 0) -> int:
        for i, opt in enumerate(options, 1):
            marker = "[bold green]>[/bold green]" if i - 1 == default else " "
            console.print(f"  {marker} [yellow]{i})[/yellow] {opt}")
        console.print(f"[cyan]{prompt} (padrão {default+1}):[/cyan] ", end="")
        try:
            raw = input("").strip()
            idx = int(raw) - 1
            return idx if 0 <= idx < len(options) else default
        except (ValueError, KeyboardInterrupt):
            return default

    def ask_string(prompt: str, placeholder: str = "") -> str:
        display = f" [dim](ex.: {placeholder})[/dim]" if placeholder else ""
        console.print(f"[cyan]{prompt}{display}:[/cyan] ", end="")
        try:
            return input("").strip()
        except KeyboardInterrupt:
            return ""

    def ask_extensions(prompt: str) -> list:
        raw = ask_string(prompt, ".pdf .doc .zip")
        if not raw:
            return []
        return [ext if ext.startswith(".") else f".{ext}" for ext in raw.split()]

    def pick_output() -> str:
        output = ask_string("Nome do arquivo de saída", "results.json")
        if not output:
            return None
        if "." in os.path.basename(output):
            return output
        console.print("\n[bold cyan]Formato de saída:[/bold cyan]")
        fmt_idx = ask_choice("Escolha o formato", ["JSON", "CSV", "HTML", "TXT"])
        fmts    = [".json", ".csv", ".html", ".txt"]
        return output + fmts[fmt_idx]

    def collect_run_options(config: dict, ask_count: bool = True) -> tuple:
        console.print("\n[bold cyan]┌─[ OPÇÕES DE EXECUÇÃO ][/bold cyan]")
        console.print("[bold cyan]│[/bold cyan]")
        count = 50
        if ask_count:
            count_str = ask_string("│  Resultados por dork", "padrão 50")
            count     = int(count_str) if count_str.isdigit() else 50
            console.print("[bold cyan]│[/bold cyan]")
        config["sqli_detection"]      = ask_yes_no("│  Ativar detecção SQLi?")
        config["xss_detection"]       = ask_yes_no("│  Ativar detecção XSS?")
        if config["xss_detection"]:
            console.print("[bold cyan]│[/bold cyan]  Tipo de XSS: 1)all 2)reflected 3)stored 4)dom")
            _xtype_idx = ask_choice("│  Tipo de XSS", ["all", "reflected", "stored", "dom"])
            config["xss_type"] = ["all", "reflected", "stored", "dom"][_xtype_idx]
        config["stealth_mode"]        = ask_yes_no("│  Ativar modo stealth?")
        config["http_fingerprinting"] = not ask_yes_no("│  Desativar fingerprinting HTTP?")
        config["analyze_files"]       = not ask_yes_no("│  Desativar análise de arquivos?")
        if ask_yes_no("│  Definir blacklist de extensões?"):
            config["blacklist"] = ask_extensions("│    Extensões da blacklist")
        if ask_yes_no("│  Definir whitelist de extensões?"):
            config["whitelist"] = ask_extensions("│    Extensões da whitelist")
        do_dbscan = ask_yes_no("│  Ativar varredura de portas DB (DBScan)?") if _DBSCAN_AVAILABLE else False
        if not _DBSCAN_AVAILABLE:
            console.print("[bold cyan]│[/bold cyan]  [dim]DBScan indisponível — db_portscan.py ausente[/dim]")
        console.print("[bold cyan]└─>[/bold cyan]")
        return count, do_dbscan

    def _ask_analyze(output: str) -> bool:
        if not output:
            return False
        if not str(output).lower().endswith(".json"):
            return False
        if not _ANALYZE_AVAILABLE:
            return False
        console.print("\n[bold cyan]┌─[ ANÁLISE DE RESULTADOS ][/bold cyan]")
        console.print("[bold cyan]│[/bold cyan]  prioridade de triage · segredos · credenciais · relatório HTML")
        try:
            console.print("[bold cyan]│  Executar análise nos resultados? y/N:[/bold cyan] ", end="")
            ans = input("").strip().lower() in ("y", "yes")
        except KeyboardInterrupt:
            ans = False
        if ans:
            console.print("[bold cyan]└─>[/bold cyan] [green]Análise ativada.[/green]\n")
        else:
            console.print("[bold cyan]└─>[/bold cyan] [dim]Análise pulada.[/dim]\n")
        return ans

    def _run_analyze(results: list, output: str) -> None:
        if not results or not _ANALYZE_AVAILABLE:
            return
        ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_out = str(output).replace(".json", f"_analysis_{ts}.html")
        console.print(f"\n[bold cyan][Agents] Iniciando análise em {len(results)} resultado(s)...[/bold cyan]")
        _wiz_args = type("A", (), {
            "analyze_fetch":          False,
            "analyze_fetch_max":      20,
            "analyze_no_llm_triage":  False,
            "analyze_report":         True,
            "analyze_fmt":            "html",
            "analyze_out":            report_out,
        })()
        try:
            out = _run_agents_pipeline(results=results, llm_plugin=None, args=_wiz_args)
            if out.get("report_path"):
                console.print(f"[bold green][✓] Relatório de análise → {out['report_path']}[/bold green]")
            n_sec = out.get("secrets_total", 0)
            if n_sec:
                console.print(f"[bold red][!] {n_sec} segredo(s) detectado(s).[/bold red]")
        except Exception as _ae:
            console.print(f"[yellow][Agents] Erro: {_ae}[/yellow]")

    def _ask_crawl() -> dict | None:
        if not _ANALYZE_AVAILABLE:
            return None
        console.print("\n[bold cyan]┌─[ CRAWL RECURSIVO ][/bold cyan]")
        console.print("[bold cyan]│[/bold cyan]  [dim](refinando dorks com base em: domínios · caminhos · tecnologias)[/dim]")
        try:
            console.print("[bold cyan]│  Ativar crawl recursivo? y/N:[/bold cyan] ", end="")
            ans = input("").strip().lower() in ("y", "yes")
        except KeyboardInterrupt:
            ans = False
        if not ans:
            console.print("[bold cyan]└─>[/bold cyan] [dim]Crawl pulado.[/dim]\n")
            return None
        console.print("[bold cyan]│[/bold cyan]")
        rounds_idx = ask_choice("Rodadas", [
            "2  [dim]— rápido[/dim]",
            "4  [dim]— equilibrado (padrão)[/dim]",
            "6  [dim]— minucioso[/dim]",
            "10 [dim]— máximo[/dim]",
        ], default=1)
        rounds_map = [2, 4, 6, 10]
        rounds     = rounds_map[rounds_idx]
        console.print("[bold cyan]│[/bold cyan]")
        stealth   = ask_yes_no("│  Modo stealth para o crawl? ")
        console.print("[bold cyan]│[/bold cyan]")
        do_report = ask_yes_no("│  Gerar relatório HTML ao final do crawl?", default_yes=True)
        console.print(f"[bold cyan]└─>[/bold cyan] [green]Crawl ativado — {rounds} rodada(s)[/green]\n")
        return {"rounds": rounds, "stealth": stealth, "do_report": do_report, "max": 300, "per_dork": 20}

    def _run_crawl_wizard(seed_dorks: list, crawl_opts: dict, output: str) -> None:
        if not crawl_opts or not _ANALYZE_AVAILABLE:
            return
        ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = None
        if crawl_opts["do_report"]:
            base        = os.path.splitext(output)[0] if output else f"mappingexpo_crawl_{ts}"
            report_path = f"{base}_crawl_{ts}.html"
        _crawl_args = type("A", (), {
            "crawl_rounds":   crawl_opts["rounds"],
            "crawl_max":      crawl_opts["max"],
            "crawl_per_dork": crawl_opts["per_dork"],
            "crawl_stealth":  crawl_opts["stealth"],
            "crawl_report":   crawl_opts["do_report"],
            "crawl_out":      report_path,
        })()
        console.print(f"\n[bold cyan][Crawl] Iniciando crawl recursivo — máximo de {crawl_opts['rounds']} rodada(s)[/bold cyan]")
        try:
            crawl_out = run_crawl(seed_dorks=seed_dorks, args=_crawl_args, target="")
            console.print(
                f"[bold green][Crawl] Concluído — "
                f"{crawl_out.get('rounds', 0)} rodada(s) · "
                f"{len(crawl_out.get('results', []))} resultado(s)[/bold green]"
            )
            if crawl_out.get("report_path"):
                console.print(f"[bold green][✓] Relatório do crawl → {crawl_out['report_path']}[/bold green]")
        except Exception as _ce:
            console.print(f"[yellow][Crawl] Erro: {_ce}[/yellow]")

    MAIN_MENU = [
        ("Busca de Google Dorks",   "Buscar no DuckDuckGo com dork(s)"),
        ("Gerador de Dorks",       "Gerar dorks automaticamente a partir de templates"),
        ("Criar config de exemplo", "Gravar mappingexpo_config.yaml em disco"),
        ("Sair",                 ""),
    ]

    while True:
        console.print("\n[bold cyan]┌─[ MENU PRINCIPAL ][/bold cyan]")
        for i, (label, desc) in enumerate(MAIN_MENU, 1):
            hint = f"  [dim]{desc}[/dim]" if desc else ""
            console.print(f"[bold cyan]│[/bold cyan]  [yellow]{i})[/yellow] {label}{hint}")
        console.print("[bold cyan]└─>[/bold cyan] ", end="")

        try:
            choice = input("").strip()
        except KeyboardInterrupt:
            console.print("\n[red]Abortado.[/red]")
            return

        if choice == "3":
            create_sample_config()
            continue

        if choice == "4":
            EXIT_MESSAGES = [
                ("Logs não mentem. Nós também não.", "dim"),
                ("Permaneça fantasma.", "bold cyan"),
                ("Cubra seus rastros.", "bold cyan"),
                ("Boa caçada.", "bold green"),
            ]
            msg, color = random.choice(EXIT_MESSAGES)
            console.print(f"[{color}]{msg}[/{color}]")
            return

        config = load_config(None)

        if choice == "1":
            console.print("\n[bold cyan]┌─[ BUSCA DE GOOGLE DORKS ][/bold cyan]")
            console.print("[bold cyan]│[/bold cyan]  [yellow]0)[/yellow] [dim]← Voltar[/dim]")
            console.print("[bold cyan]│[/bold cyan]  [yellow]1)[/yellow] Dork único")
            console.print("[bold cyan]│[/bold cyan]  [yellow]2)[/yellow] Carregar de arquivo")
            console.print("[bold cyan]└─>[/bold cyan] ", end="")
            try:
                sub = input("").strip()
            except KeyboardInterrupt:
                console.print("\n[red]Abortado.[/red]")
                return
            if sub == "0":
                continue
            if sub == "1":
                dork_input = ask_string("Informe o dork")
                if not dork_input:
                    console.print("[red][!] Dork vazio.[/red]")
                    continue
            elif sub == "2":
                dork_input = ask_string("ex.: dorks.txt")
                if not os.path.isfile(dork_input):
                    console.print(f"[red][!] Arquivo não encontrado: {dork_input}[/red]")
                    continue
            else:
                console.print("[red][!] Opção inválida.[/red]")
                continue

            count, do_dbscan = collect_run_options(config, ask_count=True)
            output      = pick_output()
            do_analyze  = _ask_analyze(output)
            crawl_opts  = _ask_crawl()

            mappingexpo = MappingExpo(config, output)
            dorks   = mappingexpo.process_dorks(dork_input)
            console.print(f"\n[bold cyan]┌─[ CARREGADOS {len(dorks)} DORK(S) ][/bold cyan]")
            console.print("[bold cyan]└─>[/bold cyan] Iniciando...\n")
            try:
                mappingexpo.run_search(dorks, count)
            except KeyboardInterrupt:
                console.print("\n[red][!] Busca interrompida.[/red]")
            mappingexpo.print_statistics()
            if output:
                console.print(f"\n[bold green][✓] Resultados salvos em: {output}[/bold green]")
            if do_analyze and mappingexpo.results:
                _run_analyze(mappingexpo.results, output)
            if crawl_opts and dorks:
                _run_crawl_wizard(dorks, crawl_opts, output or "")
            if do_dbscan and mappingexpo.results:
                console.print(
                    f"\n[bold cyan]┌─[ VARREDURA DE PORTAS DB ][/bold cyan]"
                    f"\n[bold cyan]└─>[/bold cyan] Iniciando em {len(mappingexpo.results)} resultado(s)...\n"
                )
                try:
                    _db_wiz = DBPortScanAgent(timeout=2.5, threads=60, ports=None, max_hosts=200)
                    _db_wiz_report = _db_wiz.run(mappingexpo.results)
                    if _db_wiz_report:
                        _db_wiz_report.print_summary()
                        _dump_dir_wiz  = Path(__file__).parent / "Dump"
                        _db_wiz_base   = str(_dump_dir_wiz / str(output)) if output else str(_dump_dir_wiz / "mappingexpo_dbscan.json")
                        _db_wiz_saved  = save_dbscan_report(_db_wiz_report, _db_wiz_base)
                        console.print(f"[bold green][✓] Relatório DBScan → {_db_wiz_saved}[/bold green]")
                except KeyboardInterrupt:
                    console.print("\n[yellow][DBScan] Interrompido pelo usuário.[/yellow]")
                except Exception as _dbe_wiz:
                    console.print(f"[yellow][DBScan] Erro: {_rich_escape(str(_dbe_wiz))}[/yellow]")
            continue

        if choice == "2":
            console.print("\n[bold cyan]┌─[ GERADOR DE DORKS ][/bold cyan]")
            console.print("[bold cyan]│[/bold cyan]  [yellow]0)[/yellow] [dim]← Voltar[/dim]")
            console.print("[bold cyan]│[/bold cyan]  [yellow]1)[/yellow] Template padrão")
            console.print("[bold cyan]│[/bold cyan]  [yellow]2)[/yellow] Todos os templates")
            console.print("[bold cyan]│[/bold cyan]  [yellow]3)[/yellow] Arquivo de template específico")
            console.print("[bold cyan]└─>[/bold cyan] ", end="")
            try:
                tmpl_choice = input("").strip()
            except KeyboardInterrupt:
                console.print("\n[red]Abortado.[/red]")
                return
            if tmpl_choice == "0":
                continue
            if tmpl_choice == "1":
                template_files = resolve_templates_argument(None)
            elif tmpl_choice == "2":
                template_files = resolve_templates_argument("all")
            elif tmpl_choice == "3":
                tmpl_name = ask_string("Nome do arquivo de template", "dorks_templates.yaml")
                if not tmpl_name:
                    console.print("[red][!] Nenhum nome de arquivo informado.[/red]")
                    continue
                template_files = resolve_templates_argument(tmpl_name)
            else:
                console.print("[red][!] Opção inválida.[/red]")
                continue

            VALID_CATEGORIES = get_categories_from_templates(template_files)
            if not VALID_CATEGORIES:
                console.print("[red][!] Nenhuma categoria encontrada.[/red]")
                continue

            console.print("\n[bold cyan]┌─[ CATEGORIA ][/bold cyan]")
            console.print("[bold cyan]│[/bold cyan]  [yellow]0)[/yellow] TODAS as categorias")
            for i, cat in enumerate(VALID_CATEGORIES, 1):
                console.print(f"[bold cyan]│[/bold cyan]  [yellow]{i})[/yellow] {cat}")
            console.print("[bold cyan]└─>[/bold cyan] ", end="")
            try:
                cat_choice = input("").strip()
            except KeyboardInterrupt:
                console.print("\n[red]Abortado.[/red]")
                return
            if cat_choice == "0":
                selected_categories = VALID_CATEGORIES
            else:
                try:
                    idx                 = int(cat_choice) - 1
                    selected_categories = [VALID_CATEGORIES[idx]]
                except (ValueError, IndexError):
                    console.print("[red][!] Seleção inválida.[/red]")
                    continue

            mode_idx = ask_choice("Modo", ["soft", "medium", "aggressive"])
            mode     = VALID_MODES[mode_idx]
            _, do_dbscan = collect_run_options(config, ask_count=False)
            output      = pick_output()
            do_analyze  = _ask_analyze(output)
            crawl_opts  = _ask_crawl()

            all_dorks = []
            for template_file in template_files:
                generator = DorkGenerator(str(template_file))
                all_dorks.extend(generator.generate(categories=selected_categories, mode=mode))

            console.print(f"\n[cyan][*] {len(all_dorks)} dorks gerados (modo: {mode})[/cyan]")
            mappingexpo = MappingExpo(config, output)
            try:
                mappingexpo.run_search(all_dorks, 50)
            except KeyboardInterrupt:
                console.print("\n[red][!] Busca interrompida.[/red]")
            mappingexpo.print_statistics()
            if output:
                console.print(f"\n[bold green][✓] Resultados salvos em: {output}[/bold green]")
            if do_analyze and mappingexpo.results:
                _run_analyze(mappingexpo.results, output)
            if crawl_opts and all_dorks:
                _run_crawl_wizard(all_dorks, crawl_opts, output or "")
            if do_dbscan and mappingexpo.results:
                console.print(
                    f"\n[bold cyan]┌─[ VARREDURA DE PORTAS DB ][/bold cyan]"
                    f"\n[bold cyan]└─>[/bold cyan] Iniciando em {len(mappingexpo.results)} resultado(s)...\n"
                )
                try:
                    _db_wiz2 = DBPortScanAgent(timeout=2.5, threads=60, ports=None, max_hosts=200)
                    _db_wiz2_report = _db_wiz2.run(mappingexpo.results)
                    if _db_wiz2_report:
                        _db_wiz2_report.print_summary()
                        _dump_dir_wiz2  = Path(__file__).parent / "Dump"
                        _db_wiz2_base   = str(_dump_dir_wiz2 / str(output)) if output else str(_dump_dir_wiz2 / "mappingexpo_dbscan.json")
                        _db_wiz2_saved  = save_dbscan_report(_db_wiz2_report, _db_wiz2_base)
                        console.print(f"[bold green][✓] Relatório DBScan → {_db_wiz2_saved}[/bold green]")
                except KeyboardInterrupt:
                    console.print("\n[yellow][DBScan] Interrompido pelo usuário.[/yellow]")
                except Exception as _dbe_wiz2:
                    console.print(f"[red][DBScan] Erro: {_rich_escape(str(_dbe_wiz2))}[/red]")
            continue

        console.print("[red][!] Opção inválida.[/red]")


# ══════════════════════════════════════════════════════════════
#  PRINCIPAL
# ══════════════════════════════════════════════════════════════

def main():
    """Ponto de entrada."""
    if "--wizard" in sys.argv:
        greet_user()
        run_wizard()
        return

    # ── Interface Web ────────────────────────────────────────────────────────────────
    # Verificado antes do argparse para não consumir --port / --no-browser
    if "--ui" in sys.argv:
        # mappingexpo_web.py está localizado em Tools/, que já está no sys.path
        try:
            from mappingexpo_web import launch_web
        except ImportError:
            console.print(
                "[red][!] mappingexpo_web.py não encontrado em Tools/.[/red]\n"
                "[dim]    Certifique-se de que o arquivo existe em MappingExpo/Tools/mappingexpo_web.py[/dim]\n"
                "[dim]    e de que o Flask está instalado:  pip install flask[/dim]"
            )
            sys.exit(1)

        # Lê --port e --no-browser se presentes, ignora o resto
        import argparse as _ap_ui
        _ui_p = _ap_ui.ArgumentParser(add_help=False)
        _ui_p.add_argument("--port",       type=int, default=8080)
        _ui_p.add_argument("--no-browser", action="store_true")
        _ui_known, _ = _ui_p.parse_known_args()
        launch_web(start_port=_ui_known.port, no_browser=_ui_known.no_browser)
        return
    # ─────────────────────────────────────────────────────────────────────────

    greet_user()

    parser = argparse.ArgumentParser(
        description="MappingExpo v5.0 | Ferramenta de Dorking (OSINT)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Exemplos:
  %(prog)s --ui                 # Web Console (8080)
  %(prog)s --ui --port          # Ex.: 9090
  %(prog)s --wizard
  %(prog)s -d "site:example.com filetype:pdf" -o results.json
  %(prog)s -d dorks.txt -c 100 -o output.html
  %(prog)s -u "https://example.com/page.php?id=1" --sqli --xss
  %(prog)s -f Dump/results.json --sqli --xss -o retest.json
  %(prog)s --dg=all --sqli --xss -o full_scan.json
  %(prog)s --dg=all --dbscan -o results.json
  %(prog)s --dg=all --sqli --dbscan -o full_scan.json
  %(prog)s --dg=all --dbscan --dbscan-timeout 3 --dbscan-threads 80
"""
    )

    parser.add_argument("--wizard",          action="store_true")
    parser.add_argument("--ui",             action="store_true",
                        help="Abre o Console Web (http://127.0.0.1:8080)")
    parser.add_argument("--port",           type=int, default=8080,
                        help="Porta do Console Web (padrão: 8080)")
    parser.add_argument("-d", "--dork",      help="Dork único ou arquivo contendo dorks")
    parser.add_argument("-u", "--url",       help="URL direta para testar")
    parser.add_argument("-f", "--file",      help="Carrega resultados de arquivo .json ou .txt")
    parser.add_argument("-o", "--output",    help="Nome do arquivo de saída")
    parser.add_argument("-c", "--count",     type=int, default=50)
    parser.add_argument("--config",          help="Arquivo de configuração")
    parser.add_argument("--no-analyze",      action="store_true")
    parser.add_argument("--sqli",            action="store_true")
    parser.add_argument("--xss",             action="store_true")
    parser.add_argument("--xss-type",        choices=["reflected","stored","dom","all"], default="all")
    parser.add_argument("--stealth",         action="store_true")
    parser.add_argument("--no-fingerprint",  action="store_true")
    parser.add_argument("--templates",       type=str)
    parser.add_argument("--dg",              action="append", nargs="?", const="all")
    parser.add_argument("--dg-max",          type=int, default=800)
    parser.add_argument("--mode",            nargs="?", const="soft", default="soft")
    parser.add_argument("--blacklist",       nargs="+")
    parser.add_argument("--whitelist",       nargs="+")
    parser.add_argument("--create-config",   action="store_true")
    parser.add_argument("--analyze",         action="store_true")
    parser.add_argument("--analyze-fetch",   action="store_true")
    parser.add_argument("--analyze-fetch-max", type=int, default=20)
    parser.add_argument("--analyze-fmt",     choices=["html","md","json","txt"], default="html")
    parser.add_argument("--analyze-out",     type=str, default=None)
    add_crawler_args(parser)
    # ── DB Port Scanner ───────────────────────────────────────────────────────
    parser.add_argument("--dbscan",          action="store_true",
                        help="Escaneia portas DB abertas em hosts encontrados pelos dorks")
    parser.add_argument("--dbscan-threads",  type=int, default=60,
                        help="Threads de trabalho por host para a varredura DB (padrão: 60)")
    parser.add_argument("--dbscan-timeout",  type=float, default=2.5,
                        help="Timeout de conexão TCP em segundos (padrão: 2.5)")
    parser.add_argument("--dbscan-ports",    type=int, nargs="+", default=None,
                        help="Sobrepõe as portas DB a escanear (padrão: todas as portas DB conhecidas)")
    parser.add_argument("--dbscan-max-hosts",type=int, default=200,
                        help="Máximo de hosts únicos a escanear (padrão: 200)")
    # ─────────────────────────────────────────────────────────────────────────

    args = parser.parse_args()

    for arg in sys.argv:
        if arg.startswith("--templates") and not arg.startswith("--templates="):
            console.print("[red][!] Use o formato --templates=arquivo.yaml[/red]")
            sys.exit(1)

    VALID_CATEGORIES: List[str] = []
    if args.dg or args.templates:
        template_files_for_validation = resolve_templates_argument(args.templates)
        VALID_CATEGORIES = get_categories_from_templates(template_files_for_validation)
        if not VALID_CATEGORIES and args.dg:
            parser.error("Nenhuma categoria encontrada nos arquivos de template.")

    selected_categories = None
    if args.dg:
        if len(args.dg) > 1:
            parser.error("Múltiplos argumentos --dg não são permitidos.")
        dg_value = args.dg[0]
        if dg_value == "all":
            selected_categories = VALID_CATEGORIES
        else:
            if dg_value not in VALID_CATEGORIES:
                parser.error(f"Categoria inválida '{dg_value}'. Disponíveis: {', '.join(VALID_CATEGORIES)}")
            selected_categories = [dg_value]

    if args.mode not in VALID_MODES:
        parser.error(f"Modo inválido '{args.mode}'. Disponíveis: {', '.join(VALID_MODES)}")

    print_banner()

    if args.create_config:
        create_sample_config()
        return

    if not args.dork and not args.dg and not getattr(args, "url", None) and not getattr(args, "file", None):
        parser.print_help()
        return

    config = load_config(args.config)

    if args.no_analyze:     config["analyze_files"]       = False
    if args.sqli:           config["sqli_detection"]      = True
    if args.xss:            config["xss_detection"]       = True
    if args.xss:            config["xss_type"]            = args.xss_type
    if args.stealth:        config["stealth_mode"]        = True
    if args.no_fingerprint: config["http_fingerprinting"] = False
    if args.blacklist:      config["blacklist"]            = args.blacklist
    if args.whitelist:      config["whitelist"]            = args.whitelist

    output_file = args.output
    if not output_file:
        output_file = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        console.print(f"[dim][~] -o não especificado — salvando em [bold]{output_file}[/bold][/dim]")

    _is_json_output = str(output_file).lower().endswith(".json")
    _do_analyze     = args.analyze or _is_json_output

    if _is_json_output and not args.analyze and _ANALYZE_AVAILABLE:
        console.print("\n[bold cyan]┌─[ ANÁLISE DE RESULTADOS ][/bold cyan]")
        console.print("[bold cyan]│[/bold cyan]  .json detectado na saída — análise disponível após a busca.")
        console.print("[bold cyan]│  Executar análise nos resultados? [y/N]:[/bold cyan] ", end="")
        try:
            _do_analyze = input("").strip().lower() in ("y", "yes")
        except KeyboardInterrupt:
            _do_analyze = False
        if _do_analyze:
            console.print("[bold cyan]└─>[/bold cyan] [green]Análise ativada.[/green]\n")
        else:
            console.print("[bold cyan]└─>[/bold cyan] [dim]Análise pulada.[/dim]\n")
    elif args.analyze and not _ANALYZE_AVAILABLE:
        console.print("[yellow][!] mappingexpo_agents.py não encontrado — análise indisponível.[/yellow]")
        _do_analyze = False

    mappingexpo = MappingExpo(config, output_file)

    # ── -u / --url: teste direto ───────────────────────────────────────────────
    if getattr(args, "url", None):
        target_url   = args.url
        _do_url_sqli = config.get("sqli_detection", False)
        _do_url_xss  = config.get("xss_detection",  False)

        if getattr(args, "dbscan", False):
            console.print("[yellow][!] --dbscan é ignorado no modo -u (URL direto). "
                          "Use --dbscan com -d / --dg / -f para escanear múltiplos hosts.[/yellow]")

        console.print(f"\n[bold cyan]┌─[ TESTE DE URL DIRETA ][/bold cyan]")
        console.print(f"[bold cyan]│[/bold cyan]  Alvo → [cyan]{_rich_escape(target_url)}[/cyan]")

        if not _do_url_sqli and not _do_url_xss:
            console.print("[bold cyan]│[/bold cyan]  [yellow][!] Nenhuma flag de teste — ativando SQLi automaticamente[/yellow]")
            config["sqli_detection"] = True
            mappingexpo.config["sqli_detection"] = True
            mappingexpo.analyzer.config["sqli_detection"] = True
            _do_url_sqli = True

        tests_label = " + ".join(filter(None, ["SQLi" if _do_url_sqli else "", "XSS" if _do_url_xss else ""]))
        console.print(f"[bold cyan]└─>[/bold cyan] Iniciando teste {tests_label}...\n")

        _entry = {
            "url":       target_url,
            "title":     "",
            "snippet":   "",
            "dork":      "",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "extension": mappingexpo.analyzer.get_file_extension(target_url),
            "category":  mappingexpo.analyzer.categorize_url(target_url),
        }

        if _do_url_sqli:
            _detector    = SQLiDetector(
                stealth=config.get("stealth_mode", False),
                timeout=config.get("request_timeout", 10),
            )
            _sqli_result = _detector.test_sqli(target_url)
            _entry["sqli_test"] = _sqli_result
            console.print("\n[bold yellow]┌─[ RESULTADO DO TESTE SQLi ][/bold yellow]")
            _tested = _sqli_result.get("tested", False)
            _vuln   = _sqli_result.get("vulnerable", False)
            _conf   = _sqli_result.get("overall_confidence", "none")
            _waf    = _sqli_result.get("waf_detected")
            _msg    = _sqli_result.get("message", "")
            if not _tested:
                console.print(f"[bold yellow]│[/bold yellow]  [yellow][~] Não testado — {_msg}[/yellow]")
            elif _vuln:
                _style = "bold magenta" if _conf == SQLiConfidence.CRITICAL.value else "bold red"
                console.print(f"[bold yellow]│[/bold yellow]  [{_style}][!] VULNERABLE ({_conf})[/{_style}]  {_rich_escape(target_url)}")
                for _t in _sqli_result.get("tests", []):
                    if _t.get("vulnerable"):
                        _method = _t.get("method", "?")
                        _ev     = " | ".join(_t.get("evidence", [])[:2])
                        _param  = _t.get("parameter", "")
                        _p_str  = f" [parâmetro: {_param}]" if _param else ""
                        console.print(f"[bold yellow]│[/bold yellow]    [dim]↳ método: [yellow]{_method}[/yellow]{_p_str}  evidência: [italic]{_rich_escape(_ev[:120])}[/italic][/dim]")
                mappingexpo.stats["sqli_vulnerable"] += 1
            else:
                console.print(f"[bold yellow]│[/bold yellow]  [green][✓] SAFE[/green]  {_rich_escape(target_url)}")
            if _waf:
                console.print(f"[bold yellow]│[/bold yellow]  [yellow][~] WAF detectado: {_waf}[/yellow]")
                mappingexpo.stats["waf_detected"] += 1
            console.print(f"[bold yellow]└─>[/bold yellow]  {_msg}")

        if _do_url_xss:
            try:
                from xss import XSSDetector
                _xss_det    = XSSDetector(
                    stealth  = config.get("stealth_mode", False),
                    timeout  = config.get("request_timeout", 10),
                    xss_type = config.get("xss_type", "all"),
                )
                _xss_result = _xss_det.test_xss(target_url)
                _entry["xss_test"] = _xss_result
                console.print("\n[bold yellow]┌─[ RESULTADO DO TESTE XSS ][/bold yellow]")
                _xvuln  = _xss_result.get("vulnerable", False)
                _xconf  = _xss_result.get("overall_confidence", "none")
                _xtypes = ", ".join(_xss_result.get("xss_types_found", []))
                _xwaf   = _xss_result.get("waf_detected")
                _xmsg   = _xss_result.get("message", "")
                if not _xss_result.get("tested"):
                    console.print(f"[bold yellow]│[/bold yellow]  [yellow][~] Não testado — {_xmsg}[/yellow]")
                elif _xvuln:
                    console.print(f"[bold yellow]│[/bold yellow]  [bold yellow][!] VULNERABLE ({_xconf}) [{_xtypes}][/bold yellow]  {_rich_escape(target_url)}")
                    mappingexpo.stats["xss_vulnerable"] += 1
                else:
                    console.print(f"[bold yellow]│[/bold yellow]  [green][✓] SAFE[/green]  {_rich_escape(target_url)}")
                if _xwaf:
                    console.print(f"[bold yellow]│[/bold yellow]  [yellow][~] WAF detectado: {_xwaf}[/yellow]")
                console.print(f"[bold yellow]└─>[/bold yellow]  {_xmsg}")
            except ImportError:
                console.print("[yellow][!] xss.py não encontrado — teste XSS pulado.[/yellow]")

        if output_file:
            mappingexpo.results.append(_entry)
            mappingexpo.save_results()
            console.print(f"\n[bold green][✓] Resultado salvo → Dump/{output_file}[/bold green]")
        return

    # ── -f / --file ───────────────────────────────────────────────────────────
    if getattr(args, "file", None):
        _file_path = args.file
        console.print(f"\n[bold cyan]┌─[ MODO DE ARQUIVO ][/bold cyan]")
        console.print(f"[bold cyan]│[/bold cyan]  Carregando: [cyan]{_file_path}[/cyan]")
        _loaded = _load_results_from_file(_file_path)
        if not _loaded:
            console.print("[bold cyan]└─>[/bold cyan] [red]Nenhum resultado carregado — abortando.[/red]")
            return
        console.print(f"[bold cyan]│[/bold cyan]  Carregados [green]{len(_loaded)}[/green] resultado(s)")

        _do_sqli    = config.get("sqli_detection", False)
        _do_xss     = config.get("xss_detection", False)
        _do_analyze = args.analyze or str(output_file).lower().endswith(".json")
        _do_crawl   = getattr(args, "crawl", False)
        _do_dbscan  = getattr(args, "dbscan", False)

        console.print("[bold cyan]└─>[/bold cyan] Processando...\n")

        for _r in _loaded:
            _h = mappingexpo._hash_url(_r.get("url", ""))
            mappingexpo.url_hashes.add(_h)

        if (_do_sqli or _do_xss) and _loaded:
            _analyzed = mappingexpo.analyze_results(_loaded)
            mappingexpo.results = _analyzed
        else:
            mappingexpo.results = _loaded

        mappingexpo.print_statistics()

        if output_file:
            mappingexpo.save_results()
            console.print(f"\n[bold green][✓] Resultados salvos → Dump/{output_file}[/bold green]")

        if _do_analyze and mappingexpo.results and _ANALYZE_AVAILABLE:
            ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
            fmt        = args.analyze_fmt
            report_out = args.analyze_out
            if not report_out:
                base       = str(output_file).replace(".json", "").replace(".html", "")
                report_out = f"{base}_analysis_{ts}.{fmt}"
            _analyze_args_f = type("A", (), {
                "analyze_fetch":         args.analyze_fetch,
                "analyze_fetch_max":     args.analyze_fetch_max,
                "analyze_no_llm_triage": False,
                "analyze_report":        True,
                "analyze_fmt":           fmt,
                "analyze_out":           report_out,
            })()
            try:
                _result_f = _run_agents_pipeline(results=mappingexpo.results, llm_plugin=None, args=_analyze_args_f)
                if _result_f.get("report_path"):
                    console.print(f"[bold green][✓] Relatório de análise → {_result_f['report_path']}[/bold green]")
            except Exception as _fae:
                console.print(f"[yellow][Analyzer] Erro: {_fae}[/yellow]")

        if _do_crawl and _ANALYZE_AVAILABLE:
            _seed_dorks = list({r.get("dork", "") for r in mappingexpo.results if r.get("dork")})
            if not _seed_dorks:
                _seed_dorks = [r.get("url", "") for r in mappingexpo.results[:10]]
            try:
                _crawl_out_f = run_crawl(seed_dorks=_seed_dorks, args=args, target="")
                if _crawl_out_f.get("results"):
                    _existing_urls = {r.get("url") for r in mappingexpo.results}
                    _new_crawl     = [r for r in _crawl_out_f["results"] if r.get("url") not in _existing_urls]
                    mappingexpo.results.extend(_new_crawl)
                    if output_file:
                        mappingexpo.save_results()
                    console.print(f"\n[bold green][Crawl] Concluído — +{len(_new_crawl)} novo(s) resultado(s)[/bold green]")
            except Exception as _fce:
                console.print(f"[yellow][Crawl] Erro: {_fce}[/yellow]")

        if _do_dbscan:
            if not _DBSCAN_AVAILABLE:
                console.print("[yellow][!] db_portscan.py não encontrado em Tools/ — DBScan indisponível.[/yellow]")
            elif not mappingexpo.results:
                console.print("[yellow][DBScan] Nenhum resultado para escanear.[/yellow]")
            else:
                console.print(
                    f"\n[bold cyan]┌─[ VARREDURA DE PORTAS DB ][/bold cyan]"
                    f"\n[bold cyan]└─>[/bold cyan] Iniciando em {len(mappingexpo.results)} resultado(s)...\n"
                )
                try:
                    _db_agent = DBPortScanAgent(
                        timeout   = getattr(args, "dbscan_timeout",   2.5),
                        threads   = getattr(args, "dbscan_threads",   60),
                        ports     = getattr(args, "dbscan_ports",     None),
                        max_hosts = getattr(args, "dbscan_max_hosts", 200),
                    )
                    _db_report = _db_agent.run(mappingexpo.results)
                    if _db_report:
                        _db_report.print_summary()
                        # CORREÇÃO: output_file é apenas um nome de arquivo; devemos
                        # passar o path completo do Dump/ para que save_dbscan_report
                        # grave ao lado do arquivo principal de resultados e não no CWD.
                        _dump_dir    = Path(__file__).parent / "Dump"
                        _db_out_base = str(_dump_dir / str(output_file)) if output_file else str(_dump_dir / "mappingexpo_dbscan.json")
                        _db_saved    = save_dbscan_report(_db_report, _db_out_base)
                        console.print(f"[bold green][✓] Relatório DBScan → {_db_saved}[/bold green]")
                except KeyboardInterrupt:
                    console.print("\n[yellow][DBScan] Interrompido pelo usuário.[/yellow]")
                except Exception as _dbe:
                    console.print(f"[yellow][DBScan] Erro: {_rich_escape(str(_dbe))}[/yellow]")
        return

    # ── Origem dos dorks ───────────────────────────────────────────────────────────
    if args.dg:
        template_files = resolve_templates_argument(args.templates)
        all_dorks = []
        for template_file in template_files:
            generator = DorkGenerator(str(template_file), max_combinations=args.dg_max)
            all_dorks.extend(generator.generate(categories=selected_categories, mode=args.mode))
        dorks = all_dorks
        console.print(f"[cyan][*] {len(dorks)} dorks gerados (modo: {args.mode})[/cyan]")
    else:
        dorks = mappingexpo.process_dorks(args.dork)

    console.print(f"[bold cyan]┌─[ CARREGADOS {len(dorks)} DORK(S) ][/bold cyan]")
    console.print(f"[bold cyan]└─>[/bold cyan] Iniciando...\n")

    try:
        mappingexpo.run_search(dorks, args.count)
    except KeyboardInterrupt:
        console.print("\n[red][!] Busca interrompida pelo usuário![/red]")

    mappingexpo.print_statistics()

    if _do_analyze and mappingexpo.results and _ANALYZE_AVAILABLE:
        ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
        fmt        = args.analyze_fmt
        report_out = args.analyze_out
        if not report_out:
            base       = str(output_file).replace(".json", "")
            report_out = f"{base}_analysis_{ts}.{fmt}"
        _analyze_args = type("A", (), {
            "analyze_fetch":         args.analyze_fetch,
            "analyze_fetch_max":     args.analyze_fetch_max,
            "analyze_no_llm_triage": False,
            "analyze_report":        True,
            "analyze_fmt":           fmt,
            "analyze_out":           report_out,
        })()
        try:
            result = _run_agents_pipeline(results=mappingexpo.results, llm_plugin=None, args=_analyze_args)
            if result.get("report_path"):
                console.print(f"[bold green][✓] Relatório de análise → {result['report_path']}[/bold green]")
        except Exception as _ae:
            console.print(f"[yellow][Agents] Erro: {_ae}[/yellow]")

    if getattr(args, "crawl", False):
        if not _ANALYZE_AVAILABLE:
            console.print("[yellow][!] mappingexpo_agents.py não encontrado — crawl indisponível.[/yellow]")
        else:
            try:
                crawl_out = run_crawl(seed_dorks=dorks, args=args, target="")
                if crawl_out.get("results"):
                    existing_urls  = {r.get("url") for r in mappingexpo.results}
                    new_from_crawl = [r for r in crawl_out["results"] if r.get("url") not in existing_urls]
                    mappingexpo.results.extend(new_from_crawl)
                    if mappingexpo.output_file:
                        mappingexpo.save_results()
                    console.print(
                        f"\n[bold green][Crawl] Concluído — "
                        f"{crawl_out['rounds']} rodada(s) | "
                        f"+{len(new_from_crawl)} novo(s) resultado(s)[/bold green]"
                    )
            except Exception as _ce:
                console.print(f"[yellow][Crawl] Erro: {_ce}[/yellow]")

    # ── DB Port Scanner ───────────────────────────────────────────────────────
    if getattr(args, "dbscan", False):
        if not _DBSCAN_AVAILABLE:
            console.print(
                "[yellow][!] db_portscan.py não encontrado em Tools — "
                "copie o arquivo para MappingExpo/Tools/ e tente novamente.[/yellow]"
            )
        elif not mappingexpo.results:
            console.print("[yellow][DBScan] Nenhum resultado para escanear.[/yellow]")
        else:
            console.print(
                f"\n[bold cyan]┌─[ VARREDURA DE PORTAS DB ][/bold cyan]"
                f"\n[bold cyan]└─>[/bold cyan] Iniciando em {len(mappingexpo.results)} resultado(s)...\n"
            )
            try:
                _db_agent = DBPortScanAgent(
                    timeout   = getattr(args, "dbscan_timeout",   2.5),
                    threads   = getattr(args, "dbscan_threads",   60),
                    ports     = getattr(args, "dbscan_ports",     None),
                    max_hosts = getattr(args, "dbscan_max_hosts", 200),
                )
                _db_report = _db_agent.run(mappingexpo.results)
                if _db_report:
                    _db_report.print_summary()
                    # CORREÇÃO: output_file é apenas um nome de arquivo; devemos
                    # passar o path completo do Dump/ para que save_dbscan_report
                    # grave ao lado do arquivo principal de resultados e não no CWD.
                    _dump_dir    = Path(__file__).parent / "Dump"
                    _db_out_base = str(_dump_dir / str(output_file)) if output_file else str(_dump_dir / "mappingexpo_dbscan.json")
                    _db_saved    = save_dbscan_report(_db_report, _db_out_base)
                    console.print(
                        f"[bold green][✓] Relatório DBScan → {_db_saved}[/bold green]"
                    )
            except KeyboardInterrupt:
                console.print("\n[yellow][DBScan] Interrompido pelo usuário.[/yellow]")
            except Exception as _dbe:
                console.print(f"[yellow][DBScan] Erro: {_rich_escape(str(_dbe))}[/yellow]")
    # ─────────────────────────────────────────────────────────────────────────

    if mappingexpo.output_file:
        console.print(f"\n[bold green][✓] Resultados salvos → Dump/{output_file}[/bold green]")
    else:
        console.print(f"\n[dim][~] Nenhum arquivo de saída especificado.[/dim]")


if __name__ == "__main__":
    main()
