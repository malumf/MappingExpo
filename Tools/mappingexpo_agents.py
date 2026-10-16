"""
DorkEye Agents
Post-search analysis pipeline for DorkEye Project+

Os agentes são invocados DEPOIS que o DorkEye conclui a busca.
Eles não interferem no fluxo de busca — trabalham sobre resultados já coletados.

Pipeline (ativado com --analyze):

1. TriageAgent             — classifica resultados por prioridade OSINT (+ bônus sqli/acessível)
2. PageFetchAgent          — baixa páginas HIGH/CRITICAL (retry, rotação de UA, salva headers)
3. SecurityAgent [NOVO]    — detecção de ameaças: phishing, malware, exploits, ofuscação
4. HeaderIntelAgent        — analisa headers de resposta: vazamentos de info, security headers ausentes
5. TechFingerprintAgent    — detecta CMS, frameworks, versões de JS/servidor a partir do conteúdo
6. SecretsAgent            — scan regex por segredos/credenciais + detecção de hash + severidade
7. PiiDetectorAgent        — detecta PII: e-mail, telefone, IBAN, CF, CC, SSN, DOB
8. EmailHarvesterAgent     — coleta e categoriza e-mails de todos os resultados
9. SubdomainHarvesterAgent — extrai subdomínios e gera dorks para o DorkCrawler
10. ReportAgent            — relatório HTML/MD/JSON com todas as seções novas (incl. segurança)
11. DorkCrawlerAgent       — crawl recursivo adaptativo (alimentado por TechFP + SubHarvest)
12. DBScan                 — scan de portas de banco de dados do agente (portas abertas)
13. Análise LLM            — Todos os resultados triados | dict `analysis` opcional — requer mappingexpo_llm_plugin.py

O SecurityAgent opera como middleware — faz hook em AMBOS:

- O fluxo de scan (automático, via security_scan_hook)
- O fluxo --analyze (sob demanda, como etapa 3 do pipeline)

Uso via CLI:
python mappingexpo.py --dg=all --analyze -o results.json
python mappingexpo.py -d dorks.txt --analyze --analyze-fetch --analyze-fmt=html

# Flags específicos de segurança:
python mappingexpo.py --dg=all --analyze --security-mode=active --security-quarantine
python mappingexpo.py --dg=all --analyze --no-security   # disable agent

Uso standalone (a partir de arquivo de resultados):
python mappingexpo_agents.py results.json --analyze-fmt=html --analyze-out=report.html

Autor: xPloits3c | DorkEye Project
"""

# FIX #1: dunder mangling de copy/paste (**future** → __future__)
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from html.parser import HTMLParser as _HTMLParser
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import requests

# ── Scanner de Portas DB opcional ──────────────────────────────────────────────────
try:
    from db_portscan import DBPortScanAgent as _DBPortScanAgent, save_dbscan_report as _save_dbscan
    _DBSCAN_OK = True
except ImportError:
    _DBSCAN_OK = False

# ── Console Rich ──────────────────────────────────────────────────────────────

try:
    from rich.console import Console
    from rich.panel   import Panel
    from rich.table   import Table
    _console = Console()

    def _log(msg: str, style: str = "cyan") -> None:
        _console.print(f"[{style}]{msg}[/{style}]")

    def _panel(body: str, title: str = "", border: str = "cyan") -> None:
        _console.print(Panel(body, title=title, border_style=border))

except ImportError:
    _console = None  # type: ignore

    def _log(msg: str, style: str = "") -> None:  # type: ignore
        print(msg)

    def _panel(body: str, title: str = "", border: str = "") -> None:  # type: ignore
        print(f"\n[{title}]\n{body}")

# ══════════════════════════════════════════════════════════════════════════════
# BIBLIOTECA DE PADRÕES — importada de mappingexpo_patterns.py
# ══════════════════════════════════════════════════════════════════════════════

from mappingexpo_patterns import (
    TRIAGE_RULES       as _TRIAGE_PATTERNS,
    SECRET_RULES       as _SECRET_PATTERNS,
    SECRET_SEVERITY    as _SECRET_SEVERITY,
    PII_RULES          as _PII_PATTERNS,
    SCORE_TO_LABEL     as _LABEL_FROM_SCORE,
    FETCH_UA           as _FETCH_UA_SHARED,
    FETCH_UA_POOL      as _FETCH_UA_POOL,
    SKIP_EXTENSIONS    as _SKIP_EXTENSIONS_SHARED,
    label_from_score,
    censor             as _censor_shared,
    luhn_check         as _luhn_check,
)

# ══════════════════════════════════════════════════════════════════════════════
# AGENTE BASE
# ══════════════════════════════════════════════════════════════════════════════

def _safe_json_local(raw: str, expected_type: type = dict):
    """
    Parser JSON robusto — standalone, sem dependências externas.
    Lida com: markdown fences, vírgulas finais, texto extra ao redor do JSON.
    """
    import re as _re
    text = _re.sub(r"`(?:json)?\s*", "", raw).replace("`", "").strip()
    text = _re.sub(r",\s*([}\]])", r"\1", text)

    open_c  = "{" if expected_type == dict else "["
    close_c = "}" if expected_type == dict else "]"
    start   = text.find(open_c)
    if start == -1:
        return {} if expected_type == dict else []

    depth, end = 0, -1
    for i, ch in enumerate(text[start:], start):
        if ch == open_c:  depth += 1
        elif ch == close_c:
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end == -1:
        return {} if expected_type == dict else []

    try:
        return json.loads(text[start:end])
    except json.JSONDecodeError:
        return {} if expected_type == dict else []


class BaseAgent(ABC):
    """
    Classe base para todos os agentes do DorkEye.
    Funciona sem LLM (plugin=None) — agentes usam regex por padrão.
    Se um plugin for fornecido, as etapas de LLM são ativadas como melhorias.
    """

    def __init__(self, plugin=None, name: str = "Agent"):
        self.plugin = plugin   # None = modo autônomo (sem LLM)
        self.name   = name

    def _call_llm(self, prompt: str, max_tokens: int = 700) -> str:
        """Chama o LLM se disponível, caso contrário levanta RuntimeError."""
        if not self.plugin:
            raise RuntimeError(f"[{self.name}] LLM não disponível — caindo no modo regex")
        return self.plugin._call(
            prompt,
            max_tokens=max_tokens,
            cache=True,
            mem_user=f"[{self.name}] {prompt[:100]}",
        )

    @property
    def has_llm(self) -> bool:
        """True se o plugin de LLM está ativo e disponível."""
        return self.plugin is not None

    def _safe_json(self, raw: str, expected_type: type = dict):
        """Parser JSON robusto — não depende de dorkeye_llm_plugin."""
        return _safe_json_local(raw, expected_type=expected_type)

    @staticmethod
    def _label(score: int) -> str:
        """Delega para dorkeye_patterns.label_from_score() — fonte única de verdade."""
        return label_from_score(score)

    @abstractmethod
    def run(self, *args, **kwargs):
        pass

# ══════════════════════════════════════════════════════════════════════════════
# AGENTE DE TRIAGE
# ══════════════════════════════════════════════════════════════════════════════

class TriageAgent(BaseAgent):
    """
    Classifica cada resultado por prioridade OSINT.

    Etapa 1 — Pré-pontuação por regex (sempre, sem LLM): 0-50 pontos
    Etapa 2 — Pontuação por LLM (opcional, batch_size resultados por vez): 0-100 pontos
    Pontuação final = max(regex*2, llm_score)

    Adiciona a cada resultado: triage_score (0-100), triage_label, triage_reason.
    Ordena por pontuação decrescente.
    """

    def __init__(self, plugin=None, batch_size: int = 15):
        super().__init__(plugin, name="TriageAgent")
        self.batch_size = batch_size

    def run(self, results: List[dict], use_llm: bool = True) -> List[dict]:
        if not results:
            return results

        _log(
            f"[{self.name}] Triando {len(results)} resultados "
            f"(LLM: {'on' if use_llm and self.plugin else 'off'})...",
            style="bold cyan"
        )

        # Etapa 1: pré-pontuação por regex
        for r in results:
            bonus, reasons = self._regex_score(r)
            r["_rx_bonus"]   = bonus
            r["_rx_reasons"] = reasons

        # Etapa 2: pontuação por LLM (opcional)
        if use_llm and self.plugin:
            batches = [results[i:i+self.batch_size] for i in range(0, len(results), self.batch_size)]
            for b_idx, batch in enumerate(batches, 1):
                _log(f"[{self.name}] Pontuação LLM lote {b_idx}/{len(batches)}...", style="dim")
                self._llm_score_batch(batch, b_idx)

        # Calcula a pontuação final e limpa campos temporários
        for r in results:
            if "triage_score" not in r:
                bonus = r.get("_rx_bonus", 0)
                r["triage_score"]  = min(bonus * 2, 100)
                r["triage_label"]  = self._label(r["triage_score"])
                r["triage_reason"] = ", ".join(r.get("_rx_reasons", [])) or "no pattern"
            r.pop("_rx_bonus",   None)
            r.pop("_rx_reasons", None)

        results.sort(key=lambda x: x.get("triage_score", 0), reverse=True)

        # Resumo
        counts = {l: 0 for l in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SKIP")}
        for r in results:
            lbl = r.get("triage_label", "LOW")
            counts[lbl] = counts.get(lbl, 0) + 1

        _log(
            f"[{self.name}] CRITICAL:{counts['CRITICAL']} HIGH:{counts['HIGH']} "
            f"MEDIUM:{counts['MEDIUM']} LOW:{counts['LOW']} SKIP:{counts['SKIP']}",
            style="bold green"
        )
        return results

    def _llm_score_batch(self, batch: List[dict], b_idx: int) -> None:
        lines = [
            f"[{i}] {r.get('url','')} | {r.get('title','N/A')[:55]} | {str(r.get('snippet',''))[:75]}"
            for i, r in enumerate(batch)
        ]
        prompt = (
            "You are an OSINT analyst. Assign an OSINT score from 0-100 to each result.\n\n"
            "CRITERIA:\n"
            "  90-100 CRITICAL — credentials, DB admin, shell, exposed config\n"
            "  70-89  HIGH     — admin panels, .env, .git, backups, config files\n"
            "  50-69  MEDIUM   — directory listing, vulnerable CMS, interesting login page\n"
            "  20-49  LOW      — standard login pages, generic pages\n"
            "   0-19  SKIP     — irrelevant\n\n"
            f"RESULTS:\n" + "\n".join(lines) + "\n\n"
            "Reply ONLY with a JSON array (one element per result, same order):\n"
            '[{"id":0,"score":85,"label":"HIGH","reason":"exposed phpMyAdmin panel"},...]\n###'
        )
        try:
            raw    = self._call_llm(prompt, max_tokens=len(batch) * 60)
            scores = self._safe_json(raw, expected_type=list)
            if not isinstance(scores, list):
                return
            for entry in scores:
                if not isinstance(entry, dict):
                    continue
                idx = entry.get("id")
                if not isinstance(idx, int) or idx >= len(batch):
                    continue
                r          = batch[idx]
                llm_score  = max(0, min(100, int(entry.get("score", 0))))
                final      = max(llm_score, r.get("_rx_bonus", 0) * 2)
                r["triage_score"]  = final
                r["triage_label"]  = self._label(final)
                r["triage_reason"] = str(entry.get("reason", "LLM scored"))[:120]
        except Exception as e:
            _log(f"[{self.name}] Lote LLM {b_idx} falhou: {e}", style="yellow")

    @staticmethod
    def _regex_score(result: dict) -> Tuple[int, List[str]]:
        text = " ".join([
            result.get("url", "") or "",
            result.get("title", "") or "",
            result.get("snippet", "") or "",
        ])
        bonus, reasons = 0, []
        for pattern, pts, hint in _TRIAGE_PATTERNS:
            if pattern.search(text):
                bonus += pts
                reasons.append(hint)

        # ── Bônus de runtime a partir de dados já presentes no resultado (v4.8) ─────────────
        sqli = result.get("sqli_test", {})
        if sqli.get("vulnerable"):
            conf = sqli.get("overall_confidence", "")
            if conf == "critical":
                bonus += 30
                reasons.append("sqli:critical confirmed")
            elif conf == "high":
                bonus += 22
                reasons.append("sqli:high confirmed")
            elif conf in ("medium", "low"):
                bonus += 12
                reasons.append(f"sqli:{conf} confirmed")

        if result.get("accessible") is True and result.get("status_code") == 200:
            bonus += 8
            reasons.append("accessible:200")

        # Número de parâmetros GET — mais parâmetros = maior superfície de ataque
        url = result.get("url", "")
        if "?" in url:
            try:
                from urllib.parse import parse_qs, urlparse
                n_params = len(parse_qs(urlparse(url).query))
                if n_params >= 5:
                    bonus += 10
                    reasons.append(f"get_params:{n_params}")
                elif n_params >= 2:
                    bonus += 5
                    reasons.append(f"get_params:{n_params}")
            except Exception:
                pass

        return min(bonus, 60), reasons  # limite aumentado para 60 (era 50)

    def get_by_label(self, results: List[dict], *labels: str) -> List[dict]:
        labels_set = {l.upper() for l in labels}
        return [r for r in results if r.get("triage_label", "").upper() in labels_set]

# ══════════════════════════════════════════════════════════════════════════════
# AGENTE DE FETCH DE PÁGINAS
# ══════════════════════════════════════════════════════════════════════════════

class _ScriptStyleStripper(_HTMLParser):
    """HTMLParser que remove blocos <script> e <style> de forma segura.

    Substitui a regex bypassável (CWE-20/116/185/186) pelo parser
    embutido, que lida corretamente com todas as variantes sintáticas válidas
    de tags de fechamento (ex.: </script  >, </SCRIPT\n>, etc.).
    """

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self._skip_tags: set = {"script", "style"}
        self._in_skip: int   = 0
        self._parts: list    = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self._skip_tags:
            self._in_skip += 1

    def handle_endtag(self, tag):
        if tag.lower() in self._skip_tags and self._in_skip:
            self._in_skip -= 1

    def handle_data(self, data):
        if not self._in_skip:
            self._parts.append(data)

    def handle_entityref(self, name):
        if not self._in_skip:
            self._parts.append(f"&{name};")

    def handle_charref(self, name):
        if not self._in_skip:
            self._parts.append(f"&#{name};")

    def get_result(self) -> str:
        return "".join(self._parts)


# Regex de fallback — usada SOMENTE se o HTMLParser levantar uma exceção em HTML
# severamente malformado. Este NÃO é o caminho principal.
#
# FIX CWE-20/116/185/186 ("Bad HTML filtering regexp"):
# - Abertura : `(?:[^>]*)` inalterada (lida com atributos sem `>` não quotado)
# - Fechamento: `s*>` substituído por `[^>]*>` para cobrir variantes aceitas
#   por navegadores como `</script anything>` ou `</  script  foo>`
#   (espaços após `</` tratados por `\s*` adicionado antes do nome da tag).
# Este caminho é intencionalmente um último recurso: o caminho principal usa
# _ScriptStyleStripper (HTMLParser embutido), que é imune a essas variantes.
_SCRIPT_STYLE_RE_FALLBACK = re.compile(  # noqa: S608
    r"<(?:script|style)(?:[^>]*)>[\s\S]*?</\s*(?:script|style)[^>]*>",
    re.IGNORECASE,
)


def _strip_page_content(text: str) -> str:
    """Remove tags script/style usando HTMLParser, depois remove as tags HTML restantes."""
    stripper = _ScriptStyleStripper()
    try:
        stripper.feed(text)
        stripper.close()
        text = stripper.get_result()
    except Exception:
        text = _SCRIPT_STYLE_RE_FALLBACK.sub(" ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s{3,}", "\n", text).strip()
    return text


# Aliases locais para compatibilidade com referências existentes no código
_FETCH_UA        = _FETCH_UA_SHARED
_SKIP_EXTENSIONS = _SKIP_EXTENSIONS_SHARED


class PageFetchAgent(BaseAgent):
    """
    Baixa o conteúdo HTML real das páginas HIGH e CRITICAL.

    Em vez de analisar snippets do DDG (100-200 caracteres, frequentemente inúteis),
    este agente baixa o HTML/texto real da página para dar ao
    SecretsAgent material concreto com o qual trabalhar.

    Adiciona 'page_content' (str) a cada resultado processado.
    Respeita rate limiting com um pequeno delay entre fetches.
    """

    def __init__(
        self,
        plugin=None,
        max_pages:    int   = 20,
        timeout:      int   = 10,
        max_chars:    int   = 8000,
        delay_s:      float = 1.0,
        min_label:    str   = "HIGH",
    ):
        super().__init__(plugin, name="PageFetchAgent")
        self.max_pages  = max_pages
        self.timeout    = timeout
        self.max_chars  = max_chars
        self.delay_s    = delay_s
        self.min_label  = min_label
        self._last_headers: dict = {}
        self._last_status:  int  = 0

    def run(self, results: List[dict]) -> List[dict]:
        """
        Baixa o conteúdo das páginas prioritárias.
        Modifica results in-place adicionando 'page_content'.
        Retorna a lista atualizada.
        """
        _label_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "SKIP": 0}
        min_rank    = _label_rank.get(self.min_label.upper(), 3)

        targets = [
            r for r in results
            if _label_rank.get(r.get("triage_label", "LOW"), 1) >= min_rank
            and "page_content" not in r
        ][:self.max_pages]

        if not targets:
            _log(f"[{self.name}] Nenhuma página para baixar (min_label={self.min_label}).", style="dim")
            return results

        _log(
            f"[{self.name}] Buscando {len(targets)} páginas "
            f"(max={self.max_pages}, timeout={self.timeout}s)...",
            style="bold cyan"
        )

        fetched = 0
        for r in targets:
            url = r.get("url", "")
            if not url:
                continue

            # Pula extensões binárias / não-texto
            ext = Path(urlparse(url).path).suffix.lower()
            if ext in _SKIP_EXTENSIONS:
                r["page_content"] = ""
                _log(f"[{self.name}] Pula {ext}: {url[:60]}", style="dim")
                continue

            content = self._fetch(url)
            r["page_content"] = content
            # Salva headers brutos para o HeaderIntelAgent
            if self._last_headers:
                r["response_headers"] = self._last_headers
                r["fetch_status"]     = self._last_status
                self._last_headers    = {}
                self._last_status     = 0
            status = f"+{len(content)}c" if content else "falhou"
            _log(f"[{self.name}] [{r.get('triage_label','?')}] {status} — {url[:70]}", style="dim")
            fetched += 1

            if fetched < len(targets):
                time.sleep(self.delay_s)

        ok_count = sum(1 for r in targets if r.get("page_content"))
        _log(
            f"[{self.name}] Concluído: {ok_count}/{len(targets)} páginas baixadas.",
            style="green"
        )
        return results

    def _fetch(self, url: str) -> str:
        """Baixa e retorna o texto da página (truncado em max_chars).
        v4.8: máximo de 2 retries, rotação de UA, salva response_headers no resultado.
        """
        import random as _random
        last_exc = None
        for attempt in range(3):  # 1 attempt + 2 retries
            ua = _random.choice(_FETCH_UA_POOL)
            try:
                resp = requests.get(
                    url,
                    timeout=self.timeout,
                    headers={
                        "User-Agent":      ua,
                        "Accept":          "text/html,application/xhtml+xml,text/plain",
                        "Accept-Language": "en-US,en;q=0.9,it;q=0.8",
                        "Accept-Encoding": "gzip, deflate",
                        "Connection":      "keep-alive",
                    },
                    allow_redirects=True,
                    stream=True,
                    verify=False,
                )
                if resp.status_code >= 400:
                    return ""

                # Lê no máximo max_chars*3 bytes
                raw = b""
                for chunk in resp.iter_content(chunk_size=4096):
                    raw += chunk
                    if len(raw) > self.max_chars * 3:
                        break

                content_type = resp.headers.get("Content-Type", "")
                if "text" not in content_type and "json" not in content_type:
                    return ""

                # Salva headers brutos em _fetch_meta (serão usados pelo HeaderIntelAgent)
                self._last_headers = dict(resp.headers)
                self._last_status  = resp.status_code

                text = raw.decode("utf-8", errors="replace")
                text = _strip_page_content(text)
                return text[:self.max_chars]

            except Exception as e:
                last_exc = e
                if attempt < 2:
                    time.sleep(1.5 * (attempt + 1))
                continue

        _log(f"[{self.name}] Fetch falhou após 3 tentativas: {url[:60]} — {last_exc}", style="dim")
        return ""

# ══════════════════════════════════════════════════════════════════════════════
# AGENTE DE SEGURANÇA — Middleware de detecção de ameaças
# ══════════════════════════════════════════════════════════════════════════════
#
# Opera como middleware do pipeline com hook em AMBOS os fluxos:
# 1. Fluxo de scan  → security_scan_hook(url, content, headers)
# 2. Fluxo --analyze → SecurityAgent.run(results) como etapa 3 do pipeline
#
# Categorias de detecção:
# - phishing:           impersonação de marca, coleta de credenciais, redirects
# - malware:            execução de código JS, payloads ofuscados, droppers
# - exploit:            reverse shells, SQLi, XXE, SSTI, desserialização
# - obfuscation:        escape hex/unicode, cadeias base64, alta entropia
# - suspicious_pattern: iframes ocultos, security headers ausentes, executáveis
#
# A pontuação de ameaça usa um modelo ponderado (não soma simples):
# 50% do pior indicador único
# 30% da média dos demais
# 20% de bônus de acumulação (limitado a +30)
# ══════════════════════════════════════════════════════════════════════════════

_SECURITY_AGENT_VERSION = "1.0.0"

# Limiares de pontuação de ameaça
_THRESHOLD_SAFE       = 15
_THRESHOLD_SUSPICIOUS = 40
_THRESHOLD_DANGEROUS  = 70
_THRESHOLD_CRITICAL   = 90


class ThreatLevel(Enum):
    """Nível de ameaça atribuído a um resultado."""
    CLEAN      = auto()
    LOW        = auto()
    SUSPICIOUS = auto()
    DANGEROUS  = auto()
    CRITICAL   = auto()

    @classmethod
    def from_score(cls, score: int) -> "ThreatLevel":
        if score <= _THRESHOLD_SAFE:
            return cls.CLEAN
        elif score <= _THRESHOLD_SUSPICIOUS:
            return cls.LOW
        elif score <= _THRESHOLD_DANGEROUS:
            return cls.SUSPICIOUS
        elif score <= _THRESHOLD_CRITICAL:
            return cls.DANGEROUS
        return cls.CRITICAL

    @property
    def badge(self) -> str:
        badges = {
            ThreatLevel.CLEAN:      "🟢 CLEAN",
            ThreatLevel.LOW:        "🟡 LOW",
            ThreatLevel.SUSPICIOUS: "🟠 SUSPICIOUS",
            ThreatLevel.DANGEROUS:  "🔴 DANGEROUS",
            ThreatLevel.CRITICAL:   "💀 CRITICAL",
        }
        return badges.get(self, "⚪ UNKNOWN")

    @property
    def should_block(self) -> bool:
        return self in (ThreatLevel.DANGEROUS, ThreatLevel.CRITICAL)


@dataclass
class ThreatIndicator:
    """Indicador de ameaça único detectado."""
    category:    str          # phishing | malware | exploit | obfuscation | suspicious_pattern
    description: str          # Descrição legível por humanos
    severity:    int          # Contribuição de 1-100 para a pontuação de ameaça
    evidence:    str = ""     # Padrão/snippet que disparou a detecção
    cwe_id:      str = ""     # Referência CWE opcional (ex.: CWE-79)
    mitre_id:    str = ""     # MITRE ATT&CK opcional (ex.: T1566)


@dataclass
class SecurityVerdict:
    """Veredito final de segurança para um resultado."""
    url:              str
    threat_level:     ThreatLevel
    threat_score:     int
    indicators:       List[ThreatIndicator] = field(default_factory=list)
    timestamp:        str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_duration_ms: float = 0.0
    content_hash:     str   = ""
    blocked:          bool  = False
    summary:          str   = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["threat_level"] = self.threat_level.name
        d["badge"]        = self.threat_level.badge
        return d

    def to_report_line(self) -> str:
        """Linha compacta para relatório/saída de console."""
        return (
            f"{self.threat_level.badge} │ Pontuação: {self.threat_score:3d}/100 │ "
            f"Indicadores: {len(self.indicators)} │ {self.url[:80]}"
        )


# ── Banco de Padrões de Segurança ────────────────────────────────────────────────

class _SecurityPatternDB:
    """
    Centralised malicious pattern database for SecurityAgent.
    Each pattern is a tuple: (compiled_regex, category, description, severity, cwe)
    """

    # ── URL / Phishing Patterns ──────────────────────────
    PHISHING_URL: List[Tuple[re.Pattern, str, str, int, str]] = [
        (re.compile(r"(?:login|signin|verify|secure|account|update|confirm|auth)"
                     r"[._-]", re.I),
         "phishing", "Phishing keyword in domain/path", 25, "CWE-451"),

        (re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
         "phishing", "Direct IP-based URL (no DNS)", 30, "CWE-451"),

        (re.compile(r"(?:bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|rb\.gy|shorturl|"
                     r"cutt\.ly|ow\.ly)", re.I),
         "phishing", "URL shortener (potential malicious redirect)", 15, ""),

        (re.compile(r"@[^/]+/", re.I),
         "phishing", "URL with @ (credential pre-fill / redirect trick)", 35, "CWE-601"),

        (re.compile(r"(?:\.tk|\.ml|\.ga|\.cf|\.gq|\.buzz|\.top|\.xyz|\.pw|"
                     r"\.cc|\.ws)(?:/|$)", re.I),
         "phishing", "High-risk phishing TLD", 20, ""),

        (re.compile(r"(?:data:text/html|javascript:)", re.I),
         "phishing", "Data URI / JavaScript URI scheme", 45, "CWE-79"),

        (re.compile(r"[a-z0-9]{20,}\.(?:com|net|org)", re.I),
         "phishing", "Algorithmically generated domain (DGA suspect)", 25, ""),

        (re.compile(r"(?:paypal|apple|google|microsoft|amazon|facebook|instagram|"
                     r"netflix|banking|wells.?fargo|chase|citibank)"
                     r"[^a-z]", re.I),
         "phishing", "Brand impersonation in domain", 35, "CWE-451"),
    ]

    # ── Content / Malware Patterns ───────────────────────
    MALWARE_CONTENT: List[Tuple[re.Pattern, str, str, int, str]] = [
        (re.compile(r"eval\s*\(\s*(?:atob|unescape|decodeURI|String\.fromCharCode)",
                     re.I),
         "malware", "eval() with decoding — obfuscated code execution", 50, "CWE-94"),

        (re.compile(r"document\.write\s*\(\s*(?:unescape|atob|decodeURI)", re.I),
         "malware", "document.write with decoding — DOM injection", 45, "CWE-79"),

        (re.compile(r"(?:window|document)\s*\[\s*['\"](?:loc|loca|locat)", re.I),
         "malware", "Obfuscated access to location (malicious redirect)", 40, "CWE-601"),

        (re.compile(r"new\s+Function\s*\(\s*['\"]", re.I),
         "malware", "Function() constructor — dynamic code execution", 45, "CWE-94"),

        (re.compile(r"(?:createElement|appendChild)\s*\(.*?script", re.I | re.S),
         "malware", "Dynamic <script> tag creation", 35, "CWE-79"),

        (re.compile(r"\.src\s*=\s*['\"](?:https?:)?//[^'\"]*?(?:\.php|\.asp|"
                     r"cmd=|shell|exec)", re.I),
         "malware", "Suspicious external script loading", 50, "CWE-829"),

        # Obfuscation patterns
        (re.compile(r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}", re.I),
         "obfuscation", "Long hex-escaped string (obfuscated payload)", 35, "CWE-506"),

        (re.compile(r"\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){10,}", re.I),
         "obfuscation", "Long unicode-escaped string (obfuscated payload)", 35, "CWE-506"),

        (re.compile(r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}", re.I),
         "obfuscation", "fromCharCode with many arguments (de-obfuscation)", 40, "CWE-506"),

        (re.compile(r"(?:btoa|atob)\s*\(\s*(?:btoa|atob)\s*\(", re.I),
         "obfuscation", "Double base64 encoding (evasion layer)", 45, "CWE-506"),

        (re.compile(r"[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*[a-zA-Z_$][a-zA-Z0-9_$]*"
                     r"\s*\(\s*['\"][A-Za-z0-9+/=]{50,}['\"]\s*\)", re.I),
         "obfuscation", "Decoding of long base64 blob (probable payload)", 40, "CWE-506"),

        # Form credential harvesting
        (re.compile(r"<form[^>]*action\s*=\s*['\"]https?://(?!(?:www\.)?google\."
                     r"|(?:www\.)?facebook\.|(?:www\.)?github\.)", re.I),
         "phishing", "Form with action pointing to suspicious external domain", 30, "CWE-352"),

        (re.compile(r"<input[^>]*type\s*=\s*['\"]password['\"][^>]*>", re.I),
         "phishing", "Password field in suspicious page", 20, "CWE-522"),

        (re.compile(r"(?:password|passwd|creditcard|cc_num|ssn|social.?security)",
                     re.I),
         "phishing", "Reference to sensitive data in content", 15, "CWE-312"),
    ]

    # ── Backend Exploit Patterns ─────────────────────────
    BACKEND_EXPLOIT: List[Tuple[re.Pattern, str, str, int, str]] = [
        # Reverse shells
        (re.compile(r"(?:bash\s+-i|/dev/tcp/|nc\s+-[elp]|ncat\s|"
                     r"mkfifo\s|socat\s.*exec)", re.I),
         "exploit", "Reverse shell pattern detected", 70, "CWE-78"),

        (re.compile(r"(?:python|perl|ruby|php)\s+-[ec]\s+['\"].*?(?:socket|"
                     r"connect|exec|system)", re.I | re.S),
         "exploit", "Reverse shell one-liner (Python/Perl/Ruby/PHP)", 70, "CWE-78"),

        # Command injection
        (re.compile(r"(?:;|\||&&|\$\(|`)\s*(?:cat|ls|id|whoami|uname|"
                     r"wget|curl|chmod|chown)\s", re.I),
         "exploit", "Potential command injection", 55, "CWE-78"),

        # PHP-specific
        (re.compile(r"<\?php\s.*?(?:eval|exec|system|passthru|shell_exec|"
                     r"popen|proc_open)\s*\(", re.I | re.S),
         "exploit", "PHP with command execution functions", 60, "CWE-78"),

        (re.compile(r"(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*"
                     r"(?:base64_decode|gzinflate|\$)", re.I),
         "exploit", "PHP multi-layer de-obfuscation (webshell pattern)", 65, "CWE-506"),

        # SQL Injection in content
        (re.compile(r"(?:UNION\s+ALL\s+SELECT|INTO\s+OUTFILE|INTO\s+DUMPFILE|"
                     r"LOAD_FILE\s*\(|benchmark\s*\(|sleep\s*\(\s*\d)", re.I),
         "exploit", "SQLi payload detected in content", 50, "CWE-89"),

        # XXE
        (re.compile(r"<!ENTITY\s+\S+\s+SYSTEM\s+['\"](?:file://|https?://|"
                     r"php://|expect://)", re.I),
         "exploit", "XXE Entity injection", 60, "CWE-611"),

        # SSTI / Template injection
        (re.compile(r"\{\{\s*(?:config|self\.__class__|request\.application|"
                     r"cycler\.__init__|lipsum\.__globals__)", re.I),
         "exploit", "Server-Side Template Injection (SSTI)", 55, "CWE-1336"),

        # Deserialization
        (re.compile(r"(?:O:\d+:\"[A-Z]|a:\d+:\{|rO0ABX|aced0005)", re.I),
         "exploit", "Serialized object (PHP/Java deserialization attack)", 50, "CWE-502"),
    ]

    # ── File / Document Patterns ─────────────────────────
    FILE_PAYLOAD: List[Tuple[re.Pattern, str, str, int, str]] = [
        (re.compile(r"(?:macro|vba|auto_?open|document_?open|workbook_?open)",
                     re.I),
         "malware", "VBA macro reference (potential dropper)", 40, "CWE-506"),

        (re.compile(r"(?:powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|"
                     r"rundll32|certutil)\s", re.I),
         "malware", "Windows utility invocation (potential dropper)", 50, "CWE-78"),

        (re.compile(r"(?:Invoke-Expression|IEX|Invoke-WebRequest|"
                     r"DownloadString|DownloadFile|Start-Process|"
                     r"New-Object\s+Net\.WebClient)", re.I),
         "malware", "PowerShell download/exec cradle", 60, "CWE-78"),

        (re.compile(r"<script[^>]*>\s*(?:var|let|const|function|\()", re.I),
         "suspicious_pattern", "Inline <script> tag with code in document", 20, "CWE-79"),

        (re.compile(r"(?:\.exe|\.bat|\.cmd|\.ps1|\.vbs|\.scr|\.pif|\.com|"
                     r"\.msi|\.dll)\b", re.I),
         "suspicious_pattern", "Executable file reference in content", 15, ""),

        (re.compile(r"(?:MZ|TVqQ|AAAA)(?:[A-Za-z0-9+/]{20,})", re.I),
         "malware", "Possible PE/ELF binary encoded as base64", 55, "CWE-506"),
    ]

    # ── Suspicious Header Patterns ───────────────────────
    SUSPICIOUS_HEADERS: Dict[str, List[Tuple[re.Pattern, str, int]]] = {
        "content-type": [
            (re.compile(r"application/(?:x-msdownload|x-msdos-program|"
                         r"x-executable|octet-stream)", re.I),
             "Content-Type indicates executable/binary file", 25),
        ],
        "content-disposition": [
            (re.compile(r"filename\s*=\s*['\"]?.*?\.(?:exe|bat|cmd|ps1|vbs|"
                         r"scr|msi|dll|hta)", re.I),
             "Forced download of executable file", 40),
        ],
        "x-powered-by": [
            (re.compile(r"(?:PHP/[45]\.|ASP\.NET)", re.I),
             "Outdated/vulnerable server-side stack", 10),
        ],
    }


# ── Security Analyzer Modules ────────────────────────────────────────────────

class _URLSecurityAnalyzer:
    """Analisa URLs em busca de indicadores de phishing e redirect malicioso."""

    _KNOWN_SAFE_DOMAINS: Set[str] = {
        "google.com", "github.com", "stackoverflow.com",
        "wikipedia.org", "microsoft.com", "apple.com",
        "mozilla.org", "w3.org", "python.org",
    }

    # Homoglyph / typosquatting confusables
    _CONFUSABLES: Dict[str, str] = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p',
        'с': 'c', 'х': 'x', 'у': 'y', '0': 'o',
        '1': 'l', 'і': 'i', 'ɡ': 'g',
    }

    _REDIRECT_PARAMS: Set[str] = {
        "url", "redirect", "next", "return", "goto",
        "redir", "destination", "continue", "target",
    }

    def analyze(self, url: str) -> List[ThreatIndicator]:
        indicators: List[ThreatIndicator] = []

        try:
            parsed = urlparse(url)
        except Exception:
            indicators.append(ThreatIndicator(
                category="phishing", description="URL malformada — não parseável",
                severity=30, evidence=url[:200],
            ))
            return indicators

        # Verificação de scheme
        if parsed.scheme not in ("http", "https", ""):
            indicators.append(ThreatIndicator(
                category="phishing", description=f"Scheme de URL incomum: {parsed.scheme}",
                severity=25, evidence=parsed.scheme,
            ))
        if parsed.scheme == "http":
            indicators.append(ThreatIndicator(
                category="suspicious_pattern", description="Conexão HTTP não criptografada",
                severity=10, evidence=url[:100],
            ))

        # Comprimento anormal de URL
        if len(url) > 250:
            indicators.append(ThreatIndicator(
                category="phishing", description=f"URL incomumente longa ({len(url)} chars)",
                severity=15, evidence=url[:100] + "...",
            ))

        hostname = parsed.hostname or ""

        # Empilhamento de subdomínios
        subdomain_parts = hostname.split(".")
        if len(subdomain_parts) > 4:
            indicators.append(ThreatIndicator(
                category="phishing",
                description=f"Empilhamento de subdomínios ({len(subdomain_parts)} níveis)",
                severity=25, evidence=hostname, cwe_id="CWE-451",
            ))

        # Homoglyph / typosquatting
        for char in hostname:
            if char in self._CONFUSABLES:
                indicators.append(ThreatIndicator(
                    category="phishing",
                    description="Caractere homoglyph no domínio (typosquatting)",
                    severity=45,
                    evidence=f"'{char}' → '{self._CONFUSABLES[char]}' em {hostname}",
                    cwe_id="CWE-451",
                ))
                break

        # Parâmetros de open redirect
        params = parse_qs(parsed.query)
        for param_name in params:
            if param_name.lower() in self._REDIRECT_PARAMS:
                val = params[param_name][0]
                if val.startswith(("http://", "https://", "//")):
                    indicators.append(ThreatIndicator(
                        category="phishing",
                        description=f"Open redirect via parâmetro '{param_name}'",
                        severity=30, evidence=f"{param_name}={val[:80]}",
                        cwe_id="CWE-601",
                    ))

        # Banco de padrões (pula brand impersonation em domínios conhecidos como seguros)
        base_domain = ".".join(hostname.rsplit(".", 2)[-2:]) if hostname else ""
        is_safe = base_domain in self._KNOWN_SAFE_DOMAINS

        for pattern, cat, desc, sev, cwe in _SecurityPatternDB.PHISHING_URL:
            if is_safe and "impersonation" in desc.lower():
                continue
            if pattern.search(url):
                indicators.append(ThreatIndicator(
                    category=cat, description=desc, severity=sev,
                    evidence=pattern.pattern[:80], cwe_id=cwe,
                ))

        return indicators


class _ContentSecurityAnalyzer:
    """Analisa conteúdo HTTP (HTML/JS/texto) em busca de scripts maliciosos."""

    def __init__(self, max_content_length: int = 5 * 1024 * 1024):
        self.max_content_length = max_content_length

    def analyze(self, content: str, content_type: str = "") -> List[ThreatIndicator]:
        indicators: List[ThreatIndicator] = []
        if not content:
            return indicators

        analysis_content = content[:self.max_content_length]

        # Escaneia todos os grupos de padrões
        for pattern_group in (
            _SecurityPatternDB.MALWARE_CONTENT,
            _SecurityPatternDB.BACKEND_EXPLOIT,
            _SecurityPatternDB.FILE_PAYLOAD,
        ):
            for pattern, cat, desc, sev, cwe in pattern_group:
                matches = pattern.findall(analysis_content)
                if matches:
                    adjusted_sev = min(100, sev + (len(matches) - 1) * 5)
                    evidence = matches[0] if isinstance(matches[0], str) else str(matches[0])
                    indicators.append(ThreatIndicator(
                        category=cat,
                        description=f"{desc} (×{len(matches)})" if len(matches) > 1 else desc,
                        severity=adjusted_sev,
                        evidence=evidence[:120],
                        cwe_id=cwe,
                    ))

        # Análise de entropia (detecta payloads codificados)
        high_entropy_blocks = self._find_high_entropy_blocks(analysis_content)
        if high_entropy_blocks:
            indicators.append(ThreatIndicator(
                category="obfuscation",
                description=f"Detectados {len(high_entropy_blocks)} blocos de alta entropia "
                            f"(possível payload codificado)",
                severity=min(30 + len(high_entropy_blocks) * 5, 60),
                evidence=f"Blocos: {len(high_entropy_blocks)}, "
                         f"entropia máx.: {max(e for _, e in high_entropy_blocks):.2f}",
            ))

        # Detecção de iframe oculto
        iframe_re = re.compile(
            r"<iframe[^>]*(?:style\s*=\s*['\"][^'\"]*"
            r"(?:display\s*:\s*none|visibility\s*:\s*hidden|"
            r"width\s*:\s*[01]|height\s*:\s*[01])|"
            r"width\s*=\s*['\"]?[01]['\"]?|height\s*=\s*['\"]?[01]['\"]?)",
            re.I | re.S,
        )
        if iframe_re.search(analysis_content):
            indicators.append(ThreatIndicator(
                category="malware",
                description="Iframe oculto (hidden/zero-size) — possível injeção",
                severity=45, evidence="Iframe oculto detectado", cwe_id="CWE-829",
            ))

        return indicators

    @staticmethod
    def _find_high_entropy_blocks(
        content: str, block_size: int = 256, threshold: float = 4.5,
    ) -> List[Tuple[int, float]]:
        """Encontra blocos de texto com alta entropia de Shannon."""
        high_blocks: List[Tuple[int, float]] = []
        for i in range(0, min(len(content), 100_000), block_size):
            block = content[i:i + block_size]
            if len(block) < block_size // 2:
                continue
            freq: Dict[str, int] = {}
            for ch in block:
                freq[ch] = freq.get(ch, 0) + 1
            entropy = 0.0
            for count in freq.values():
                p = count / len(block)
                if p > 0:
                    entropy -= p * math.log2(p)
            if entropy > threshold:
                high_blocks.append((i, entropy))
        return high_blocks


class _HeaderSecurityAnalyzer:
    """Analisa headers de resposta HTTP em busca de anomalias de segurança."""

    def analyze(self, headers: Dict[str, str]) -> List[ThreatIndicator]:
        indicators: List[ThreatIndicator] = []
        if not headers:
            return indicators

        normalized = {k.lower(): v for k, v in headers.items()}

        # Padrões suspeitos
        for header_name, patterns in _SecurityPatternDB.SUSPICIOUS_HEADERS.items():
            value = normalized.get(header_name, "")
            if value:
                for pattern, desc, sev in patterns:
                    if pattern.search(value):
                        indicators.append(ThreatIndicator(
                            category="suspicious_pattern", description=desc,
                            severity=sev, evidence=f"{header_name}: {value[:100]}",
                        ))

        # Security headers ausentes (agregados)
        sec_hdrs = {
            "x-frame-options": 5, "content-security-policy": 5,
            "x-content-type-options": 5, "strict-transport-security": 5,
        }
        missing = [h for h in sec_hdrs if h not in normalized]
        if len(missing) >= 3:
            indicators.append(ThreatIndicator(
                category="suspicious_pattern",
                description=f"{len(missing)}/4 security headers padrão ausentes",
                severity=10 + len(missing) * 3,
                evidence="Ausentes: " + ", ".join(missing),
            ))

        return indicators


class SecurityAgent(BaseAgent):
    """
    Agente de segurança do DorkEye — detecta phishing, malware, exploits
    e payloads ofuscados nos resultados do scan.

    Dois modos:
      - active:  analisa, marca E bloqueia resultados DANGEROUS/CRITICAL
      - passive: apenas analisa e marca (padrão no pipeline --analyze)

    Integração no pipeline --analyze:
      Adiciona 'security_verdict' (dict) a cada resultado processado.

    Integração no fluxo de scan (hook standalone):
      from mappingexpo_agents import security_scan_hook
      verdict = security_scan_hook(url, content, headers)
      if verdict.blocked:
          continue  # skip result
    """

    def __init__(
        self,
        plugin=None,
        mode:              str  = "passive",
        quarantine_dir:    Optional[str] = None,
        on_threat_callback: Optional[Callable[[SecurityVerdict], None]] = None,
    ):
        super().__init__(plugin, name="SecurityAgent")
        self.mode               = mode.lower()
        self.quarantine_dir     = quarantine_dir
        self.on_threat_callback = on_threat_callback

        self._url_analyzer     = _URLSecurityAnalyzer()
        self._content_analyzer = _ContentSecurityAnalyzer()
        self._header_analyzer  = _HeaderSecurityAnalyzer()

        # Estatísticas
        self._stats: Dict[str, int] = {
            "total_scanned": 0, "clean": 0, "low": 0,
            "suspicious": 0, "dangerous": 0, "critical": 0, "blocked": 0,
        }
        self._verdicts: List[SecurityVerdict] = []

        if quarantine_dir:
            os.makedirs(quarantine_dir, exist_ok=True)

    # ── Entry point do pipeline (fluxo --analyze) ─────────────────────────────────

    def run(self, results: List[dict]) -> List[dict]:
        """
        Escaneia todos os resultados no pipeline --analyze.
        Adiciona 'security_verdict' (dict) a cada resultado.
        Em mode='active', define result['security_blocked']=True para DANGEROUS/CRITICAL.
        """
        candidates = [
            r for r in results
            if r.get("url") and r.get("triage_label", "SKIP") != "SKIP"
        ]
        if not candidates:
            _log(f"[{self.name}] Nenhum resultado para escanear.", style="dim")
            return results

        _log(
            f"[{self.name}] Scan de segurança em {len(candidates)} resultados "
            f"(mode={'🛡️ ACTIVE' if self.mode == 'active' else '👁️ PASSIVE'})...",
            style="bold cyan"
        )

        threats_found = 0
        blocked_count = 0

        for r in candidates:
            url     = r.get("url", "")
            content = r.get("page_content", "") or r.get("snippet", "") or ""
            headers = r.get("response_headers", {}) or {}

            verdict = self.scan_single(url, content, headers)
            r["security_verdict"] = verdict.to_dict()

            if verdict.blocked:
                r["security_blocked"] = True
                blocked_count += 1

            if verdict.threat_level not in (ThreatLevel.CLEAN, ThreatLevel.LOW):
                threats_found += 1
                _log(
                    f"[{self.name}] {verdict.to_report_line()}",
                    style="red" if verdict.threat_level.should_block else "yellow"
                )

        _log(
            f"[{self.name}] Concluído: {self._stats['total_scanned']} escaneados, "
            f"{threats_found} ameaças, {blocked_count} bloqueados.",
            style="bold green" if threats_found == 0 else "bold red"
        )
        return results

    # ── Scan de resultado único (usável em ambos os fluxos) ───────────────────────────

    def scan_single(
        self,
        url:          str,
        content:      str = "",
        headers:      Optional[Dict[str, str]] = None,
        content_type: str = "",
    ) -> SecurityVerdict:
        """
        Analisa um único resultado.

        Chamável tanto do pipeline --analyze (via self.run)
        quanto do fluxo de scan (via security_scan_hook).
        """
        start_time = time.monotonic()
        all_indicators: List[ThreatIndicator] = []

        # Fase 1: análise de URL
        all_indicators.extend(self._url_analyzer.analyze(url))

        # Fase 2: análise de conteúdo
        if content:
            all_indicators.extend(
                self._content_analyzer.analyze(content, content_type)
            )

        # Fase 3: análise de headers
        if headers:
            all_indicators.extend(self._header_analyzer.analyze(headers))

        # Fase 4: pontuação de ameaça
        threat_score = self._calculate_threat_score(all_indicators)
        threat_level = ThreatLevel.from_score(threat_score)

        # Fase 5: decisão de bloqueio
        blocked = (self.mode == "active" and threat_level.should_block)

        # Fase 6: hash do conteúdo
        content_hash = ""
        if content:
            content_hash = hashlib.sha256(
                content.encode("utf-8", errors="replace")
            ).hexdigest()[:16]

        scan_ms = (time.monotonic() - start_time) * 1000
        verdict = SecurityVerdict(
            url=url, threat_level=threat_level, threat_score=threat_score,
            indicators=all_indicators, scan_duration_ms=round(scan_ms, 2),
            content_hash=content_hash, blocked=blocked,
            summary=self._generate_summary(all_indicators, threat_level),
        )

        # Atualiza estatísticas
        self._stats["total_scanned"] += 1
        self._stats[threat_level.name.lower()] = (
            self._stats.get(threat_level.name.lower(), 0) + 1
        )
        if blocked:
            self._stats["blocked"] += 1
        self._verdicts.append(verdict)

        # Callback
        if self.on_threat_callback and threat_score > _THRESHOLD_SAFE:
            self.on_threat_callback(verdict)

        # Quarentena
        if blocked and self.quarantine_dir and content:
            self._quarantine(verdict, content)

        return verdict

    # ── Estatísticas e relatórios ───────────────────────────────────────────────────

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    @property
    def verdicts(self) -> List[SecurityVerdict]:
        return list(self._verdicts)

    def get_threats_above(self, level: ThreatLevel) -> List[SecurityVerdict]:
        """Retorna todos os vereditos acima de um dado nível de ameaça."""
        order = list(ThreatLevel)
        threshold_idx = order.index(level)
        return [v for v in self._verdicts if order.index(v.threat_level) >= threshold_idx]

    def generate_console_report(self) -> str:
        """Relatório em texto para saída no console Rich."""
        lines = [
            f"  Total escaneado: {self._stats['total_scanned']:>6}",
            f"  🟢 Clean:       {self._stats.get('clean', 0):>6}",
            f"  🟡 Low:         {self._stats.get('low', 0):>6}",
            f"  🟠 Suspicious:  {self._stats.get('suspicious', 0):>6}",
            f"  🔴 Dangerous:   {self._stats.get('dangerous', 0):>6}",
            f"  💀 Critical:    {self._stats.get('critical', 0):>6}",
            f"  🚫 Blocked:     {self._stats['blocked']:>6}",
        ]
        threats = [v for v in self._verdicts if v.threat_level != ThreatLevel.CLEAN]
        if threats:
            lines.append("  ─────────────────────────────────────")
            for v in sorted(threats, key=lambda x: -x.threat_score)[:15]:
                lines.append(f"  {v.to_report_line()}")
                for ind in v.indicators[:3]:
                    lines.append(f"    ├─ [{ind.category.upper()}] {ind.description}")
                    if ind.cwe_id:
                        lines.append(f"    │  └─ {ind.cwe_id}")
        return "\n".join(lines)

    def generate_html_section(self) -> str:
        """Snippet HTML para integração na saída HTML do ReportAgent."""
        threat_colors = {
            "CLEAN": "#00c853", "LOW": "#ffd600", "SUSPICIOUS": "#ff9100",
            "DANGEROUS": "#ff1744", "CRITICAL": "#d50000",
        }
        rows = []
        for v in self._verdicts:
            if v.threat_level == ThreatLevel.CLEAN:
                continue
            color = threat_colors.get(v.threat_level.name, "#9e9e9e")
            pills = " ".join(
                f'<span style="background:{color}20;color:{color};'
                f'border:1px solid {color}40;padding:1px 6px;border-radius:3px;'
                f'font-size:10px;margin-right:3px">{ind.category}</span>'
                for ind in v.indicators[:4]
            )
            rows.append(
                f"<tr style='border-left:3px solid {color}'>"
                f"<td><span style='background:{color};color:#fff;padding:2px 8px;"
                f"border-radius:4px;font-size:10px;font-weight:700'>"
                f"{v.threat_level.name}</span></td>"
                f"<td style='font-weight:700;text-align:center'>{v.threat_score}/100</td>"
                f"<td title='{v.url}'><a href='{v.url}' target='_blank'>"
                f"{v.url[:65]}{'...' if len(v.url) > 65 else ''}</a></td>"
                f"<td>{pills}</td>"
                f"<td>{'🚫' if v.blocked else '✓'}</td></tr>"
            )
        if not rows:
            return ""
        return (
            '<table><tr><th>Nível</th><th>Pontuação</th>'
            '<th>URL</th><th>Indicadores</th><th>Status</th></tr>'
            + "".join(rows) + '</table>'
        )

    def reset(self):
        """Redefine estatísticas e vereditos para uma nova sessão."""
        self._stats = {k: 0 for k in self._stats}
        self._verdicts.clear()

    # ── Métodos privados ───────────────────────────────────────────────────────

    @staticmethod
    def _calculate_threat_score(indicators: List[ThreatIndicator]) -> int:
        """
        Pontuação de ameaça ponderada:
          50% do pior indicador único
          30% da média dos demais
          20% de bônus de acumulação (limitado a +30)
        """
        if not indicators:
            return 0
        severities = sorted([i.severity for i in indicators], reverse=True)
        max_sev = severities[0]
        avg_rest = (
            sum(severities[1:]) / len(severities[1:])
            if len(severities) > 1 else 0
        )
        accum_bonus = min(len(indicators) * 3, 30)
        score = int(max_sev * 0.50 + avg_rest * 0.30 + accum_bonus * 0.20)
        return min(100, max(0, score))

    @staticmethod
    def _generate_summary(
        indicators: List[ThreatIndicator], threat_level: ThreatLevel,
    ) -> str:
        if not indicators:
            return "Nenhum indicador de ameaça detectado."
        categories: Dict[str, int] = {}
        for ind in indicators:
            categories[ind.category] = categories.get(ind.category, 0) + 1
        parts = [f"{cat}: {n}" for cat, n in sorted(categories.items(), key=lambda x: -x[1])]
        return (
            f"{threat_level.badge} — "
            f"{len(indicators)} indicadores ({', '.join(parts)})"
        )

    def _quarantine(self, verdict: SecurityVerdict, content: str) -> None:
        if not self.quarantine_dir:
            return
        safe_name = re.sub(r"[^a-zA-Z0-9]", "_", verdict.url)[:80]
        filename  = f"{verdict.content_hash}_{safe_name}.quarantine"
        filepath  = os.path.join(self.quarantine_dir, filename)
        data = {
            "verdict":        verdict.to_dict(),
            "content_preview": content[:2000],
            "content_hash_full": hashlib.sha256(
                content.encode("utf-8", errors="replace")
            ).hexdigest(),
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            _log(f"[{self.name}] Em quarentena: {filepath}", style="dim")
        except OSError as e:
            _log(f"[{self.name}] Falha na quarentena: {e}", style="yellow")


# ── Hooks de integração do Security Agent (fluxo de scan) ─────────────────────────

_global_security_agent: Optional[SecurityAgent] = None


def get_security_agent(**kwargs) -> SecurityAgent:
    """
    Retorna o singleton global do SecurityAgent.
    Chamável de qualquer módulo do DorkEye.

    Uso:
        from mappingexpo_agents import get_security_agent
        agent = get_security_agent(mode="active")
        verdict = agent.scan_single(url, content)
    """
    global _global_security_agent
    if _global_security_agent is None:
        _global_security_agent = SecurityAgent(**kwargs)
    return _global_security_agent


def reset_security_agent() -> None:
    """Redefine o singleton global (para novas sessões de scan)."""
    global _global_security_agent
    if _global_security_agent:
        _global_security_agent.reset()


def security_scan_hook(
    url: str, content: str = "", headers: Optional[Dict[str, str]] = None,
) -> SecurityVerdict:
    """
    Hook rápido para integração inline no fluxo de scan.

    Uso no dorkeye.py (loop de scan):
        from mappingexpo_agents import security_scan_hook
        verdict = security_scan_hook(result_url, response_text, resp_headers)
        if verdict.blocked:
            continue  # skip malicious result

    Uso no fluxo --analyze:
        verdict = security_scan_hook(url, fetched_content)
        report_data["security"] = verdict.to_dict()
    """
    agent = get_security_agent()
    return agent.scan_single(url, content, headers)

# ══════════════════════════════════════════════════════════════════════════════
# AGENTE DE SEGREDOS
# ══════════════════════════════════════════════════════════════════════════════

# _censor importado como _censor_shared de dorkeye_patterns — alias local
def _censor(value: str, visible: int = 4) -> str:
    return _censor_shared(value, show=visible)


class SecretsAgent(BaseAgent):
    """
    Analisa o conteúdo real da página (page_content) em busca de
    credenciais, chaves de API, conexões de banco de dados e outros dados sensíveis.

    Funciona em duas fases:
      1. Scan regex (rápido, sem LLM) — encontra padrões conhecidos com alta confiança
      2. Scan LLM (opcional) — análise contextual para padrões ambíguos ou ocultos

    Prioridade de análise de conteúdo:
      page_content (conteúdo real baixado) > snippet (snippet do DDG)

    Adiciona 'secrets' (lista) a cada resultado com achados.
    """

    def __init__(self, plugin=None, use_llm: bool = True, max_content: int = 6000):
        super().__init__(plugin, name="SecretsAgent")
        self.use_llm     = use_llm and plugin is not None
        self.max_content = max_content

    def run(self, results: List[dict]) -> List[dict]:
        """
        Escaneia todos os resultados que têm conteúdo disponível.
        Retorna a lista com 'secrets' populado.
        """
        candidates = [
            r for r in results
            if (r.get("page_content") or r.get("snippet"))
            and r.get("triage_label", "SKIP") != "SKIP"
        ]

        if not candidates:
            _log(f"[{self.name}] Nenhum conteúdo disponível para escanear.", style="dim")
            return results

        _log(
            f"[{self.name}] Scan de segredos em {len(candidates)} resultados "
            f"(LLM: {'on' if self.use_llm else 'off'})...",
            style="bold cyan"
        )

        total_found = 0
        for r in candidates:
            content = r.get("page_content") or r.get("snippet") or ""
            content = content[:self.max_content]
            url     = r.get("url", "")

            findings: List[dict] = []

            # Fase 1: scan regex
            regex_hits = self._regex_scan(content, url)
            findings.extend(regex_hits)

            # Fase 2: scan LLM (apenas se LLM ativo e conteúdo rico o suficiente)
            if self.use_llm and len(content) > 100:
                llm_hits = self._llm_scan(content, url)
                existing_values = {f.get("value", "") for f in findings}
                for hit in llm_hits:
                    if hit.get("value", "") not in existing_values:
                        findings.append(hit)

            if findings:
                r["secrets"] = findings
                total_found += len(findings)
                _log(
                    f"[{self.name}] {len(findings)} segredo(s) → [{r.get('triage_label','?')}] {url[:65]}",
                    style="bold red"
                )

        _log(
            f"[{self.name}] Scan concluído: {total_found} segredos no total.",
            style="bold green" if total_found == 0 else "bold red"
        )
        return results

    def _regex_scan(self, content: str, url: str) -> List[dict]:
        findings = []
        seen_values: set = set()

        for category, pattern, description, has_group in _SECRET_PATTERNS:
            for match in pattern.finditer(content):
                if has_group and match.lastindex:
                    raw_value = match.group(1).strip()
                else:
                    raw_value = match.group(0).strip()
                if not raw_value or len(raw_value) < 4:
                    continue

                norm = raw_value.lower().replace(" ", "").replace("-", "")
                if norm in seen_values:
                    continue
                seen_values.add(norm)

                start   = max(0, match.start() - 70)
                end     = min(len(content), match.end() + 70)
                context = content[start:end].replace("\n", " ").strip()

                severity = _SECRET_SEVERITY.get(category, "MEDIUM")

                findings.append({
                    "type":       category,
                    "detection":  "REGEX",
                    "value":      _censor(raw_value),
                    "confidence": "HIGH",
                    "severity":   severity,
                    "context":    context[:160],
                    "source":     url,
                    "desc":       description,
                })
        return findings

    def _llm_scan(self, content: str, url: str) -> List[dict]:
        prompt = (
            "You are a security expert. Analyse this text and find ALL secrets or sensitive data.\n\n"
            f"SOURCE: {url}\n"
            f"CONTENT:\n{content[:3000]}\n\n"
            "Look for: API keys, tokens, passwords, hashes, JWT, DB connections, cloud credentials, SSH keys.\n"
            "Reply ONLY with a JSON array (empty [] if nothing found):\n"
            '[{"type":"API_KEY","value":"sk-abc...xyz0","confidence":"HIGH","context":"context line"}]\n###'
        )
        try:
            raw  = self._call_llm(prompt, max_tokens=500)
            data = self._safe_json(raw, expected_type=list)
            if not isinstance(data, list):
                return []
            results = []
            for item in data:
                if isinstance(item, dict) and item.get("value"):
                    item["detection"] = "LLM"
                    item["source"]    = url
                    if "severity" not in item:
                        item["severity"] = _SECRET_SEVERITY.get(
                            item.get("type", ""), "MEDIUM"
                        )
                    results.append(item)
            return results
        except Exception as e:
            _log(f"[{self.name}] Erro no scan LLM ({url[:50]}): {e}", style="yellow")
            return []

# ══════════════════════════════════════════════════════════════════════════════
# AGENTE DE RELATÓRIO
# ══════════════════════════════════════════════════════════════════════════════

class ReportAgent(BaseAgent):
    """
    Gera o relatório final da sessão de análise.

    Entrada: resultados triados com segredos, análise LLM opcional
    Saída: arquivo HTML (tema escuro), Markdown ou JSON
    """

    def __init__(self, plugin=None):
        super().__init__(plugin, name="ReportAgent")

    def run(
        self,
        results:     List[dict],
        analysis:    Optional[dict]  = None,
        target:      str             = "",
        output_path: Optional[str]   = None,
        fmt:         str             = "html",
        extra:       Optional[dict]  = None,
    ) -> str:
        _log(f"[{self.name}] Gerando relatório (fmt={fmt})...", style="bold cyan")

        analysis  = analysis or {}
        extra     = extra    or {}
        all_secrets = [s for r in results for s in r.get("secrets", [])]

        counts = {l: 0 for l in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SKIP")}
        for r in results:
            lbl = r.get("triage_label", "LOW")
            counts[lbl] = counts.get(lbl, 0) + 1

        if   fmt == "json": content = self._json(results, analysis, all_secrets, counts, target, extra)
        elif fmt == "md":   content = self._markdown(results, analysis, all_secrets, counts, target, extra)
        else:               content = self._html(results, analysis, all_secrets, counts, target, extra)

        if output_path:
            output_path = self._fix_ext(output_path, fmt)
            try:
                Path(output_path).write_text(content, encoding="utf-8")
                _log(f"[{self.name}] Relatório salvo: {output_path}", style="bold green")
            except IOError as e:
                _log(f"[{self.name}] Erro ao salvar: {e}", style="red")

        return content

    def _markdown(self, results, analysis, secrets, counts, target, extra=None) -> str:
        extra   = extra or {}
        now     = datetime.now().strftime("%Y-%m-%d %H:%M")
        top     = [r for r in results if r.get("triage_label") in ("CRITICAL","HIGH")]
        recs    = analysis.get("recommendations", [])
        pats    = analysis.get("patterns", [])
        emails  = extra.get("emails", [])
        pii     = extra.get("pii", [])
        subs    = extra.get("subdomains", {})
        sec_stats = extra.get("security_stats", {})
        sec_threats = extra.get("security_threats", [])

        lines = [
            "# DorkEye — Relatório de Análise",
            f"\n> {now}  |  Alvo: `{target or 'N/A'}`  |  DorkEye v4.8 + Agents v3.1\n",
            "---\n",
            "## Resumo\n",
            analysis.get("summary", "_Análise LLM não disponível._"),
            "\n---\n",
            "## Métricas\n",
            "| Label | Total |",
            "|-------|-------|",
            f"| 🔴 CRITICAL | {counts['CRITICAL']} |",
            f"| 🟠 HIGH     | {counts['HIGH']} |",
            f"| 🟡 MEDIUM   | {counts['MEDIUM']} |",
            f"| 🟢 LOW      | {counts['LOW']} |",
            f"| **TOTAL**   | **{len(results)}** |",
            f"| **SEGREDOS** | **{len(secrets)}** |",
            f"| **PII**     | **{len(pii)}** |",
            f"| **EMAILS**  | **{len(emails)}** |",
            "",
        ]

        if sec_stats:
            lines += [
                "\n---\n",
                "## 🛡️ Relatório do Security Agent\n",
                f"Escaneados: {sec_stats.get('total_scanned', 0)} | "
                f"Bloqueados: {sec_stats.get('blocked', 0)} | "
                f"Modo: {sec_stats.get('mode', 'passive').upper()}\n",
                "| Nível | Total |",
                "|-------|-------|",
                f"| 🟢 Clean      | {sec_stats.get('clean', 0)} |",
                f"| 🟡 Low        | {sec_stats.get('low', 0)} |",
                f"| 🟠 Suspicious | {sec_stats.get('suspicious', 0)} |",
                f"| 🔴 Dangerous  | {sec_stats.get('dangerous', 0)} |",
                f"| 💀 Critical   | {sec_stats.get('critical', 0)} |",
                "",
            ]
        if sec_threats:
            lines += [
                "\n### Ameaças Detectadas\n",
                "| Pontuação | Nível | URL | Categorias |",
                "|-------|-------|-----|------------|",
            ]
            for t in sec_threats[:30]:
                cats = ", ".join(
                    i.get("category", "?") for i in t.get("indicators", [])[:3]
                )
                lines.append(
                    f"| {t.get('threat_score', 0)} | **{t.get('threat_level', '?')}** "
                    f"| `{t.get('url', '')[:65]}` | {cats} |"
                )

        if top:
            lines += ["\n---\n", "## Principais Achados — CRITICAL & HIGH\n",
                      "| Pontuação | Label | URL | Motivo |", "|-------|-------|-----|--------|"]
            for r in top[:25]:
                lines.append(
                    f"| {r.get('triage_score',0)} | **{r.get('triage_label','')}** "
                    f"| `{r.get('url','')[:75]}` | {r.get('triage_reason','')[:60]} |"
                )
        if secrets:
            lines += ["\n---\n", f"## Segredos Encontrados ({len(secrets)})\n",
                      "| Tipo | Severidade | Detecção | Valor | Origem |",
                      "|------|----------|-----------|-------|--------|"]
            for s in secrets:
                lines.append(
                    f"| {s.get('type','?')} | {s.get('severity','?')} | {s.get('detection','?')} "
                    f"| `{s.get('value','?')}` | {s.get('source','?')[:60]} |"
                )
        if pii:
            lines += ["\n---\n", f"## PII Detectado ({len(pii)})\n",
                      "| Tipo | Valor | Origem |", "|------|-------|--------|"]
            for p in pii[:50]:
                lines.append(f"| {p.get('type','?')} | `{p.get('value','?')}` | {p.get('source','?')[:60]} |")
        if emails:
            lines += ["\n---\n", f"## E-mails Coletados ({len(emails)})\n",
                      "| Categoria | E-mail | Origem |", "|----------|-------|--------|"]
            for e in emails[:50]:
                lines.append(f"| {e.get('category','?')} | `{e.get('email','?')}` | {e.get('source','?')[:60]} |")
        if subs:
            lines += ["\n---\n", "## Subdomínios Encontrados\n"]
            for bd, sub_list in subs.items():
                lines.append(f"**{bd}**: {', '.join(sub_list[:20])}")
        if pats:
            lines += ["\n---\n", "## Padrões Detectados\n"] + [f"- {p}" for p in pats]
        if recs:
            lines += ["\n---\n", "## Recomendações\n"] + [f"- {r}" for r in recs]

        lines += [
            "\n---\n",
            f"## Todos os Resultados ({len(results)})\n",
            "| Pontuação | Label | URL | Título |",
            "|-------|-------|-----|-------|",
        ]
        for r in results:
            lines.append(
                f"| {r.get('triage_score',0)} | {r.get('triage_label','?')} "
                f"| `{r.get('url','')[:70]}` | {r.get('title','N/A')[:50]} |"
            )
        lines.append(f"\n\n---\n*DorkEye v4.8 + Agents v3.1 — {now}*")
        return "\n".join(lines)

    def _html(self, results, analysis, secrets, counts, target, extra=None) -> str:
        extra   = extra or {}
        now     = datetime.now().strftime("%Y-%m-%d %H:%M")
        top     = [r for r in results if r.get("triage_label") in ("CRITICAL","HIGH")]
        recs    = analysis.get("recommendations", [])
        pats    = analysis.get("patterns", [])
        summary = analysis.get("summary", "")
        emails  = extra.get("emails", [])
        pii     = extra.get("pii", [])
        subs    = extra.get("subdomains", {})
        cve_d   = extra.get("cve_dorks", [])
        sec_html = extra.get("security_html", "")
        sec_stats = extra.get("security_stats", {})

        _sc = {"CRITICAL":"#ff4444","HIGH":"#ff8800","MEDIUM":"#ffcc00","LOW":"#44cc44","SKIP":"#888"}
        _sv = {"CRITICAL":"#ff4444","HIGH":"#ff8800","MEDIUM":"#ffcc00","LOW":"#44cc44"}

        def badge(lbl, colors=_sc):
            c = colors.get(lbl,"#888")
            return f'<span style="background:{c};color:#000;padding:1px 7px;border-radius:3px;font-size:11px;font-weight:bold">{lbl}</span>'

        rows_top = "".join(
            f"<tr><td>{r.get('triage_score',0)}</td><td>{badge(r.get('triage_label','?'))}</td>"
            f"<td><a href='{r.get('url','')}' target='_blank'>{r.get('url','')[:80]}</a></td>"
            f"<td>{r.get('triage_reason','')[:70]}</td></tr>"
            for r in top[:25]
        )
        rows_all = "".join(
            f"<tr><td>{r.get('triage_score',0)}</td><td>{badge(r.get('triage_label','?'))}</td>"
            f"<td><a href='{r.get('url','')}' target='_blank'>{r.get('url','')[:80]}</a></td>"
            f"<td>{r.get('title','N/A')[:55]}</td></tr>"
            for r in results
        )
        rows_sec = "".join(
            f"<tr><td><code>{s.get('type','?')}</code></td>"
            f"<td>{badge(s.get('severity','?'), _sv)}</td>"
            f"<td><span style='color:{'#4af' if s.get('detection')=='LLM' else '#fa4'}'>"
            f"{s.get('detection','?')}</span></td>"
            f"<td><code>{s.get('value','?')}</code></td>"
            f"<td>{s.get('source','?')[:60]}</td></tr>"
            for s in secrets
        )
        rows_pii = "".join(
            f"<tr><td><code>{p.get('type','?')}</code></td>"
            f"<td><code>{p.get('value','?')}</code></td>"
            f"<td>{p.get('desc','')[:50]}</td>"
            f"<td>{p.get('source','?')[:60]}</td></tr>"
            for p in pii[:100]
        )
        rows_email = "".join(
            f"<tr><td>{e.get('category','?')}</td>"
            f"<td><code>{e.get('email','?')}</code></td>"
            f"<td>{e.get('source','?')[:60]}</td></tr>"
            for e in emails[:100]
        )
        rows_subs = "".join(
            f"<tr><td><b>{bd}</b></td><td>{', '.join(sl[:15])}</td></tr>"
            for bd, sl in subs.items()
        )
        rows_cve = "".join(
            f"<tr><td><code>{d}</code></td></tr>"
            for d in cve_d[:30]
        )
        pats_html = "".join(f"<li>{p}</li>" for p in pats)
        recs_html = "".join(f"<li>{r}</li>" for r in recs)

        sec_metrics_html = ""
        if sec_stats:
            sec_metrics_html = (
                '<div class="metrics" style="margin-bottom:10px">'
                f'<div class="metric"><div class="num" style="color:#00c853">{sec_stats.get("clean",0)}</div><div class="lbl">CLEAN</div></div>'
                f'<div class="metric"><div class="num" style="color:#ffd600">{sec_stats.get("low",0)}</div><div class="lbl">LOW</div></div>'
                f'<div class="metric"><div class="num" style="color:#ff9100">{sec_stats.get("suspicious",0)}</div><div class="lbl">SUSPICIOUS</div></div>'
                f'<div class="metric"><div class="num" style="color:#ff1744">{sec_stats.get("dangerous",0)}</div><div class="lbl">DANGEROUS</div></div>'
                f'<div class="metric"><div class="num" style="color:#d50000">{sec_stats.get("critical",0)}</div><div class="lbl">CRITICAL</div></div>'
                f'<div class="metric"><div class="num" style="color:#ff4444">{sec_stats.get("blocked",0)}</div><div class="lbl">BLOCKED</div></div>'
                '</div>'
            )

        def section(title, content, show=True):
            if not show:
                return ""
            return f"<h2>{title}</h2><div class='card'>{content}</div>"

        return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8">
<title>DorkEye Agents — Relatório — {target or 'Sessão'}</title>
<style>
:root{{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--text:#c9d1d9;--acc:#58a6ff;--brd:#30363d}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;font-size:14px;line-height:1.6;padding:28px}}
h1{{color:var(--acc);font-size:26px;margin-bottom:4px}}
h2{{color:var(--acc);font-size:17px;margin:28px 0 10px;border-bottom:1px solid var(--brd);padding-bottom:5px}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:20px}}
.card{{background:var(--bg2);border:1px solid var(--brd);border-radius:8px;padding:16px;margin-bottom:12px}}
.metrics{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}}
.metric{{background:var(--bg3);border-radius:6px;padding:10px 18px;text-align:center;min-width:85px}}
.metric .num{{font-size:26px;font-weight:bold}}
.metric .lbl{{font-size:11px;color:#8b949e}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:var(--bg3);padding:8px 10px;text-align:left;border-bottom:2px solid var(--brd);color:var(--acc)}}
td{{padding:6px 10px;border-bottom:1px solid var(--brd);vertical-align:top;word-break:break-word}}
tr:hover{{background:var(--bg3)}}
a{{color:var(--acc);text-decoration:none;word-break:break-all}}
a:hover{{text-decoration:underline}}
code{{background:var(--bg3);padding:1px 5px;border-radius:3px;font-size:12px}}
ul{{padding-left:18px}}li{{margin:3px 0}}
footer{{margin-top:36px;font-size:11px;color:#8b949e;text-align:center}}
</style></head><body>
<h1>&#128065; DorkEye — Relatório</h1>
<div class="meta">Gerado: {now} &nbsp;|&nbsp; Alvo: <code>{target or 'N/A'}</code> &nbsp;|&nbsp; DorkEye Project</div>
{'<h2>Resumo</h2><div class="card">'+summary+'</div>' if summary else ''}
<h2>Métricas</h2>
<div class="metrics">
  <div class="metric"><div class="num" style="color:#ff4444">{counts['CRITICAL']}</div><div class="lbl">CRITICAL</div></div>
  <div class="metric"><div class="num" style="color:#ff8800">{counts['HIGH']}</div><div class="lbl">HIGH</div></div>
  <div class="metric"><div class="num" style="color:#ffcc00">{counts['MEDIUM']}</div><div class="lbl">MEDIUM</div></div>
  <div class="metric"><div class="num" style="color:#44cc44">{counts['LOW']}</div><div class="lbl">LOW</div></div>
  <div class="metric"><div class="num">{len(results)}</div><div class="lbl">TOTAL</div></div>
  <div class="metric"><div class="num" style="color:#ff4444">{len(secrets)}</div><div class="lbl">SEGREDOS</div></div>
  <div class="metric"><div class="num" style="color:#ff8800">{len(pii)}</div><div class="lbl">PII</div></div>
  <div class="metric"><div class="num" style="color:#58a6ff">{len(emails)}</div><div class="lbl">EMAILS</div></div>
</div>
{section('🛡️ Security Agent', sec_metrics_html + sec_html, bool(sec_html or sec_stats))}
{section('Principais Achados — CRITICAL &amp; HIGH', '<table><tr><th>Pontuação</th><th>Label</th><th>URL</th><th>Motivo</th></tr>'+rows_top+'</table>', bool(top))}
{section(f'Segredos Encontrados ({len(secrets)})', '<table><tr><th>Tipo</th><th>Severidade</th><th>Detecção</th><th>Valor</th><th>Origem</th></tr>'+rows_sec+'</table>', bool(secrets))}
{section(f'PII Detectado ({len(pii)})', '<table><tr><th>Tipo</th><th>Valor</th><th>Descrição</th><th>Origem</th></tr>'+rows_pii+'</table>', bool(pii))}
{section(f'E-mails Coletados ({len(emails)})', '<table><tr><th>Categoria</th><th>E-mail</th><th>Origem</th></tr>'+rows_email+'</table>', bool(emails))}
{section('Subdomínios Encontrados', '<table><tr><th>Domínio Base</th><th>Subdomínios</th></tr>'+rows_subs+'</table>', bool(subs))}
{section(f'CVE / Dorks de Follow-up ({len(cve_d)})', '<table><tr><th>Dork</th></tr>'+rows_cve+'</table>', bool(cve_d))}
{'<h2>Padrões</h2><div class="card"><ul>'+pats_html+'</ul></div>' if pats else ''}
{'<h2>Recomendações</h2><div class="card"><ul>'+recs_html+'</ul></div>' if recs else ''}
<h2>Todos os Resultados ({len(results)})</h2>
<div class="card"><table><tr><th>Pontuação</th><th>Label</th><th>URL</th><th>Título</th></tr>{rows_all}</table></div>
<footer>DorkEye Project | Agents v3.1 &mdash; {now}</footer>
</body></html>"""

    def _json(self, results, analysis, secrets, counts, target, extra=None) -> str:
        extra = extra or {}
        return json.dumps({
            "meta": {
                "generated_at": datetime.now().isoformat(),
                "target":       target or "",
                "engine":       "DorkEye v5.0 + Agents v3.1",
            },
            "metrics": {
                "total":     len(results),
                "by_label":  counts,
                "secrets":   len(secrets),
                "pii":       len(extra.get("pii", [])),
                "emails":    len(extra.get("emails", [])),
                "subdomains": sum(len(v) for v in extra.get("subdomains", {}).values()),
            },
            "security": {
                "stats":   extra.get("security_stats", {}),
                "threats": extra.get("security_threats", []),
            },
            "analysis":   analysis,
            "secrets":    secrets,
            "pii":        extra.get("pii", []),
            "emails":     extra.get("emails", []),
            "subdomains": extra.get("subdomains", {}),
            "cve_dorks":  extra.get("cve_dorks", []),
            "results":    results,
        }, indent=2, ensure_ascii=False)

    @staticmethod
    def _fix_ext(path: str, fmt: str) -> str:
        ext_map = {"md": ".md", "html": ".html", "json": ".json"}
        p, wanted = Path(path), ext_map.get(fmt, ".html")
        return str(p) if p.suffix.lower() == wanted else str(p.with_suffix(wanted))

# ══════════════════════════════════════════════════════════════════════════════
# AGENTE DE HEADER INTEL
# ══════════════════════════════════════════════════════════════════════════════

_SECURITY_HEADERS_REQUIRED = {
    "strict-transport-security": "HSTS ausente — risco de MITM",
    "content-security-policy":   "CSP ausente — risco de XSS",
    "x-frame-options":           "Proteção contra clickjacking ausente",
    "x-content-type-options":    "Proteção contra MIME sniffing ausente",
    "referrer-policy":           "Referrer-Policy ausente",
    "permissions-policy":        "Permissions-Policy ausente",
}

_INFO_LEAK_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-wordpress-cache",
    "x-runtime", "x-rack-cache", "via",
]

_OUTDATED_VERSION_RE = re.compile(
    r"(?:apache|nginx|php|openssl|iis|tomcat|jetty|lighttpd)[/\s]"
    r"(\d+\.\d+(?:\.\d+)?)",
    re.I,
)


class HeaderIntelAgent(BaseAgent):
    """
    Analisa headers de resposta HTTP salvos pelo PageFetchAgent.

    Para cada resultado com 'response_headers' detecta:
      - Vazamentos de info: Server, X-Powered-By, versões de software
      - Security headers ausentes: HSTS, CSP, X-Frame-Options etc.
      - Versões de software desatualizadas em valores de header

    Adiciona 'header_intel' (dict) a cada resultado processado.
    Não faz requests HTTP — trabalha sobre dados já presentes.
    """

    def __init__(self, plugin=None):
        super().__init__(plugin, name="HeaderIntelAgent")

    def run(self, results: List[dict]) -> List[dict]:
        candidates = [r for r in results if r.get("response_headers")]
        if not candidates:
            _log(f"[{self.name}] Nenhum header disponível — rode com --analyze-fetch.", style="dim")
            return results

        _log(f"[{self.name}] Analisando headers de {len(candidates)} resultados...", style="bold cyan")

        total_findings = 0
        for r in candidates:
            intel = self._analyze(r["response_headers"], r.get("url", ""))
            r["header_intel"] = intel
            n = len(intel.get("info_leaks", [])) + len(intel.get("missing_security", []))
            if n:
                total_findings += n
                _log(
                    f"[{self.name}] [{r.get('triage_label','?')}] "
                    f"{n} achado(s) → {r.get('url','')[:65]}",
                    style="yellow"
                )

        _log(f"[{self.name}] Concluído: {total_findings} achado(s) de header no total.", style="bold green")
        return results

    def _analyze(self, headers: dict, url: str) -> dict:
        intel = {
            "url":              url,
            "info_leaks":       [],
            "missing_security": [],
            "outdated":         [],
        }
        headers_lc = {k.lower(): v for k, v in headers.items()}

        for h in _INFO_LEAK_HEADERS:
            val = headers_lc.get(h, "")
            if val:
                entry = {"header": h, "value": val[:120]}
                # Verifica versões desatualizadas
                m = _OUTDATED_VERSION_RE.search(val)
                if m:
                    entry["version"] = m.group(0)
                    intel["outdated"].append(entry)
                intel["info_leaks"].append(entry)

        for h, reason in _SECURITY_HEADERS_REQUIRED.items():
            if h not in headers_lc:
                intel["missing_security"].append({"header": h, "reason": reason})

        if headers_lc.get("x-debug") or headers_lc.get("x-debug-token"):
            intel["info_leaks"].append({"header": "x-debug", "value": "headers de debug expostos"})
        if headers_lc.get("x-cache-debug"):
            intel["info_leaks"].append({"header": "x-cache-debug", "value": headers_lc["x-cache-debug"][:80]})

        return intel

# ══════════════════════════════════════════════════════════════════════════════
# AGENTE DE TECH FINGERPRINT
# ══════════════════════════════════════════════════════════════════════════════

# FIX #3: * → _ (naming error from copy/paste)
_TECH_SIGNATURES: List[Tuple[re.Pattern, str, str]] = [
    # CMS
    (re.compile(r"wp-content|wp-json|wordpress",                        re.I), "WordPress",     "cms"),
    # FIX #4 regex lógica: "option=com*" → "option=com_\w*"
    (re.compile(r"joomla|option=com_\w*",                               re.I), "Joomla",        "cms"),
    (re.compile(r"drupal|sites/default",                                re.I), "Drupal",         "cms"),
    (re.compile(r"magento|mage/|varien/",                               re.I), "Magento",        "cms"),
    (re.compile(r"prestashop|modules/paypal",                           re.I), "PrestaShop",     "cms"),
    (re.compile(r"typo3|fileadmin/",                                    re.I), "TYPO3",          "cms"),
    (re.compile(r"shopify",                                             re.I), "Shopify",        "cms"),
    # FIX #5 menor: "wix.com" → "wix\.com"
    (re.compile(r"wix\.com|wixstatic",                                  re.I), "Wix",            "cms"),
    # Framework
    (re.compile(r"laravel|artisan|eloquent",                            re.I), "Laravel",        "framework"),
    # FIX #6 menor: "wsgi.py|manage.py" → "wsgi\.py|manage\.py"
    (re.compile(r"django|wsgi\.py|manage\.py",                         re.I), "Django",         "framework"),
    (re.compile(r"rails|ruby on rails|action_controller",              re.I), "Rails",          "framework"),
    (re.compile(r"flask|werkzeug",                                      re.I), "Flask",          "framework"),
    # FIX #7 menor: "express.js" → "express\.js"
    (re.compile(r"express\.js|expressjs",                               re.I), "Express.js",     "framework"),
    # FIX #2 crítico: "*next/static" → "_next/static" + "next.js" → "next\.js"
    (re.compile(r"next\.js|_next/static",                               re.I), "Next.js",        "framework"),
    (re.compile(r"nuxt|nuxtjs",                                         re.I), "Nuxt.js",        "framework"),
    # Bibliotecas JS (com versão)
    (re.compile(r"jquery[/-](\d+\.\d+\.\d+)",                          re.I), "jQuery",         "js_lib"),
    (re.compile(r"react(?:\.min)?\.js|react-dom",                      re.I), "React",          "js_lib"),
    (re.compile(r"vue(?:\.min)?\.js|vue@\d",                           re.I), "Vue.js",         "js_lib"),
    (re.compile(r"angular(?:\.min)?\.js|angular/core",                 re.I), "Angular",        "js_lib"),
    (re.compile(r"bootstrap[/-](\d+\.\d+\.\d+)",                      re.I), "Bootstrap",      "js_lib"),
    # Server / infra
    (re.compile(r"apache[/ ](\d+\.\d+)",                               re.I), "Apache",         "server"),
    (re.compile(r"nginx[/ ](\d+\.\d+)",                                re.I), "Nginx",          "server"),
    (re.compile(r"microsoft-iis[/ ](\d+\.\d+)",                       re.I), "IIS",            "server"),
    (re.compile(r"openssl[/ ](\d+\.\d+)",                              re.I), "OpenSSL",        "server"),
    (re.compile(r"php[/ ](\d+\.\d+)",                                  re.I), "PHP",            "lang"),
    (re.compile(r"python[/ ](\d+\.\d+)",                               re.I), "Python",         "lang"),
    (re.compile(r"node\.js[/ ](\d+\.\d+)",                             re.I), "Node.js",        "lang"),
    # DevOps / infra
    (re.compile(r"jenkins|hudson",                                      re.I), "Jenkins",        "devops"),
    (re.compile(r"gitlab",                                              re.I), "GitLab",         "devops"),
    (re.compile(r"kibana",                                              re.I), "Kibana",         "devops"),
    (re.compile(r"grafana",                                             re.I), "Grafana",        "devops"),
    (re.compile(r"docker|dockerfile",                                   re.I), "Docker",         "devops"),
    (re.compile(r"kubernetes|k8s",                                      re.I), "Kubernetes",     "devops"),
    (re.compile(r"elasticsearch",                                       re.I), "Elasticsearch",  "devops"),
    # DB panels
    # FIX #8 regex lógica: "pma*" → "pma_"
    (re.compile(r"phpmyadmin|pma_",                                     re.I), "phpMyAdmin",     "db_panel"),
    # FIX #9 menor: "adminer.php" → "adminer\.php"
    (re.compile(r"adminer\.php|adminer/",                               re.I), "Adminer",        "db_panel"),
    (re.compile(r"pgadmin",                                             re.I), "pgAdmin",        "db_panel"),
]

_TECH_CVE_DORK_TEMPLATES: Dict[str, List[str]] = {
    "WordPress":  [
        'site:{domain} inurl:wp-login.php',
        'site:{domain} inurl:xmlrpc.php',
        'site:{domain} inurl:wp-config.php.bak',
    ],
    "Joomla":     ['site:{domain} inurl:configuration.php', 'site:{domain} inurl:/administrator/'],
    "Drupal":     ['site:{domain} inurl:CHANGELOG.txt', 'site:{domain} inurl:sites/default/files'],
    "Laravel":    ['site:{domain} inurl:.env', 'site:{domain} filetype:log storage/logs'],
    "Django":     ['site:{domain} "DisallowedHost"', 'site:{domain} "DEBUG = True"'],
    "phpMyAdmin": ['site:{domain} intitle:"phpMyAdmin" inurl:index.php'],
    "Jenkins":    ['site:{domain} intitle:"Dashboard [Jenkins]"', 'site:{domain} inurl:/jenkins/api/'],
    "Kibana":     ['site:{domain} inurl:app/kibana', 'site:{domain} intitle:"Kibana"'],
    "Grafana":    ['site:{domain} inurl:3000/login intitle:Grafana'],
    "jQuery":     ['site:{domain} inurl:jquery-1', 'site:{domain} inurl:jquery-2'],
}


class TechFingerprintAgent(BaseAgent):
    """
    Detecta tecnologias usadas pelo alvo a partir de page_content + response_headers.

    Para cada resultado com conteúdo disponível:
      - Identifica CMS, frameworks, bibliotecas JS, servidores, linguagens
      - Tenta extrair versões específicas
      - Produz 'tech_fingerprint' (dict) e adiciona dorks de CVE direcionados
        para alimentar o DorkCrawlerAgent na próxima rodada

    Adiciona 'tech_fingerprint' a cada resultado processado.
    Também retorna 'cve_dorks' (List[str]) no valor de retorno.
    """

    def __init__(self, plugin=None):
        super().__init__(plugin, name="TechFingerprintAgent")

    def run(self, results: List[dict]) -> List[dict]:
        candidates = [
            r for r in results
            if r.get("page_content") or r.get("response_headers") or r.get("snippet")
        ]
        if not candidates:
            _log(f"[{self.name}] Nenhum conteúdo disponível.", style="dim")
            return results

        _log(f"[{self.name}] Fingerprinting de {len(candidates)} resultados...", style="bold cyan")

        total_techs = 0
        for r in candidates:
            text = " ".join(filter(None, [
                r.get("page_content", ""),
                r.get("snippet", ""),
                r.get("url", ""),
                r.get("title", ""),
                " ".join(str(v) for v in (r.get("response_headers") or {}).values()),
            ]))
            fp = self._fingerprint(text, r.get("url", ""))
            if fp["techs"]:
                r["tech_fingerprint"] = fp
                total_techs += len(fp["techs"])
                _log(
                    f"[{self.name}] [{r.get('triage_label','?')}] "
                    f"{', '.join(t['name'] for t in fp['techs'][:5])} — {r.get('url','')[:55]}",
                    style="cyan"
                )

        _log(f"[{self.name}] Concluído: {total_techs} tecnologias detectadas.", style="bold green")
        return results

    def _fingerprint(self, text: str, url: str) -> dict:
        fp: dict = {"url": url, "techs": [], "cve_dorks": []}
        seen: set = set()

        domain = ""
        try:
            domain = urlparse(url).netloc
        except Exception:
            pass

        for pattern, name, category in _TECH_SIGNATURES:
            m = pattern.search(text)
            if m and name not in seen:
                seen.add(name)
                entry: dict = {"name": name, "category": category}
                # Tenta extrair a versão do grupo de captura
                if m.lastindex:
                    entry["version"] = m.group(1)
                fp["techs"].append(entry)

                if name in _TECH_CVE_DORK_TEMPLATES and domain:
                    for tmpl in _TECH_CVE_DORK_TEMPLATES[name]:
                        fp["cve_dorks"].append(tmpl.replace("{domain}", domain))

        return fp

    def get_all_cve_dorks(self, results: List[dict]) -> List[str]:
        """Coleta todos os dorks de CVE gerados — a serem passados ao DorkCrawlerAgent."""
        dorks: List[str] = []
        seen: set = set()
        for r in results:
            for d in r.get("tech_fingerprint", {}).get("cve_dorks", []):
                if d not in seen:
                    seen.add(d)
                    dorks.append(d)
        return dorks

# ══════════════════════════════════════════════════════════════════════════════
# AGENTE DE COLETA DE E-MAILS
# ══════════════════════════════════════════════════════════════════════════════

# FIX #10: *EMAIL_RE → _EMAIL_RE
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

_EMAIL_CATEGORIES = {
    "admin":    re.compile(r"^(?:admin|administrator|root|sysadmin|webmaster|hostmaster|postmaster)@", re.I),
    "security": re.compile(r"^(?:security|abuse|vuln|pentest|csirt|cert|soc|noc|infosec)@",          re.I),
    "info":     re.compile(r"^(?:info|contact|hello|support|help|service|sales|marketing)@",          re.I),
    "noreply":  re.compile(r"^(?:no.?reply|noreply|donotreply|mailer.?daemon|bounce)@",               re.I),
}


class EmailHarvesterAgent(BaseAgent):
    """
    Coleta e categoriza endereços de e-mail a partir de snippet + page_content.

    Categorias: admin, security, info, noreply, personal (todo o resto).
    Produz 'emails_found' (List[dict]) para o resultado e uma lista global
    acessível via get_all_emails().

    Não faz requests HTTP — trabalha sobre dados já presentes.
    """

    def __init__(self, plugin=None):
        super().__init__(plugin, name="EmailHarvesterAgent")
        self._global_emails: Dict[str, dict] = {}  # email → entry, dedup global

    def run(self, results: List[dict]) -> List[dict]:
        candidates = [
            r for r in results
            if r.get("page_content") or r.get("snippet")
        ]
        if not candidates:
            _log(f"[{self.name}] Nenhum conteúdo disponível.", style="dim")
            return results

        _log(f"[{self.name}] Coleta de e-mails em {len(candidates)} resultados...", style="bold cyan")

        for r in candidates:
            text = (r.get("page_content", "") or "") + " " + (r.get("snippet", "") or "")
            found = self._harvest(text, r.get("url", ""))
            if found:
                r["emails_found"] = found
                _log(
                    f"[{self.name}] {len(found)} e-mail(s) → {r.get('url','')[:65]}",
                    style="yellow"
                )

        total = len(self._global_emails)
        _log(f"[{self.name}] Concluído: {total} e-mails únicos encontrados.", style="bold green")
        return results

    def _harvest(self, text: str, source_url: str) -> List[dict]:
        found = []
        for m in _EMAIL_RE.finditer(text):
            email = m.group(0).lower().strip()
            if email in self._global_emails:
                continue
            category = self._categorize(email)
            entry = {
                "email":    email,
                "category": category,
                "source":   source_url,
            }
            self._global_emails[email] = entry
            found.append(entry)
        return found

    @staticmethod
    def _categorize(email: str) -> str:
        for cat, pat in _EMAIL_CATEGORIES.items():
            if pat.match(email):
                return cat
        return "personal"

    def get_all_emails(self) -> List[dict]:
        """Retorna todos os e-mails coletados, ordenados por categoria."""
        order = {"admin": 0, "security": 1, "info": 2, "personal": 3, "noreply": 4}
        return sorted(self._global_emails.values(), key=lambda e: order.get(e["category"], 9))

# ══════════════════════════════════════════════════════════════════════════════
# AGENTE DETECTOR DE PII
# ══════════════════════════════════════════════════════════════════════════════

class PiiDetectorAgent(BaseAgent):
    """
    Detecta dados pessoais (PII) em snippet + page_content.

    Tipos detectados: e-mail, telefone (IT/EU/US), IBAN, código fiscal italiano,
    cartão de crédito (validação Luhn), SSN dos EUA, data de nascimento, passaporte,
    IPs públicos.

    Adiciona 'pii_found' (List[dict]) a cada resultado com achados.
    Separado do SecretsAgent — PII ≠ credenciais técnicas.
    """

    def __init__(self, plugin=None, max_content: int = 8000):
        super().__init__(plugin, name="PiiDetectorAgent")
        self.max_content = max_content

    def run(self, results: List[dict]) -> List[dict]:
        candidates = [
            r for r in results
            if r.get("page_content") or r.get("snippet")
        ]
        if not candidates:
            _log(f"[{self.name}] Nenhum conteúdo disponível.", style="dim")
            return results

        _log(f"[{self.name}] Scan de PII em {len(candidates)} resultados...", style="bold cyan")

        total_found = 0
        for r in candidates:
            content = ((r.get("page_content", "") or "") + " " + (r.get("snippet", "") or ""))
            content = content[:self.max_content]
            findings = self._scan(content, r.get("url", ""))
            if findings:
                r["pii_found"] = findings
                total_found += len(findings)
                _log(
                    f"[{self.name}] {len(findings)} PII → "
                    f"[{r.get('triage_label','?')}] {r.get('url','')[:60]}",
                    style="bold red"
                )

        _log(
            f"[{self.name}] Concluído: {total_found} PII no total.",
            style="bold green" if total_found == 0 else "bold red"
        )
        return results

    def _scan(self, content: str, url: str) -> List[dict]:
        findings = []
        seen: set = set()

        for category, pattern, description, has_group in _PII_PATTERNS:
            for match in pattern.finditer(content):
                if has_group and match.lastindex:
                    raw_value = match.group(1).strip()
                else:
                    raw_value = match.group(0).strip()

                if not raw_value or len(raw_value) < 4:
                    continue

                if category == "CREDIT_CARD" and not _luhn_check(raw_value):
                    continue

                norm = re.sub(r"\s", "", raw_value.lower())
                if norm in seen:
                    continue
                seen.add(norm)

                start   = max(0, match.start() - 50)
                end     = min(len(content), match.end() + 50)
                context = content[start:end].replace("\n", " ").strip()

                findings.append({
                    "type":    category,
                    "value":   _censor(raw_value, visible=3),
                    "desc":    description,
                    "context": context[:140],
                    "source":  url,
                })

        return findings

# ══════════════════════════════════════════════════════════════════════════════
# AGENTE DE COLETA DE SUBDOMÍNIOS
# ══════════════════════════════════════════════════════════════════════════════

class SubdomainHarvesterAgent(BaseAgent):
    """
    Extrai subdomínios de URL + snippet + page_content de todos os resultados.

    Para cada domínio base detectado coleta subdomínios únicos, os deduplica
    e gera dorks 'site:sub.domain.*' prontos para serem injetados no
    DorkCrawlerAgent na próxima rodada.

    Adiciona 'subdomains' (List[str]) a cada resultado e produz uma lista global
    acessível via get_all_subdomains() e get_followup_dorks().
    """

    def __init__(self, plugin=None):
        super().__init__(plugin, name="SubdomainHarvesterAgent")
        self._global_subdomains: Dict[str, set] = {}

    def run(self, results: List[dict]) -> List[dict]:
        if not results:
            return results

        _log(f"[{self.name}] Coleta de subdomínios em {len(results)} resultados...", style="bold cyan")

        base_domains: set = set()
        for r in results:
            bd = self._base_domain(r.get("url", ""))
            if bd:
                base_domains.add(bd)
        if not base_domains:
            _log(f"[{self.name}] Nenhum domínio base encontrado.", style="dim")
            return results

        _log(f"[{self.name}] Domínios base: {', '.join(list(base_domains)[:5])}", style="dim")

        for r in results:
            text = " ".join(filter(None, [
                r.get("url", ""),
                r.get("snippet", ""),
                r.get("page_content", ""),
                r.get("title", ""),
            ]))
            found_subs = []
            for bd in base_domains:
                subs = self._extract_subdomains(text, bd)
                for s in subs:
                    if bd not in self._global_subdomains:
                        self._global_subdomains[bd] = set()
                    self._global_subdomains[bd].add(s)
                    found_subs.append(s)
            if found_subs:
                r["subdomains"] = sorted(set(found_subs))

        total = sum(len(v) for v in self._global_subdomains.values())
        _log(f"[{self.name}] Concluído: {total} subdomínios únicos encontrados.", style="bold green")
        for bd, subs in self._global_subdomains.items():
            _log(f"[{self.name}]   {bd}: {', '.join(sorted(subs)[:8])}", style="dim")
        return results

    @staticmethod
    def _base_domain(url: str) -> str:
        try:
            host = urlparse(url).netloc.lower()
            host = host.split(":")[0]
            parts = host.split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:])
        except Exception:
            pass
        return ""

    @staticmethod
    def _extract_subdomains(text: str, base_domain: str) -> List[str]:
        escaped = re.escape(base_domain)
        pattern = re.compile(
            r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+?"
            + escaped + r")\b"
        )
        results = []
        for m in pattern.finditer(text):
            sub = m.group(1).lower()
            if sub != base_domain and len(sub) < 200:
                results.append(sub)
        return results

    def get_all_subdomains(self) -> Dict[str, List[str]]:
        """Retorna todos os subdomínios encontrados por domínio base."""
        return {bd: sorted(subs) for bd, subs in self._global_subdomains.items()}

    def get_followup_dorks(self) -> List[str]:
        """Gera dorks site:subdomain para alimentar o DorkCrawlerAgent."""
        dorks = []
        for bd, subs in self._global_subdomains.items():
            for sub in sorted(subs):
                dorks.append(f'site:{sub}')
                dorks.append(f'site:{sub} inurl:admin')
                dorks.append(f'site:{sub} inurl:.env OR inurl:.git')
        return dorks

# ══════════════════════════════════════════════════════════════════════════════
# AGENTE DORK CRAWLER — dorking recursivo adaptativo
# ══════════════════════════════════════════════════════════════════════════════

# FIX #11: *CMS_DORK_TEMPLATES → _CMS_DORK_TEMPLATES
_CMS_DORK_TEMPLATES: Dict[str, List[str]] = {
    "wordpress": [
        'site:{domain} inurl:wp-config.php',
        'site:{domain} inurl:wp-content/uploads filetype:php',
        'site:{domain} inurl:wp-json/wp/v2/users',
        'site:{domain} inurl:xmlrpc.php',
        'site:{domain} inurl:wp-admin/install.php',
        'site:{domain} filetype:log inurl:wp-content',
    ],
    "joomla": [
        'site:{domain} inurl:configuration.php',
        'site:{domain} inurl:administrator/index.php',
        'site:{domain} inurl:components/com_',
        'site:{domain} filetype:xml inurl:joomla',
    ],
    "drupal": [
        'site:{domain} inurl:sites/default/settings.php',
        'site:{domain} inurl:/user/login',
        'site:{domain} inurl:node?destination=',
        'site:{domain} filetype:php inurl:modules',
    ],
    "laravel": [
        'site:{domain} inurl:.env',
        'site:{domain} filetype:log inurl:storage/logs',
        'site:{domain} inurl:public/index.php',
        'site:{domain} inurl:api/v1',
    ],
    "django": [
        'site:{domain} inurl:admin/',
        'site:{domain} "debug" "traceback" "request"',
        'site:{domain} inurl:static/ filetype:py',
        'site:{domain} filetype:sqlite3',
    ],
    "phpmyadmin": [
        'site:{domain} inurl:phpmyadmin/index.php',
        'site:{domain} inurl:pma/ intitle:phpMyAdmin',
        'site:{domain} inurl:phpmyadmin setup',
    ],
    "adminer": [
        'site:{domain} inurl:adminer.php',
        'site:{domain} inurl:adminer/ intitle:Adminer',
    ],
    "magento": [
        'site:{domain} inurl:/admin/ intitle:Magento',
        'site:{domain} inurl:app/etc/local.xml',
        'site:{domain} inurl:downloader/index.php',
    ],
    "prestashop": [
        'site:{domain} inurl:admin123',
        'site:{domain} inurl:/config/settings.inc.php',
        'site:{domain} inurl:modules/paypal',
    ],
}

_PATH_DORK_TEMPLATES: List[str] = [
    'site:{domain} inurl:{path}',
    'site:{domain} inurl:{path} filetype:php',
    'site:{domain} inurl:{path} filetype:env',
    'site:{domain} inurl:{path} filetype:log',
    'site:{domain} inurl:{path} filetype:sql',
    'site:{domain} inurl:{path} filetype:bak',
    'site:{domain} inurl:{path} intitle:"index of"',
]

_EXT_DORK_TEMPLATES: Dict[str, List[str]] = {
    ".env":    ['site:{domain} filetype:env', 'site:{domain} inurl:.env.backup', 'site:{domain} inurl:.env.old'],
    ".sql":    ['site:{domain} filetype:sql', 'site:{domain} inurl:backup filetype:sql', 'site:{domain} inurl:dump filetype:sql'],
    ".bak":    ['site:{domain} filetype:bak', 'site:{domain} inurl:backup filetype:bak', 'site:{domain} ext:bak'],
    ".log":    ['site:{domain} filetype:log', 'site:{domain} inurl:logs filetype:log', 'site:{domain} ext:log inurl:error'],
    ".php":    ['site:{domain} filetype:php inurl:config', 'site:{domain} filetype:php inurl:install', 'site:{domain} filetype:php inurl:setup'],
    ".xml":    ['site:{domain} filetype:xml inurl:config', 'site:{domain} filetype:xml inurl:api', 'site:{domain} ext:xml inurl:sitemap'],
    ".json":   ['site:{domain} filetype:json inurl:api', 'site:{domain} filetype:json inurl:config', 'site:{domain} ext:json inurl:secret'],
    ".yaml":   ['site:{domain} filetype:yaml', 'site:{domain} ext:yml inurl:config', 'site:{domain} filetype:yml inurl:docker'],
    ".conf":   ['site:{domain} filetype:conf', 'site:{domain} ext:conf inurl:nginx', 'site:{domain} ext:conf inurl:apache'],
    ".sqlite": ['site:{domain} filetype:sqlite', 'site:{domain} ext:db', 'site:{domain} filetype:sqlite3'],
    ".git":    ['site:{domain} inurl:.git/config', 'site:{domain} inurl:.git/HEAD', 'site:{domain} inurl:.git/COMMIT_EDITMSG'],
}

# TECH_DETECTION → _TECH_DETECTION + regex logic
_TECH_DETECTION: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"wp-content|wp-admin|wordpress",                re.I), "wordpress"),
    # FIX: "option=com*" → "option=com_\w*"
    (re.compile(r"joomla|com_content|option=com_\w*",            re.I), "joomla"),
    (re.compile(r"drupal|sites/default|node/\d+",                re.I), "drupal"),
    # FIX menor: "blade.php" → "blade\.php"
    (re.compile(r"laravel|artisan|eloquent|blade\.php",          re.I), "laravel"),
    # FIX menor: "settings.py|manage.py" → "settings\.py|manage\.py"
    (re.compile(r"django|wsgi|settings\.py|manage\.py",         re.I), "django"),
    (re.compile(r"phpmyadmin|pma_|phpMyAdmin",                   re.I), "phpmyadmin"),
    # FIX menor: "adminer.php" → "adminer\.php"
    (re.compile(r"adminer\.php|adminer/",                        re.I), "adminer"),
    (re.compile(r"magento|mage/|varien/",                        re.I), "magento"),
    (re.compile(r"prestashop|/modules/|/themes/community",       re.I), "prestashop"),
]

_INTERESTING_PATHS = re.compile(
    r"/(admin|administrator|backup|backups|config|configs|api|v1|v2|v3|"
    r"debug|test|tests|dev|staging|old|archive|logs|log|uploads|files|"
    r"db|database|sql|data|export|dump|install|setup|portal|panel|"
    r"private|secret|hidden|internal|manage|management|dashboard)/",
    re.I
)

_SUSPICIOUS_PARAMS = re.compile(
    r"[?&](id|file|path|page|url|redirect|include|require|src|doc|"
    r"template|view|module|action|query|search|q|load|read|show|"
    r"download|open|image|img|lang|locale)=",
    re.I
)


class DorkCrawlerAgent(BaseAgent):
    """
    Agente de crawl recursivo adaptativo via DDGS.

    Roda múltiplas rodadas de dorking, refinando automaticamente os dorks
    a cada rodada com base em padrões encontrados nos resultados anteriores.
    Zero LLM — inteiramente baseado em regex, templates e pattern matching.

    Pipeline de rodada:
      1. Busca com os dorks atuais via DDGS
      2. TriageAgent classifica os novos resultados
      3. _extract_intelligence() extrai padrões: domínios, paths, CMS, ext
      4. _generate_followup_dorks() produz novos dorks direcionados
      5. Verifica as condições de parada
      6. Reinicia da etapa 1 com os novos dorks

    Condições de parada (todas avaliadas antes de disparar):
      - Máximo de rodadas alcançado
      - Máximo de resultados totais alcançado
      - Nenhum novo resultado HIGH/CRITICAL na última rodada
      - Nenhum novo dork pode ser gerado (todos já usados)
    """

    def __init__(
        self,
        plugin          = None,
        max_rounds:     int   = 4,
        max_results:    int   = 300,
        results_per_dork: int = 20,
        min_new_high:   int   = 1,
        delay_between:  float = 3.0,
        stealth:        bool  = False,
    ):
        super().__init__(plugin, name="DorkCrawlerAgent")
        self.max_rounds       = max_rounds
        self.max_results      = max_results
        self.results_per_dork = results_per_dork
        self.min_new_high     = min_new_high
        self.delay_between    = delay_between * (2.0 if stealth else 1.0)
        self.stealth          = stealth

        self._all_results:   List[dict] = []
        self._seen_urls:     set        = set()
        self._used_dorks:    set        = set()
        self._round_log:     List[dict] = []

    def run(
        self,
        seed_dorks: List[str],
        target:     str = "",
    ) -> dict:
        if not seed_dorks:
            _log(f"[{self.name}] Nenhum dork seed fornecido.", style="yellow")
            return self._build_output("no_seed_dorks")

        _log(
            f"[{self.name}] Iniciando crawl recursivo — "
            f"seed:{len(seed_dorks)} dork | "
            f"max_rounds:{self.max_rounds} | "
            f"max_results:{self.max_results} | "
            f"stealth:{'on' if self.stealth else 'off'}",
            style="bold cyan"
        )
        if target:
            _log(f"[{self.name}] Alvo: {target}", style="cyan")

        current_dorks = list(seed_dorks)
        stop_reason   = "completed"

        try:
            from ddgs import DDGS
        except ImportError:
            _log(f"[{self.name}] ddgs não instalado. Instale com: pip install ddgs", style="red")
            return self._build_output("ddgs_missing")

        triage_agent = TriageAgent(plugin=self.plugin)

        for round_n in range(1, self.max_rounds + 1):
            if not current_dorks:
                stop_reason = "no_new_dorks"
                break
            if len(self._all_results) >= self.max_results:
                stop_reason = "max_results_reached"
                break

            _log(
                f"\n[{self.name}] ── Rodada {round_n}/{self.max_rounds} "
                f"({len(current_dorks)} dork, "
                f"{len(self._all_results)} resultados até agora) ──",
                style="bold cyan"
            )

            round_results = self._search_dorks(current_dorks, DDGS)

            new_results = []
            for r in round_results:
                url = r.get("url", "")
                if url and url not in self._seen_urls:
                    self._seen_urls.add(url)
                    new_results.append(r)

            _log(
                f"[{self.name}] Rodada {round_n}: "
                f"{len(round_results)} encontrados, {len(new_results)} novos únicos",
                style="cyan"
            )

            if not new_results:
                _log(f"[{self.name}] Nenhum novo resultado — parando.", style="yellow")
                stop_reason = "no_new_results"
                break

            new_triaged = triage_agent.run(new_results, use_llm=self.has_llm)
            self._all_results.extend(new_triaged)

            n_high = sum(
                1 for r in new_triaged
                if r.get("triage_label") in ("CRITICAL", "HIGH")
            )
            _log(
                f"[{self.name}] Triage rodada {round_n}: "
                f"CRITICAL+HIGH={n_high} | "
                f"TOTAL={len(self._all_results)}",
                style="green" if n_high > 0 else "dim"
            )

            self._round_log.append({
                "round":       round_n,
                "dorks_used":  list(current_dorks),
                "found":       len(round_results),
                "new_unique":  len(new_results),
                "high_crit":   n_high,
                "total_so_far": len(self._all_results),
            })

            if round_n > 1 and n_high < self.min_new_high:
                _log(
                    f"[{self.name}] Apenas {n_high} novos HIGH/CRITICAL "
                    f"(min={self.min_new_high}) — parar.",
                    style="yellow"
                )
                stop_reason = "no_new_findings"
                break

            if round_n == self.max_rounds:
                stop_reason = "max_rounds_reached"
                break

            intelligence = self._extract_intelligence(new_triaged)
            self._log_intelligence(intelligence, round_n)

            next_dorks = self._generate_followup_dorks(intelligence)
            if not next_dorks:
                _log(f"[{self.name}] Nenhum novo dork pode ser gerado — parando.", style="yellow")
                stop_reason = "no_new_dorks"
                break

            current_dorks = next_dorks
            _log(
                f"[{self.name}] {len(current_dorks)} dorks de follow-up gerados para a rodada {round_n+1}",
                style="bold cyan"
            )
            for d in current_dorks[:8]:
                _log(f"  → {d}", style="dim")
            if len(current_dorks) > 8:
                _log(f"  ... e mais {len(current_dorks)-8}", style="dim")

            if round_n < self.max_rounds:
                _log(
                    f"[{self.name}] Dormindo {self.delay_between:.1f}s "
                    f"(stealth: {'on' if self.stealth else 'off'})...",
                    style="dim"
                )
                time.sleep(self.delay_between)

        self._all_results.sort(
            key=lambda x: x.get("triage_score", 0), reverse=True
        )

        output = self._build_output(stop_reason)
        self._print_summary(output)
        return output

    def _search_dorks(self, dorks: List[str], DDGS) -> List[dict]:
        results = []
        for dork in dorks:
            if dork in self._used_dorks:
                continue
            self._used_dorks.add(dork)
            _log(f"[{self.name}] Buscando: {dork[:80]}", style="dim")
            try:
                for item in DDGS().text(dork, max_results=self.results_per_dork):
                    url = item.get("href") or item.get("url", "")
                    if not url:
                        continue
                    results.append({
                        "url":       url,
                        "title":     item.get("title", ""),
                        "snippet":   item.get("body", ""),
                        "dork":      dork,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "extension": Path(urlparse(url).path).suffix.lower(),
                        "category":  "webpage",
                    })
            except Exception as e:
                _log(f"[{self.name}] Erro DDGS '{dork[:50]}': {e}", style="yellow")

            time.sleep(max(1.0, self.delay_between / 3))

        return results

    def _extract_intelligence(self, results: List[dict]) -> dict:
        intelligence: dict = {
            "domains": set(), "paths": set(), "technologies": set(),
            "extensions": set(), "params": set(),
        }
        prioritized = sorted(results, key=lambda r: r.get("triage_score", 0), reverse=True)

        for r in prioritized:
            url      = r.get("url", "")
            title    = r.get("title", "")
            snippet  = r.get("snippet", "") or ""
            combined = f"{url} {title} {snippet}"

            parsed = urlparse(url)
            if parsed.netloc:
                domain = parsed.netloc.lstrip("www.")
                intelligence["domains"].add(domain)

            path = parsed.path
            for m in _INTERESTING_PATHS.finditer(path):
                intelligence["paths"].add(m.group(1).lower())

            for pattern, tech in _TECH_DETECTION:
                if pattern.search(combined):
                    intelligence["technologies"].add(tech)

            ext = Path(path).suffix.lower()
            if ext and ext in _EXT_DORK_TEMPLATES:
                intelligence["extensions"].add(ext)

            for m in _SUSPICIOUS_PARAMS.finditer(url):
                intelligence["params"].add(m.group(1).lower())

        return {k: sorted(v) for k, v in intelligence.items()}

    def _generate_followup_dorks(self, intelligence: dict) -> List[str]:
        generated: set = set()
        domains      = intelligence.get("domains", [])[:8]
        paths        = intelligence.get("paths", [])[:5]
        technologies = intelligence.get("technologies", [])
        extensions   = intelligence.get("extensions", [])
        params       = intelligence.get("params", [])[:4]

        for tech in technologies:
            templates = _CMS_DORK_TEMPLATES.get(tech, [])
            for tmpl in templates:
                for domain in domains:
                    dork = tmpl.format(domain=domain)
                    if dork not in self._used_dorks:
                        generated.add(dork)

        for path in paths:
            for domain in domains[:4]:
                for tmpl in _PATH_DORK_TEMPLATES[:3]:
                    dork = tmpl.format(domain=domain, path=path)
                    if dork not in self._used_dorks:
                        generated.add(dork)

        for ext in extensions:
            templates = _EXT_DORK_TEMPLATES.get(ext, [])
            for tmpl in templates[:2]:
                for domain in domains[:4]:
                    dork = tmpl.format(domain=domain)
                    if dork not in self._used_dorks:
                        generated.add(dork)

        for param in params:
            for domain in domains[:3]:
                for d in [
                    f'site:{domain} inurl:"?{param}="',
                    f'site:{domain} inurl:"{param}=" filetype:php',
                ]:
                    if d not in self._used_dorks:
                        generated.add(d)

        for domain in domains[:5]:
            for d in [
                f'site:{domain} intitle:"index of"',
                f'site:{domain} inurl:backup',
                f'site:{domain} inurl:.git',
                f'site:{domain} inurl:api',
                f'site:{domain} filetype:env',
            ]:
                if d not in self._used_dorks:
                    generated.add(d)

        return list(generated)

    def _log_intelligence(self, intel: dict, round_n: int) -> None:
        parts = []
        if intel.get("domains"):      parts.append(f"domains:{len(intel['domains'])}")
        if intel.get("technologies"): parts.append(f"tech:{','.join(intel['technologies'])}")
        if intel.get("paths"):        parts.append(f"paths:{len(intel['paths'])}")
        if intel.get("extensions"):   parts.append(f"ext:{','.join(intel['extensions'])}")
        if intel.get("params"):       parts.append(f"params:{','.join(intel['params'])}")
        _log(
            f"[{self.name}] Intelligence round {round_n}: "
            + (" | ".join(parts) if parts else "nada novo"),
            style="cyan"
        )

    def _build_output(self, stop_reason: str) -> dict:
        return {
            "results":     self._all_results,
            "rounds":      len(self._round_log),
            "dorks_used":  sorted(self._used_dorks),
            "round_log":   self._round_log,
            "stop_reason": stop_reason,
            "total":       len(self._all_results),
            "critical":    sum(1 for r in self._all_results if r.get("triage_label") == "CRITICAL"),
            "high":        sum(1 for r in self._all_results if r.get("triage_label") == "HIGH"),
            "medium":      sum(1 for r in self._all_results if r.get("triage_label") == "MEDIUM"),
        }

    def _print_summary(self, output: dict) -> None:
        _panel(
            f"  Rodadas concluídas: {output['rounds']}/{self.max_rounds}\n"
            f"  Motivo de parada  : {output['stop_reason']}\n"
            f"  Dorks usados      : {len(output['dorks_used'])}\n"
            f"  Resultados totais : {output['total']}\n"
            f"  CRITICAL          : {output['critical']}\n"
            f"  HIGH              : {output['high']}\n"
            f"  MEDIUM            : {output['medium']}",
            title="[bold cyan][ DorkCrawlerAgent — Resumo do Crawl ][/bold cyan]",
            border="cyan",
        )

# ══════════════════════════════════════════════════════════════════════════════
# CLI INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

def add_crawler_args(parser) -> object:
    """Adiciona as flags --crawl-* ao parser do CLI do DorkEye."""
    g = parser.add_argument_group(
        "Crawl Recursivo — dorking multi-rodada adaptativo (sem IA)"
    )
    g.add_argument("--crawl", action="store_true",
                   help="Ativa o crawl recursivo adaptativo após a busca inicial")
    g.add_argument("--crawl-rounds", type=int, default=4,
                   help="Número máximo de rodadas de refinamento (padrão: 4)")
    g.add_argument("--crawl-max", type=int, default=300,
                   help="Limite total de resultados agregados (padrão: 300)")
    g.add_argument("--crawl-per-dork", type=int, default=20,
                   help="Resultados do DDGS por dork por rodada (padrão: 20)")
    g.add_argument("--crawl-stealth", action="store_true",
                   help="Modo stealth: delays maiores entre buscas")
    g.add_argument("--crawl-report", action="store_true",
                   help="Gera relatório HTML ao final do crawl")
    g.add_argument("--crawl-out", type=str, default=None,
                   help="Path do relatório do crawl (padrão: dorkeye_crawl_<timestamp>.html)")
    return parser


def add_security_args(parser) -> object:
    """Adiciona as flags --security-* ao parser do CLI do DorkEye."""
    g = parser.add_argument_group(
        "Security Agent — detecção de ameaças para phishing, malware, exploits"
    )
    g.add_argument("--no-security", action="store_true",
                   help="Desativa o SecurityAgent no pipeline")
    g.add_argument("--security-mode", type=str, default="passive",
                   choices=["active", "passive"],
                   help="active: bloqueia DANGEROUS/CRITICAL | passive: apenas relata (padrão: passive)")
    g.add_argument("--security-quarantine", action="store_true",
                   help="Salva conteúdo em quarentena em dorkeye_quarantine/")
    return parser


def run_crawl(
    seed_dorks: List[str],
    args,
    target:  str = "",
    plugin       = None,
) -> dict:
    """Entry point para o mappingexpo.py — inicia o DorkCrawlerAgent."""
    crawler = DorkCrawlerAgent(
        plugin           = plugin,
        max_rounds       = getattr(args, "crawl_rounds",   4),
        max_results      = getattr(args, "crawl_max",      300),
        results_per_dork = getattr(args, "crawl_per_dork", 20),
        stealth          = getattr(args, "crawl_stealth",  False),
    )

    output = crawler.run(seed_dorks=seed_dorks, target=target)

    if getattr(args, "crawl_report", False) and output.get("results"):
        fmt = "html"
        out = getattr(args, "crawl_out", None)
        if not out:
            ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
            out = f"dorkeye_crawl_{ts}.{fmt}"

        reporter = ReportAgent()
        reporter.run(
            results     = output["results"],
            analysis    = {},
            target      = target,
            output_path = out,
            fmt         = fmt,
        )
        output["report_path"] = out
        _log(f"[Crawl] Relatório salvo: {out}", style="bold green")

    return output


def run_analysis_pipeline(
    results:    List[dict],
    llm_plugin = None,
    args       = None,
    target:    str = "",
) -> dict:
    """
    Roda o pipeline de análise pós-busca v3.1.

    Funciona SEM LLM (llm_plugin=None):
        1.  TriageAgent             — classifica com regex + bônus de runtime
        2.  PageFetchAgent          — baixa páginas HIGH/CRITICAL (com --analyze-fetch)
        3.  SecurityAgent  [NOVO]   — detecção de phishing/malware/exploit/ofuscação
        4.  HeaderIntelAgent        — analisa headers de resposta
        5.  TechFingerprintAgent    — detecta CMS/frameworks/versões
        6.  SecretsAgent            — scan de segredos + hash + severidade
        7.  PiiDetectorAgent        — detecta PII (CC, IBAN, CF, SSN etc.)
        8.  EmailHarvesterAgent     — coleta e categoriza e-mails
        9.  SubdomainHarvesterAgent — extrai subdomínios, gera dorks de follow-up
        10. ReportAgent             — gera relatório HTML/MD/JSON completo (incl. segurança)
        11. DBPortScanAgent         — escaneia portas DB expostas (opt-in: --dbscan)
    """
    if args is None:
        args = type("A", (), {
            "analyze_fetch":         False,
            "analyze_fetch_max":     20,
            "analyze_no_llm_triage": False,
            "analyze_report":        True,
            "analyze_fmt":           "html",
            "analyze_out":           None,
            "no_security":           False,
            "security_mode":         "passive",
            "security_quarantine":   False,
            "dbscan":                False,
            "dbscan_timeout":        2.5,
            "dbscan_threads":        60,
            "dbscan_ports":          None,
            "dbscan_max_hosts":      200,
        })()

    output = {
        "triaged":          None,
        "secrets_total":    0,
        "pii_total":        0,
        "emails_total":     0,
        "subdomains":       {},
        "cve_dorks":        [],
        "report_path":      None,
        "analysis":         {},
        "security_stats":   {},
        "security_threats": [],
        "dbscan_report":    None,
        "dbscan_stats":     {},
    }

    if not results:
        _log("[Agents] Nenhum resultado para analisar.", style="yellow")
        return output

    mode_label = "LLM + regex" if llm_plugin else "autonomous regex"
    _log(f"[Agents] Pipeline v3.1 — mode: {mode_label}", style="bold cyan")

    # ── 1. Triage ─────────────────────────────────────────────────────────────
    use_llm_triage = (
        llm_plugin is not None
        and not getattr(args, "analyze_no_llm_triage", False)
    )
    triage  = TriageAgent(plugin=llm_plugin)
    triaged = triage.run(results, use_llm=use_llm_triage)
    output["triaged"] = triaged

    counts = {l: 0 for l in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SKIP")}
    for r in triaged:
        counts[r.get("triage_label", "LOW")] = counts.get(r.get("triage_label", "LOW"), 0) + 1

    _panel(
        "\n".join(
            f"  [{counts[l]:>3}]  {l}"
            for l in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SKIP")
        ) + f"\n\n  TOTAL: {len(triaged)}",
        title="[bold cyan][ Resultados do Triage ][/bold cyan]",
        border="cyan",
    )

    # ── 2. Page Fetch (opcional) ──────────────────────────────────────────────
    if getattr(args, "analyze_fetch", False):
        fetch_max = getattr(args, "analyze_fetch_max", 20)
        fetcher   = PageFetchAgent(max_pages=fetch_max)
        triaged   = fetcher.run(triaged)

    # ── 3. Security Agent [NOVO na v3.1] ───────────────────────────────────────
    sec_agent = None
    if not getattr(args, "no_security", False):
        sec_mode       = getattr(args, "security_mode", "passive")
        sec_quarantine = "dorkeye_quarantine" if getattr(args, "security_quarantine", False) else None

        sec_agent = SecurityAgent(mode=sec_mode, quarantine_dir=sec_quarantine)
        triaged   = sec_agent.run(triaged)

        output["security_stats"] = {
            **sec_agent.stats,
            "mode": sec_mode,
        }

        threat_verdicts = sec_agent.get_threats_above(ThreatLevel.LOW)
        output["security_threats"] = [v.to_dict() for v in threat_verdicts]

        if sec_agent.stats["total_scanned"] > 0:
            n_threats = sum(
                sec_agent.stats.get(k, 0)
                for k in ("suspicious", "dangerous", "critical")
            )
            panel_style = "red" if n_threats > 0 else "green"
            _panel(
                sec_agent.generate_console_report(),
                title=f"[bold {panel_style}][ 🛡️ Security Agent — "
                      f"{'ACTIVE' if sec_mode == 'active' else 'PASSIVE'} ][/bold {panel_style}]",
                border=panel_style,
            )

    # ── 4. Header Intel ───────────────────────────────────────────────────────
    header_agent = HeaderIntelAgent()
    triaged      = header_agent.run(triaged)

    # ── 5. Tech Fingerprint ───────────────────────────────────────────────────
    tech_agent = TechFingerprintAgent()
    triaged    = tech_agent.run(triaged)
    cve_dorks  = tech_agent.get_all_cve_dorks(triaged)
    output["cve_dorks"] = cve_dorks
    if cve_dorks:
        _log(f"[Agents] TechFP: {len(cve_dorks)} dorks de CVE gerados.", style="cyan")

    # ── 6. Secrets scan ───────────────────────────────────────────────────────
    use_llm_secrets = llm_plugin is not None
    secrets_agent   = SecretsAgent(plugin=llm_plugin, use_llm=use_llm_secrets)
    triaged         = secrets_agent.run(triaged)

    all_secrets = [s for r in triaged for s in r.get("secrets", [])]
    output["secrets_total"] = len(all_secrets)

    if all_secrets:
        _sev_ord = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_secrets_sorted = sorted(
            all_secrets, key=lambda s: _sev_ord.get(s.get("severity", "LOW"), 9)
        )
        _panel(
            "\n".join(
                f"  [{s.get('severity','?'):8}] [{s.get('detection','?'):5}] "
                f"{s.get('type','?'):14} — {s.get('value','?')} "
                f"({s.get('source','?')[:45]})"
                for s in all_secrets_sorted[:30]
            ),
            title=f"[bold red][ {len(all_secrets)} Segredo(s) Encontrado(s) ][/bold red]",
            border="red",
        )

    # ── 7. PII Detection ──────────────────────────────────────────────────────
    pii_agent = PiiDetectorAgent()
    triaged   = pii_agent.run(triaged)
    all_pii   = [p for r in triaged for p in r.get("pii_found", [])]
    output["pii_total"] = len(all_pii)
    if all_pii:
        _log(f"[Agents] PII: {len(all_pii)} item(ns) de dados pessoais detectado(s).", style="bold red")

    # ── 8. Email Harvesting ───────────────────────────────────────────────────
    email_agent   = EmailHarvesterAgent()
    triaged       = email_agent.run(triaged)
    all_emails    = email_agent.get_all_emails()
    output["emails_total"] = len(all_emails)
    if all_emails:
        _log(f"[Agents] Email: {len(all_emails)} e-mails únicos coletados.", style="cyan")

    # ── 9. Subdomain Harvesting ───────────────────────────────────────────────
    subdomain_agent = SubdomainHarvesterAgent()
    triaged         = subdomain_agent.run(triaged)
    all_subdomains  = subdomain_agent.get_all_subdomains()
    followup_dorks  = subdomain_agent.get_followup_dorks()
    output["subdomains"] = all_subdomains
    output["cve_dorks"]  = list(dict.fromkeys(cve_dorks + followup_dorks))
    if all_subdomains:
        total_subs = sum(len(v) for v in all_subdomains.values())
        _log(f"[Agents] Subdomain: {total_subs} subdomínios encontrados.", style="cyan")

    # ── 11. DB Port Scanner (opcional — ative com --dbscan) ────────────────
    if getattr(args, "dbscan", False):
        if not _DBSCAN_OK:
            _log("[Agents] db_portscan.py não encontrado em Tools/ — DBScan pulado.", style="yellow")
        else:
            _log("[Agents] Etapa 11 — Scanner de Portas DB", style="bold cyan")
            _db_agent = _DBPortScanAgent(
                timeout   = getattr(args, "dbscan_timeout",   2.5),
                threads   = getattr(args, "dbscan_threads",   60),
                ports     = getattr(args, "dbscan_ports",     None),
                max_hosts = getattr(args, "dbscan_max_hosts", 200),
            )
            _db_report = _db_agent.run(triaged)
            if _db_report:
                output["dbscan_report"] = _db_report.to_dict()
                output["dbscan_stats"]  = _db_report.stats
                _db_report.print_summary()
                n_crit = _db_report.stats.get("critical", 0)
                n_high = _db_report.stats.get("high", 0)
                if n_crit or n_high:
                    _panel(
                        "\n".join(
                            f"  [{f.severity}]  {f.host}:{f.port}  [{f.service}]  {f.detail[:80]}"
                            for f in _db_report.critical_findings + _db_report.high_findings
                        ),
                        title=f"[bold magenta][ DBScan — {n_crit} CRITICAL / {n_high} HIGH ][/bold magenta]",
                        border="magenta" if n_crit else "red",
                    )
    # ─────────────────────────────────────────────────────────────────────────

    # ── Análise LLM (apenas se llm_plugin disponível) ────────────────────────────
    analysis: dict = {}
    if llm_plugin:
        try:
            analysis = llm_plugin.analyze_results(triaged, target=target)
            output["analysis"] = analysis
            _sev   = analysis.get("severity", "LOW")
            _sc    = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}
            _style = _sc.get(_sev, "white")
            _panel(
                f"[bold white]Resumo:[/bold white] {analysis.get('summary','N/A')}\n\n"
                f"[bold yellow]De alto valor:[/bold yellow] "
                f"{', '.join(analysis.get('high_value',[])[:5]) or 'nenhum'}\n"
                f"[bold cyan]Padrões:[/bold cyan] "
                f"{', '.join(analysis.get('patterns',[])[:5]) or 'nenhum'}\n"
                f"[bold green]Recomendações:[/bold green] "
                f"{chr(10).join(analysis.get('recommendations',[])[:3]) or 'nenhum'}\n"
                f"[bold white]Severidade:[/bold white] [{_style}]{_sev}[/{_style}]",
                title="[bold magenta][ Análise LLM ][/bold magenta]",
                border="magenta",
            )
        except Exception as e:
            _log(f"[Agents] Erro na análise LLM: {e}", style="yellow")

    # ── 10. Report ────────────────────────────────────────────────────────────
    if getattr(args, "analyze_report", False):
        fmt = getattr(args, "analyze_fmt", "html")
        out = getattr(args, "analyze_out", None)
        if not out:
            ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
            out = f"dorkeye_analysis_{ts}.{fmt}"

        sec_html = ""
        if sec_agent:
            sec_html = sec_agent.generate_html_section()

        reporter = ReportAgent(plugin=llm_plugin)
        reporter.run(
            results     = triaged,
            analysis    = analysis,
            target      = target,
            output_path = out,
            fmt         = fmt,
            extra       = {
                "emails":           all_emails,
                "pii":              all_pii,
                "subdomains":       all_subdomains,
                "cve_dorks":        output["cve_dorks"],
                "security_html":    sec_html,
                "security_stats":   output.get("security_stats", {}),
                "security_threats": output.get("security_threats", []),
            },
        )
        output["report_path"] = out

    # Estatísticas LLM
    if llm_plugin:
        try:
            s = llm_plugin.stats()
            _log(
                f"[Agents] LLM — provider:{s['provider']} | "
                f"cache:{s['cache']} | mem:{s['memory_entries']}",
                style="dim"
            )
        except Exception:
            pass

    return output

# ══════════════════════════════════════════════════════════════════════════════
# STANDALONE — analisa um arquivo JSON de resultados do DorkEye
# ══════════════════════════════════════════════════════════════════════════════

# FIX #1 (continuação): **name** → __name__
if __name__ == "__main__":
    import argparse as _ap
    import sys

    parser = _ap.ArgumentParser(
        description="DorkEye Agents v3.1 — Análise standalone sobre arquivo de resultados",
        formatter_class=_ap.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  # Análise standalone (sem exigência de LLM)\n"
            "  python mappingexpo_agents.py results.json\n"
            "  python mappingexpo_agents.py results.json --analyze-fetch --analyze-fmt=html\n\n"
            "  # Com security agent em modo active + quarentena\n"
            "  python mappingexpo_agents.py results.json --security-mode=active --security-quarantine\n\n"
            "  # Desativa o security agent\n"
            "  python mappingexpo_agents.py results.json --no-security\n\n"
            "  # Com LLM Ollama (opcional — adiciona resumo e análise contextual)\n"
            "  python mappingexpo_agents.py results.json --llm --analyze-fetch\n"
        ),
    )
    parser.add_argument(
        "results_file",
        help="Arquivo JSON de resultados do DorkEye (produzido com -o results.json)",
    )
    parser.add_argument("--target", default="", help="Descrição do alvo (opcional)")
    parser.add_argument("--analyze-fetch",     action="store_true",
                        help="Baixa páginas HIGH/CRITICAL para análise mais precisa")
    parser.add_argument("--analyze-fetch-max", type=int, default=20,
                        help="Máximo de páginas para baixar (padrão: 20)")
    parser.add_argument("--analyze-no-llm-triage", action="store_true",
                        help="Triage apenas com regex (ignora LLM mesmo se disponível)")
    parser.add_argument("--analyze-report",    action="store_true", default=True,
                        help="Gera arquivo de relatório (padrão: True)")
    parser.add_argument("--analyze-fmt",       choices=["html","md","json","txt"],
                        default="html", help="Formato do relatório (padrão: html)")
    parser.add_argument("--analyze-out",       default=None,
                        help="Path de saída do relatório")

    add_security_args(parser)

    # ── DB Port Scanner ───────────────────────────────────────────────────────
    parser.add_argument("--dbscan",           action="store_true",
                        help="Escaneia portas DB abertas nos hosts dos resultados (etapa 11)")
    parser.add_argument("--dbscan-timeout",   type=float, default=2.5,
                        help="Timeout de conexão TCP em segundos (padrão: 2.5)")
    parser.add_argument("--dbscan-threads",   type=int,   default=60,
                        help="Threads de trabalho por host (padrão: 60)")
    parser.add_argument("--dbscan-ports",     type=int,   nargs="+", default=None,
                        help="Sobrescreve a lista de portas (padrão: todas as portas DB conhecidas)")
    parser.add_argument("--dbscan-max-hosts", type=int,   default=200,
                        help="Máximo de hosts para escanear (padrão: 200)")
    # ─────────────────────────────────────────────────────────────────────────

    _llm_available = False
    try:
        from mappingexpo_llm_plugin import add_llm_args, init_llm_plugin
        add_llm_args(parser)
        _llm_available = True
    except ImportError:
        parser.add_argument("--llm", action="store_true",
                            help="(indisponível: mappingexpo_llm_plugin.py não encontrado)")

    args     = parser.parse_args()
    args.llm = getattr(args, "llm", False)

    from pathlib import Path as _Path
    p = _Path(args.results_file)
    if not p.exists():
        print(f"[!] Arquivo não encontrado: {p}", file=sys.stderr)
        sys.exit(1)

    try:
        raw_data = json.loads(p.read_text(encoding="utf-8"))
        results  = raw_data if isinstance(raw_data, list) else raw_data.get("results", [])
    except Exception as e:
        print(f"[!] Erro de leitura: {e}", file=sys.stderr)
        sys.exit(1)

    if not results:
        print(f"[!] Nenhum resultado encontrado em '{p}'.", file=sys.stderr)
        sys.exit(1)

    llm = None
    if args.llm and _llm_available:
        llm = init_llm_plugin(args)
        if not llm:
            print("[!] LLM não inicializado — continuando em modo autônomo.", file=sys.stderr)
    elif args.llm and not _llm_available:
        print("[!] mappingexpo_llm_plugin.py não encontrado — modo autônomo.", file=sys.stderr)

    print(f"\n[*] Analisando {len(results)} resultados de '{p.name}'")
    print(f"[*] Mode: {'LLM + regex' if llm else 'autonomous (regex)'}")
    sec_mode = getattr(args, "security_mode", "passive")
    no_sec   = getattr(args, "no_security", False)
    print(f"[*] Security: {'DISABLED' if no_sec else sec_mode.upper()}")

    out = run_analysis_pipeline(
        results    = results,
        llm_plugin = llm,
        args       = args,
        target     = args.target,
    )

    print()
    if out.get("report_path"):
        print(f"[✓] Relatório: {out['report_path']}")
    print(f"[✓] Segredos encontrados: {out['secrets_total']}")
    print(f"[✓] PII encontrados:     {out.get('pii_total', 0)}")
    print(f"[✓] E-mails coletados:   {out.get('emails_total', 0)}")
    n_subs = sum(len(v) for v in out.get('subdomains', {}).values())
    print(f"[✓] Subdomínios:         {n_subs}")
    print(f"[✓] Dorks de CVE:       {len(out.get('cve_dorks', []))}")

    sec_stats = out.get("security_stats", {})
    if sec_stats:
        print(f"[✓] Segurança escaneada: {sec_stats.get('total_scanned', 0)}")
        print(f"[✓] Ameaças de segurança: {len(out.get('security_threats', []))}")
        print(f"[✓] Bloqueados (seg.):   {sec_stats.get('blocked', 0)}")

    db_stats = out.get("dbscan_stats", {})
    if db_stats:
        print(f"[✓] Hosts DBScan:        {db_stats.get('hosts_scanned', 0)}")
        print(f"[✓] Portas abertas DBScan: {db_stats.get('open_ports', 0)}")
        print(f"[✓] DBScan CRITICAL:   {db_stats.get('critical', 0)}  (no-auth)")
        print(f"[✓] DBScan HIGH:       {db_stats.get('high', 0)}")

    if out.get("triaged"):
        from collections import Counter
        dist = Counter(r.get("triage_label", "?") for r in out["triaged"])
        print(f"[✓] Triage: CRITICAL={dist.get('CRITICAL',0)} HIGH={dist.get('HIGH',0)} "
              f"MEDIUM={dist.get('MEDIUM',0)} LOW={dist.get('LOW',0)}")
