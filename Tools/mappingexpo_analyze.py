#!/usr/bin/env python3
"""
MappingExpo Analyzer 
======================
Análise pós-busca totalmente autônoma para o MappingExpo Project

Funciona apenas com Python + requests + rich (já no requirements.txt).
Lê resultados salvos pelo MappingExpo (-o results.json) e produz:

  1. Triage    — classifica cada resultado com pontuação 0-100 (regex puro)
  2. Fetch     — baixa o conteúdo real das páginas prioritárias
  3. Secrets   — scan de credenciais e dados sensíveis (40+ padrões regex)
  4. Report    — HTML com tema escuro / Markdown / JSON / texto

Ex.:
    python mappingexpo_analyze.py Dump/results.json
    python mappingexpo_analyze.py Dump/results.json --fetch --fmt=html --out=report.html
    python mappingexpo_analyze.py Dump/results.json --fetch --fetch-max=30 --fmt=md

Integrado ao mappingexpo.py via --analyze-local:
    python mappingexpo.py --dg=all -o results.html --analyze-local
    python mappingexpo.py -d dorks.txt --analyze-local --analyze-local-fetch --analyze-local-fmt=html

Autor: @xPloits3c
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from collections import defaultdict
from datetime import datetime
from html.parser import HTMLParser as _HTMLParser
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import urllib3
import requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Rich (opcional, mas já no requirements.txt) ─────────────────────────
try:
    from rich.console  import Console
    from rich.panel    import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table    import Table
    from rich.rule     import Rule
    _con = Console()

    def _log(msg: str, style: str = "cyan")         -> None: _con.print(f"[{style}]{msg}[/{style}]")
    def _rule(title: str = "", style: str = "cyan") -> None: _con.print(Rule(title=title, style=style))
    def _panel(body: str, title: str = "", border: str = "cyan") -> None:
        _con.print(Panel(body, title=title, border_style=border))
    def _progress():
        return Progress(SpinnerColumn(), TextColumn("{task.description}"),
                        BarColumn(), TextColumn("{task.completed}/{task.total}"),
                        console=_con, transient=True)
    HAS_RICH = True

except ImportError:
    HAS_RICH = False
    def _log(msg: str, style: str = "")            -> None: print(msg)
    def _rule(title: str = "", style: str = "")    -> None: print(f"\n{'─'*60}  {title}")
    def _panel(body: str, title: str = "", border: str = "") -> None:
        print(f"\n[{title}]\n{body}")
    def _progress(): return None  # type: ignore


# ══════════════════════════════════════════════════════════════════════════════
#  BIBLIOTECA DE PADRÕES — importada de mappingexpo_patterns.py
# ══════════════════════════════════════════════════════════════════════════════
from mappingexpo_patterns import (
    TRIAGE_RULES,
    SECRET_RULES,
    SecretRule,
    SCORE_TO_LABEL     as _SCORE_TO_LABEL,
    FETCH_UA           as _FETCH_UA,
    SKIP_EXTENSIONS    as _SKIP_EXT,
    label_from_score   as _label,
    censor             as _censor_base,
)


# ══════════════════════════════════════════════════════════════════════════════
#  AUXILIARES
# ══════════════════════════════════════════════════════════════════════════════

def _censor(value: str, show: int = 4) -> str:
    return _censor_base(value, show=show)


class _ScriptStyleStripper(_HTMLParser):
    """HTMLParser que remove blocos <script> e <style> de forma segura.

    Substitui a regex bypassável (CWE-20/116) pelo parser embutido,
    que lida corretamente com todas as variantes sintáticas válidas da
    tag de fechamento (es. </script  >, </SCRIPT\n>, etc.).
    """

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self._skip_tags: set = {"script", "style"}
        self._in_skip: int = 0
        self._parts: list = []

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
#   - Abertura : `(?:[^>]*)` inalterada (lida com atributos sem `>` não quotado)
#   - Fechamento: `s*>` substituído por `[^>]*>` para cobrir variantes aceitas
#               por navegadores como `</script anything>` ou `</  script  foo>`
#               (espaços após `</` tratados por `\s*` adicionado antes do nome da tag).
# Este caminho é intencionalmente um último recurso: o caminho principal usa
# _ScriptStyleStripper (HTMLParser embutido), que é imune a essas variantes.
_SCRIPT_STYLE_RE_FALLBACK = re.compile(  # noqa: S608
    r"<(?:script|style)(?:[^>]*)>[\s\S]*?</\s*(?:script|style)[^>]*>",
    re.IGNORECASE,
)


def _strip_html(text: str) -> str:
    """Remove tags HTML e comprime os espaços.

    Usa HTMLParser para remover <script>/<style> (seguro contra
    variantes bypassáveis de tag de fechamento) e regex apenas para as
    tags genéricas restantes, comentários e entidades HTML.
    """
    stripper = _ScriptStyleStripper()
    try:
        stripper.feed(text)
        stripper.close()
        text = stripper.get_result()
    except Exception:
        text = _SCRIPT_STYLE_RE_FALLBACK.sub(" ", text)

    text = re.sub(r"<!--.*?-->", " ", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>",   " ", text)
    text = re.sub(r"&[a-z]+;",  " ", text)
    text = re.sub(r"\s{3,}",   "\n", text)
    return text.strip()


def _dedup_secrets(secrets: List[dict]) -> List[dict]:
    """Deduplicação por (tipo, valor)."""
    seen, out = set(), []
    for s in secrets:
        key = (s.get("type",""), s.get("value",""))
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  TRIAGE
# ══════════════════════════════════════════════════════════════════════════════

def triage_results(results: List[dict]) -> List[dict]:
    """
    Classifica cada resultado com pontuação 0-100 usando apenas regex.
    Adiciona: triage_score, triage_label, triage_reasons.
    Ordena por pontuação decrescente.
    """
    _log("[Triage] Classificando resultados...", style="bold cyan")

    for r in results:
        text   = " ".join(filter(None, [r.get("url",""), r.get("title",""), r.get("snippet","")]))
        bonus  = 0
        reasons: List[str] = []

        for pattern, pts, hint in TRIAGE_RULES:
            if pattern.search(text):
                bonus += pts
                reasons.append(hint)

        score = min(bonus, 100)
        r["triage_score"]   = score
        r["triage_label"]   = _label(score)
        r["triage_reasons"] = list(dict.fromkeys(reasons))  # dedup preservando a ordem

    results.sort(key=lambda x: x.get("triage_score", 0), reverse=True)

    counts = defaultdict(int)
    for r in results:
        counts[r["triage_label"]] += 1

    _panel(
        "\n".join(
            f"  [{counts[l]:>3}]  {l}"
            for l in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SKIP")
        ) + f"\n\n  TOTAL: {len(results)}",
        title="[bold cyan][ Triage ][/bold cyan]" if HAS_RICH else "Triage",
        border="cyan",
    )
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  FETCH DE PÁGINAS
# ══════════════════════════════════════════════════════════════════════════════

def fetch_pages(
    results:   List[dict],
    max_pages: int   = 20,
    min_label: str   = "HIGH",
    timeout:   int   = 10,
    max_chars: int   = 10000,
    delay_s:   float = 1.2,
) -> List[dict]:
    """
    Baixa o conteúdo HTML real das páginas prioritárias.
    Adiciona 'page_content' (str) aos resultados processados.
    """
    _label_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "SKIP": 0}
    min_rank    = _label_rank.get(min_label.upper(), 3)

    targets = [
        r for r in results
        if _label_rank.get(r.get("triage_label", "LOW"), 1) >= min_rank
        and "page_content" not in r
    ][:max_pages]

    if not targets:
        _log("[Fetch] Nenhuma página para baixar.", style="dim")
        return results

    _log(
        f"[Fetch] Baixando {len(targets)} páginas "
        f"(min={min_label}, timeout={timeout}s, delay={delay_s}s)...",
        style="bold cyan"
    )

    fetched = 0
    for idx, r in enumerate(targets):
        url = r.get("url", "")
        if not url:
            continue

        # Pula extensões binárias
        ext = Path(urlparse(url).path).suffix.lower()
        if ext in _SKIP_EXT:
            r["page_content"] = ""
            continue

        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers={
                    "User-Agent":      _FETCH_UA,
                    "Accept":          "text/html,application/xhtml+xml,text/plain,*/*",
                    "Accept-Language": "en-US,en;q=0.9,it;q=0.8",
                },
                allow_redirects=True,
                stream=True,
                verify=False,
            )
            if resp.status_code >= 400:
                r["page_content"] = ""
                r["fetch_status"] = resp.status_code
                _log(f"[Fetch] {resp.status_code} — {url[:70]}", style="dim")
                continue

            # Lê no máximo max_chars*3 bytes
            raw = b""
            for chunk in resp.iter_content(chunk_size=4096):
                raw += chunk
                if len(raw) > max_chars * 3:
                    break

            ct = resp.headers.get("Content-Type", "")
            if "text" not in ct and "json" not in ct and "xml" not in ct:
                r["page_content"] = ""
                continue

            text = raw.decode("utf-8", errors="replace")
            text = _strip_html(text)[:max_chars]

            r["page_content"] = text
            r["fetch_status"] = resp.status_code
            fetched += 1
            _log(
                f"[Fetch] [{r.get('triage_label','?')}] +{len(text)}c — {url[:70]}",
                style="dim"
            )

        except Exception as e:
            r["page_content"] = ""
            r["fetch_error"]  = str(e)[:80]
            _log(f"[Fetch] Erro — {url[:60]}: {e}", style="yellow")

        if idx < len(targets) - 1:
            time.sleep(delay_s)

    _log(
        f"[Fetch] Concluído: {fetched}/{len(targets)} páginas baixadas.",
        style="green"
    )
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  SCAN DE SEGREDOS
# ══════════════════════════════════════════════════════════════════════════════

def scan_secrets(results: List[dict]) -> Tuple[List[dict], List[dict]]:
    """
    Scan de regex em page_content (se disponível) ou snippet.
    Adiciona 'secrets' (lista) a cada resultado com achados.

    Retorna:
        (updated_results, global_secrets_list)
    """
    _log("[Secrets] Iniciando scan de regex...", style="bold cyan")

    total_found   = 0
    all_secrets_g = []

    candidates = [
        r for r in results
        if (r.get("page_content") or r.get("snippet"))
        and r.get("triage_label", "SKIP") != "SKIP"
    ]

    if not candidates:
        _log("[Secrets] Nenhum conteúdo disponível.", style="dim")
        return results, []

    for r in candidates:
        content = r.get("page_content") or r.get("snippet") or ""
        url     = r.get("url", "")
        findings: List[dict] = []

        for category, pattern, description, has_group in SECRET_RULES:
            for match in pattern.finditer(content):
                if has_group and match.lastindex:
                    raw_val = match.group(1).strip()
                else:
                    raw_val = match.group(0).strip()

                if not raw_val or len(raw_val) < 4:
                    continue

                # Contexto: 70 caracteres ao redor do match
                s_ctx   = max(0, match.start() - 70)
                e_ctx   = min(len(content), match.end() + 70)
                context = content[s_ctx:e_ctx].replace("\n", " ").strip()

                findings.append({
                    "type":       category,
                    "desc":       description,
                    "value":      _censor(raw_val),
                    "confidence": "HIGH",
                    "context":    context[:160],
                    "source":     url,
                })

        # Dedup por (tipo, valor)
        findings = _dedup_secrets(findings)

        if findings:
            r["secrets"] = findings
            total_found += len(findings)
            all_secrets_g.extend(findings)
            _log(
                f"[Secrets] {len(findings):>2} encontrados "
                f"[{r.get('triage_label','?')}] {url[:70]}",
                style="bold red"
            )

    _log(
        f"[Secrets] Scan concluído: {total_found} segredos em {len(candidates)} resultados.",
        style="bold green" if total_found == 0 else "bold red"
    )

    if total_found > 0 and HAS_RICH:
        # Tabela-resumo por tipo
        by_type = defaultdict(int)
        for s in all_secrets_g:
            by_type[s["type"]] += 1
        table = Table(title="Segredos por tipo", style="red")
        table.add_column("Tipo",  style="bold red")
        table.add_column("Total", style="bold white")
        for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
            table.add_row(t, str(c))
        _con.print(table)

    return results, all_secrets_g


# ══════════════════════════════════════════════════════════════════════════════
#  RELATÓRIO
# ══════════════════════════════════════════════════════════════════════════════

def build_report(
    results:    List[dict],
    all_secrets: List[dict],
    target:     str  = "",
    fmt:        str  = "html",
) -> str:
    """
    Gera o relatório no formato escolhido.
    fmt: "html" | "md" | "json" | "txt"
    """
    now    = datetime.now().strftime("%Y-%m-%d %H:%M")
    counts = defaultdict(int)
    for r in results:
        counts[r.get("triage_label", "LOW")] += 1

    top = [r for r in results if r.get("triage_label") in ("CRITICAL", "HIGH")]

    if fmt == "json":
        return _report_json(results, all_secrets, counts, target, now)
    elif fmt == "md":
        return _report_md(results, all_secrets, counts, top, target, now)
    elif fmt == "txt":
        return _report_txt(results, all_secrets, counts, top, target, now)
    else:
        return _report_html(results, all_secrets, counts, top, target, now)


def _report_html(results, all_secrets, counts, top, target, now) -> str:
    _sc = {"CRITICAL":"#ff4444","HIGH":"#ff8800","MEDIUM":"#ffcc00","LOW":"#44cc44","SKIP":"#888"}

    def badge(lbl: str) -> str:
        c = _sc.get(lbl, "#888")
        return (f'<span style="background:{c};color:#000;padding:1px 8px;'
                f'border-radius:3px;font-size:11px;font-weight:bold">{lbl}</span>')

    rows_top = "".join(
        f"<tr>"
        f"<td>{r.get('triage_score',0)}</td>"
        f"<td>{badge(r.get('triage_label','?'))}</td>"
        f"<td><a href='{r.get('url','')}' target='_blank'>{r.get('url','')[:85]}</a></td>"
        f"<td>{', '.join(r.get('triage_reasons',[]))[:70]}</td>"
        f"</tr>"
        for r in top[:30]
    )
    rows_all = "".join(
        f"<tr>"
        f"<td>{r.get('triage_score',0)}</td>"
        f"<td>{badge(r.get('triage_label','?'))}</td>"
        f"<td><a href='{r.get('url','')}' target='_blank'>{r.get('url','')[:85]}</a></td>"
        f"<td>{r.get('title','')[:55]}</td>"
        f"<td>{'✓' if r.get('secrets') else ''}</td>"
        f"</tr>"
        for r in results
    )
    rows_sec = "".join(
        f"<tr>"
        f"<td><code>{s.get('type','?')}</code></td>"
        f"<td>{s.get('desc','')[:40]}</td>"
        f"<td><code>{s.get('value','?')}</code></td>"
        f"<td>{s.get('confidence','?')}</td>"
        f"<td><a href='{s.get('source','')}' target='_blank'>{s.get('source','')[:60]}</a></td>"
        f"</tr>"
        for s in all_secrets
    )

    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8">
<title>MappingExpo Analyzer — {target or 'Relatório'}</title>
<style>
:root{{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--text:#c9d1d9;--acc:#58a6ff;--brd:#30363d}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',Consolas,sans-serif;font-size:14px;line-height:1.6;padding:28px}}
h1{{color:var(--acc);font-size:24px;margin-bottom:4px}}
h2{{color:var(--acc);font-size:16px;margin:26px 0 10px;border-bottom:1px solid var(--brd);padding-bottom:5px}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:18px}}
.card{{background:var(--bg2);border:1px solid var(--brd);border-radius:8px;padding:14px;margin-bottom:12px}}
.metrics{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}}
.metric{{background:var(--bg3);border-radius:6px;padding:10px 18px;text-align:center;min-width:80px}}
.metric .num{{font-size:26px;font-weight:bold}}
.metric .lbl{{font-size:11px;color:#8b949e}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:var(--bg3);padding:7px 10px;text-align:left;border-bottom:2px solid var(--brd);color:var(--acc)}}
td{{padding:5px 10px;border-bottom:1px solid var(--brd);vertical-align:top;word-break:break-word}}
tr:hover{{background:var(--bg3)}}
a{{color:var(--acc);text-decoration:none}}a:hover{{text-decoration:underline}}
code{{background:var(--bg3);padding:1px 5px;border-radius:3px;font-size:12px;font-family:Consolas,monospace}}
footer{{margin-top:32px;font-size:11px;color:#8b949e;text-align:center}}
.warn{{color:#ff8800;font-weight:bold}}
</style></head><body>
<h1>&#128065; MappingExpo Analyzer — Relatório</h1>
<div class="meta">
  Gerado: {now} &nbsp;|&nbsp;
  Alvo: <code>{target or 'N/A'}</code> &nbsp;|&nbsp;
  MappingExpo Analyzer v1.0 (no-AI)
</div>
<h2>Métricas</h2>
<div class="metrics">
  <div class="metric"><div class="num" style="color:#ff4444">{counts['CRITICAL']}</div><div class="lbl">CRITICAL</div></div>
  <div class="metric"><div class="num" style="color:#ff8800">{counts['HIGH']}</div><div class="lbl">HIGH</div></div>
  <div class="metric"><div class="num" style="color:#ffcc00">{counts['MEDIUM']}</div><div class="lbl">MEDIUM</div></div>
  <div class="metric"><div class="num" style="color:#44cc44">{counts['LOW']}</div><div class="lbl">LOW</div></div>
  <div class="metric"><div class="num">{len(results)}</div><div class="lbl">TOTAL</div></div>
  <div class="metric"><div class="num" style="color:#ff4444">{len(all_secrets)}</div><div class="lbl">SEGREDOS</div></div>
</div>
{'<h2 class="warn">&#9888; Principais Achados — CRITICAL &amp; HIGH</h2><div class="card"><table><tr><th>Pontuação</th><th>Label</th><th>URL</th><th>Motivos</th></tr>' + rows_top + '</table></div>' if top else ''}
{'<h2 class="warn">&#128274; Segredos Encontrados (' + str(len(all_secrets)) + ')</h2><div class="card"><table><tr><th>Tipo</th><th>Descrição</th><th>Valor</th><th>Confiança</th><th>Origem</th></tr>' + rows_sec + '</table></div>' if all_secrets else ''}
<h2>Todos os Resultados ({len(results)})</h2>
<div class="card"><table>
<tr><th>Pontuação</th><th>Label</th><th>URL</th><th>Título</th><th>&#128274;</th></tr>
{rows_all}
</table></div>
<footer>MappingExpo Analyzer v1.0 (no-AI, pure regex) &mdash; {now}</footer>
</body></html>"""


def _report_md(results, all_secrets, counts, top, target, now) -> str:
    lines = [
        "# MappingExpo Analyzer — Relatório",
        f"\n> {now}  |  Alvo: `{target or 'N/A'}`  |  MappingExpo Analyzer v1.0 (no-AI)\n",
        "---\n",
        "## Métricas\n",
        "| Label | Contagem |", "|-------|-------|",
        f"| 🔴 CRITICAL | {counts['CRITICAL']} |",
        f"| 🟠 HIGH     | {counts['HIGH']} |",
        f"| 🟡 MEDIUM   | {counts['MEDIUM']} |",
        f"| 🟢 LOW      | {counts['LOW']} |",
        f"| **TOTAL**   | **{len(results)}** |",
        f"| **SECRETS** | **{len(all_secrets)}** |",
    ]
    if top:
        lines += ["\n---\n", "## Principais Achados — CRITICAL & HIGH\n",
                  "| Pontuação | Label | URL | Motivos |", "|-------|-------|-----|---------|"]
        for r in top[:30]:
            lines.append(
                f"| {r.get('triage_score',0)} | **{r.get('triage_label','')}** "
                f"| `{r.get('url','')[:80]}` | {', '.join(r.get('triage_reasons',[]))[:60]} |"
            )
    if all_secrets:
        lines += ["\n---\n", f"## Segredos Encontrados ({len(all_secrets)})\n",
                  "| Tipo | Descrição | Valor | Origem |",
                  "|------|-------------|-------|--------|"]
        for s in all_secrets:
            lines.append(
                f"| **{s.get('type','?')}** | {s.get('desc','')[:35]} "
                f"| `{s.get('value','?')}` | {s.get('source','?')[:60]} |"
            )
    lines += [
        "\n---\n", f"## Todos os Resultados ({len(results)})\n",
        "| Pontuação | Label | URL | Segredos |", "|-------|-------|-----|---------|",
    ]
    for r in results:
        lines.append(
            f"| {r.get('triage_score',0)} | {r.get('triage_label','?')} "
            f"| `{r.get('url','')[:75]}` | {'🔴' if r.get('secrets') else ''} |"
        )
    lines.append(f"\n\n---\n*MappingExpo Analyzer v1.0 (no-AI) — {now}*")
    return "\n".join(lines)


def _report_txt(results, all_secrets, counts, top, target, now) -> str:
    lines = [
        "=" * 70,
        "  RELATÓRIO MAPPINGEXPO ANALYZER",
        f"  {now}  |  Alvo: {target or 'N/A'}",
        "=" * 70,
        f"\nMÉTRICAS:",
        f"  CRITICAL : {counts['CRITICAL']}",
        f"  HIGH     : {counts['HIGH']}",
        f"  MEDIUM   : {counts['MEDIUM']}",
        f"  LOW      : {counts['LOW']}",
        f"  TOTAL    : {len(results)}",
        f"  SEGREDOS : {len(all_secrets)}",
    ]
    if top:
        lines += ["\n" + "─" * 70, "PRINCIPAIS ACHADOS (CRITICAL & HIGH):", "─" * 70]
        for r in top[:30]:
            lines.append(
                f"  [{r.get('triage_score',0):>3}] [{r.get('triage_label','?'):<8}] "
                f"{r.get('url','')[:75]}"
            )
            if r.get("triage_reasons"):
                lines.append(f"       Motivos: {', '.join(r['triage_reasons'])}")
    if all_secrets:
        lines += ["\n" + "─" * 70, f"SEGREDOS ENCONTRADOS ({len(all_secrets)}):", "─" * 70]
        for s in all_secrets:
            lines.append(f"  [{s.get('type','?'):<12}] {s.get('value','?'):<30}  {s.get('source','?')[:60]}")
            lines.append(f"    Descrição: {s.get('desc','')}  |  Contexto: {s.get('context','')[:80]}")
    lines += ["\n" + "─" * 70, f"TODOS OS RESULTADOS ({len(results)}):", "─" * 70]
    for r in results:
        sec_flag = " [SEGREDO]" if r.get("secrets") else ""
        lines.append(
            f"  [{r.get('triage_score',0):>3}] [{r.get('triage_label','?'):<8}]{sec_flag} "
            f"{r.get('url','')[:75]}"
        )
    lines.append(f"\nMappingExpo Analyzer v1.0 (no-AI) — {now}")
    return "\n".join(lines)


def _report_json(results, all_secrets, counts, target, now) -> str:
    return json.dumps({
        "meta": {
            "generated_at": now,
            "target": target,
            "engine": "MappingExpo Analyzer v1.0 (no-AI, pure regex)",
        },
        "metrics":  {"total": len(results), "by_label": dict(counts), "secrets": len(all_secrets)},
        "secrets":  all_secrets,
        "results":  results,
    }, indent=2, ensure_ascii=False)


# ══════════════════════════════════════════════════════════════════════════════
#  PIPELINE PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def run_pipeline(
    results:    List[dict],
    do_fetch:   bool = False,
    fetch_max:  int  = 20,
    fetch_min_label: str = "HIGH",
    fmt:        str  = "html",
    out:        Optional[str] = None,
    target:     str  = "",
) -> dict:
    """
    Executa o pipeline completo: triage → [fetch] → segredos → relatório.

    Args:
        results:         lista de dicts de resultados do MappingExpo
        do_fetch:        True = baixar páginas reais
        fetch_max:       máximo de páginas para baixar
        fetch_min_label: label mínimo para download (HIGH / MEDIUM)
        fmt:             formato do relatório ("html" | "md" | "json" | "txt")
        out:             path de saída (None = não salvar)
        target:          descrição do alvo para o relatório

    Retorna:
        dict com: triaged, all_secrets, report_path, counts
    """
    _rule(" MappingExpo Analyzer v1.0 — sem IA necessária ", style="bold cyan")

    # 1. Triage
    results = triage_results(results)

    # 2. Fetch (opcional)
    if do_fetch:
        results = fetch_pages(
            results,
            max_pages  = fetch_max,
            min_label  = fetch_min_label,
        )

    # 3. Scan de segredos
    results, all_secrets = scan_secrets(results)

    # 4. Relatório
    _log(f"[Relatório] Gerando relatório (fmt={fmt})...", style="bold cyan")
    content = build_report(results, all_secrets, target=target, fmt=fmt)

    report_path = None
    if out:
        # Ajusta a extensão
        ext_map = {"html": ".html", "md": ".md", "json": ".json", "txt": ".txt"}
        p = Path(out)
        if p.suffix.lower() not in ext_map.values():
            p = p.with_suffix(ext_map.get(fmt, ".html"))
        try:
            p.write_text(content, encoding="utf-8")
            report_path = str(p)
            _log(f"[Relatório] Salvo: {report_path}", style="bold green")
        except IOError as e:
            _log(f"[Relatório] Erro ao salvar: {e}", style="red")

    counts = defaultdict(int)
    for r in results:
        counts[r.get("triage_label", "LOW")] += 1

    # Resumo final
    _rule(" Análise Concluída ", style="bold green")
    _log(
        f"CRITICAL:{counts['CRITICAL']}  HIGH:{counts['HIGH']}  "
        f"MEDIUM:{counts['MEDIUM']}  LOW:{counts['LOW']}  "
        f"TOTAL:{len(results)}  SECRETS:{len(all_secrets)}",
        style="bold white"
    )
    if report_path:
        _log(f"Relatório: {report_path}", style="bold green")

    return {
        "triaged":     results,
        "all_secrets": all_secrets,
        "report_path": report_path,
        "counts":      dict(counts),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  INTEGRAÇÃO CLI mappingexpo.py
#  Estas funções são importadas pelo mappingexpo.py
# ══════════════════════════════════════════════════════════════════════════════

def add_local_analyze_args(parser) -> object:
    """
    Adiciona as flags --analyze-local-* ao parser do CLI mappingexpo.py.
    Não requer --llm.
    """
    g = parser.add_argument_group(
        "Análise Local (sem IA — regex puro, não requer --llm)"
    )
    g.add_argument(
        "--analyze-local",
        action="store_true",
        help="Análise pós-busca: triage + scan de segredos (regex, sem IA)",
    )
    g.add_argument(
        "--analyze-local-fetch",
        action="store_true",
        help="Baixa o conteúdo real das páginas HIGH/CRITICAL",
    )
    g.add_argument(
        "--analyze-local-fetch-max",
        type=int, default=20,
        help="Máximo de páginas para baixar (padrão: 20)",
    )
    g.add_argument(
        "--analyze-local-fmt",
        choices=["html", "md", "json", "txt"],
        default="html",
        help="Formato do relatório: html | md | json | txt (padrão: html)",
    )
    g.add_argument(
        "--analyze-local-out",
        type=str, default=None,
        help="Path de saída do relatório (padrão: mappingexpo_local_analysis_<ts>.<fmt>)",
    )
    return parser


def run_local_analysis(results: List[dict], args, target: str = "") -> dict:
    """
    Entry point para o mappingexpo.py — chamado quando --analyze-local está ativo.
    Não requer llm_plugin.
    """
    fmt = getattr(args, "analyze_local_fmt", "html")
    out = getattr(args, "analyze_local_out", None)
    if not out:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = f"mappingexpo_local_analysis_{ts}.{fmt}"

    return run_pipeline(
        results   = results,
        do_fetch  = getattr(args, "analyze_local_fetch",     False),
        fetch_max = getattr(args, "analyze_local_fetch_max", 20),
        fmt       = fmt,
        out       = out,
        target    = target,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  PONTO DE ENTRADA CLI STANDALONE
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="MappingExpo Analyzer v1.0 — Análise pós-busca sem IA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Exemplos:

  # Análise básica (triage + regex de segredos)
    python mappingexpo_analyze.py Dump/results.json

  # Com download de páginas + relatório HTML
    python mappingexpo_analyze.py Dump/results.json --fetch --fmt=html --out=report.html

  # Relatório Markdown com contexto do alvo
    python mappingexpo_analyze.py results.json --target "gov.it admin panels" --fmt=md

  # Baixa até 40 páginas (mais preciso para segredos)
    python mappingexpo_analyze.py results.json --fetch --fetch-max=40 --fmt=html

  # Saída JSON legível por máquina
    python mappingexpo_analyze.py results.json --fmt=json --out=analise.json
""",
    )

    parser.add_argument("results_file",    help="Arquivo JSON de resultados do MappingExpo")
    parser.add_argument("--target",        default="", help="Descrição do alvo (opcional)")
    parser.add_argument("--fetch",         action="store_true", help="Baixa páginas HIGH/CRITICAL")
    parser.add_argument("--fetch-max",     type=int,  default=20,   help="Máximo de páginas para baixar (padrão: 20)")
    parser.add_argument("--fetch-label",   default="HIGH",          help="Label mínimo para fetch (padrão: HIGH)")
    parser.add_argument("--fmt",           choices=["html","md","json","txt"], default="html", help="Formato do relatório")
    parser.add_argument("--out",           default=None, help="Path de saída do relatório")
    parser.add_argument("--no-report",     action="store_true", help="Não gera arquivo de relatório, exibe apenas no console")

    args = parser.parse_args()

    # Carrega os resultados
    p = Path(args.results_file)
    if not p.exists():
        print(f"[!] Arquivo não encontrado: {p}", file=sys.stderr)
        sys.exit(1)

    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[!] Erro ao ler o arquivo: {e}", file=sys.stderr)
        sys.exit(1)

    if isinstance(raw, list):
        results = raw
    elif isinstance(raw, dict):
        results = raw.get("results", [])
    else:
        results = []

    if not results:
        print(f"[!] Nenhum resultado encontrado em '{p}'.", file=sys.stderr)
        print("    Salve resultados do MappingExpo com: -o results.json", file=sys.stderr)
        sys.exit(1)

    _log(f"[*] Carregados {len(results)} resultados de '{p.name}'", style="bold cyan")
    if args.target:
        _log(f"[*] Alvo: {args.target}", style="cyan")

    # Determina o path de saída
    out = None
    if not args.no_report:
        out = args.out
        if not out:
            ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
            out = f"mappingexpo_analysis_{ts}.{args.fmt}"

    run_pipeline(
        results   = results,
        do_fetch  = args.fetch,
        fetch_max = args.fetch_max,
        fetch_min_label = args.fetch_label,
        fmt       = args.fmt,
        out       = out,
        target    = args.target,
    )


if __name__ == "__main__":
    main()
