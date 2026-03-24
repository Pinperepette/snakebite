#!/usr/bin/env python3
"""
snakebite - PyPI Supply Chain Attack Detector
===============================================
Scans PyPI packages for malicious patterns using heuristic analysis
and LLM-powered false positive filtering.

Usage:
    snakebite feed                                  # Monitor PyPI RSS feed
    snakebite feed --loop 60                        # Monitor continuously every 60s
    snakebite local                                 # Scan all locally installed packages
    snakebite local flask requests numpy            # Scan specific packages
    snakebite local --no-llm                        # Heuristics only, no LLM
    snakebite local -m claude                       # Anthropic API (ANTHROPIC_API_KEY)
    snakebite local -m claude-code                  # Claude Code CLI (subscription)
    snakebite local -m chatgpt                      # OpenAI API (OPENAI_API_KEY)
    snakebite local -m ollama:qwen2.5:32b           # Ollama local
"""

import argparse
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib import request


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
NAME = "snakebite"
PYPI_RSS_NEWEST = "https://pypi.org/rss/packages.xml"
PYPI_RSS_UPDATES = "https://pypi.org/rss/updates.xml"
PYPI_JSON_API = "https://pypi.org/pypi/{}/json"
OLLAMA_API = "http://localhost:11434/api/generate"
OPENAI_API = "https://api.openai.com/v1/chat/completions"
MAX_FILE_SIZE = 512 * 1024

INTERESTING_FILES = {
    "setup.py", "setup.cfg", "pyproject.toml",
    "__init__.py", "__main__.py", "conftest.py",
}
INTERESTING_EXTENSIONS = {".py", ".pth", ".sh", ".bat", ".cmd", ".ps1"}

BANNER = r"""
   ___          _       _    _ _
  / __|_ _  ___| |_____| |__(_) |_ ___
  \__ \ ' \/ _ \ / / -_) '_ \ |  _/ -_)
  |___/_||_\__,_|_\_\___|_.__/_|\__\___|
  v{version} - PyPI Supply Chain Attack Detector
"""

# ANSI
RED = "\033[0;31m"
YEL = "\033[1;33m"
GRN = "\033[0;32m"
CYN = "\033[0;36m"
DIM = "\033[2m"
NC = "\033[0m"
BOLD = "\033[1m"


# ---------------------------------------------------------------------------
# Heuristic engine
# ---------------------------------------------------------------------------

@dataclass
class Hit:
    rule: str
    severity: str
    file: str
    line_no: int
    line: str
    context: str = ""


RULES = [
    {
        "id": "PTH_EXEC",
        "severity": "CRITICAL",
        "desc": ".pth file with executable code",
        "file_match": lambda f: f.endswith(".pth"),
        "pattern": re.compile(
            r"^(?!#).*\b(import|exec|eval|subprocess|os\.system|__import__)\b",
            re.IGNORECASE,
        ),
    },
    {
        "id": "BASE64_NESTED",
        "severity": "CRITICAL",
        "desc": "Nested base64 decoding (obfuscation)",
        "pattern": re.compile(
            r"base64\s*\.\s*b64decode\s*\(.*base64|"
            r"b64decode\s*\(.*b64decode|"
            r"exec\s*\(\s*base64\s*\.\s*b64decode",
            re.IGNORECASE,
        ),
    },
    {
        "id": "EXEC_ENCODED",
        "severity": "CRITICAL",
        "desc": "exec/eval with encoded payload",
        "pattern": re.compile(
            r"exec\s*\(\s*(base64|codecs|zlib|gzip|bz2|lzma)\s*\.|"
            r"eval\s*\(\s*(base64|codecs|zlib|gzip|bz2|lzma)\s*\.",
            re.IGNORECASE,
        ),
    },
    {
        "id": "SETUP_NETWORK",
        "severity": "CRITICAL",
        "desc": "Network call in setup/init/.pth",
        "file_match": lambda f: any(
            n in f for n in ("setup.py", "__init__.py", ".pth")
        ),
        "pattern": re.compile(
            r"\b(urllib\.request|requests\.(get|post|put)|"
            r"http\.client|httpx\.(get|post)|"
            r"socket\.connect|socket\.create_connection|"
            r"urlopen|curl|wget)\b",
            re.IGNORECASE,
        ),
    },
    {
        "id": "SETUP_SUBPROCESS",
        "severity": "HIGH",
        "desc": "subprocess/os.system in setup/init/.pth",
        "file_match": lambda f: any(
            n in f for n in ("setup.py", "__init__.py", ".pth")
        ),
        "pattern": re.compile(
            r"\b(subprocess\.(run|call|Popen|check_output|check_call)|"
            r"os\.(system|popen|exec[lv]?p?e?)|"
            r"commands\.getoutput)\b"
        ),
    },
    {
        "id": "CRED_HARVEST",
        "severity": "CRITICAL",
        "desc": "Accessing SSH keys / cloud credentials",
        "pattern": re.compile(
            r"(\.ssh/(id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts)|"
            r"\.aws/(credentials|config)|"
            r"\.azure/|"
            r"gcloud/application_default_credentials|"
            r"\.kube/config|"
            r"\.docker/config\.json|"
            r"\.npmrc|\.pypirc)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "ENV_DUMP",
        "severity": "HIGH",
        "desc": "Dumping all env vars in install/init context",
        "file_match": lambda f: any(
            n in f.lower() for n in ("setup.py", "__init__.py", ".pth")
        ),
        "pattern": re.compile(
            r"\bdict\s*\(\s*os\.environ\s*\)|"
            r"\bjson\.dumps\s*\(\s*.*os\.environ|"
            r'\bsubprocess\b.*\bprintenv\b|'
            r"\bstr\s*\(\s*os\.environ\s*\)",
        ),
    },
    {
        "id": "CRYPTO_WALLET",
        "severity": "CRITICAL",
        "desc": "Accessing cryptocurrency wallets",
        "pattern": re.compile(
            r"(\.bitcoin/wallet|\.ethereum/keystore|"
            r"\.solana/id\.json|\.gnupg/|"
            r"wallet\.dat|\.electrum/wallets)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "DNS_EXFIL",
        "severity": "HIGH",
        "desc": "Cloud metadata / DNS exfiltration",
        "pattern": re.compile(
            r"(socket\.gethostbyname|"
            r"169\.254\.169\.254|"
            r"metadata\.google\.internal|"
            r"100\.100\.100\.200)",
        ),
    },
    {
        "id": "OBFUSCATION",
        "severity": "HIGH",
        "desc": "Code obfuscation (chr concat, reversed exec, dynamic imports)",
        "file_match": lambda f: "/test" not in f.lower() and "test_" not in f.lower().split("/")[-1],
        "pattern": re.compile(
            r"(chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+\s*\)){3,}|"
            r"\[\s*::\s*-1\s*\].*exec|exec.*\[\s*::\s*-1\s*\]|"
            r"__import__\s*\(\s*['\"]base64['\"]|"
            r"exec\s*\(\s*['\"]\\x[0-9a-f]",
        ),
    },
    {
        "id": "ARCHIVE_EXFIL",
        "severity": "HIGH",
        "desc": "Archive + network send (exfiltration pattern)",
        "pattern": re.compile(
            r"(tarfile|zipfile|shutil\.(make_archive|copytree)).*"
            r"(requests\.post|urlopen|curl|httpx\.post)|"
            r"(requests\.post|urlopen|curl|httpx\.post).*"
            r"(tarfile|zipfile|shutil\.(make_archive|copytree))",
            re.DOTALL,
        ),
    },
    {
        "id": "K8S_SECRETS",
        "severity": "CRITICAL",
        "desc": "Reading Kubernetes secrets",
        "pattern": re.compile(
            r"(/var/run/secrets/kubernetes|"
            r"api/v1/namespaces/.*/secrets|"
            r"kubectl\s+get\s+secrets?)",
        ),
    },
    {
        "id": "PERSISTENCE",
        "severity": "CRITICAL",
        "desc": "Persistence mechanism (systemd/cron/launchd)",
        "pattern": re.compile(
            r"(systemd.*service|crontab|"
            r"LaunchAgents|LaunchDaemons|"
            r"/etc/init\.d/|"
            r"\.bashrc.*>>|\.profile.*>>|\.zshrc.*>>)",
        ),
    },
    {
        "id": "OPENSSL_ENCRYPT",
        "severity": "HIGH",
        "desc": "OpenSSL encryption (exfil preparation)",
        "pattern": re.compile(
            r"openssl\s+(enc|pkeyutl|rsautl|smime)\b",
        ),
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {"INFO": CYN, "WARN": YEL, "ERR": RED, "OK": GRN}
    c = colors.get(level, NC)
    print(f"{DIM}{ts}{NC} {c}{level:4s}{NC} {msg}")


def fetch_url(url: str, timeout: int = 30) -> bytes:
    req = request.Request(url, headers={"User-Agent": f"{NAME}/{VERSION}"})
    with request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def pypi_info(name: str) -> Optional[dict]:
    try:
        return json.loads(fetch_url(PYPI_JSON_API.format(name)))
    except Exception:
        return None


def _xml_tag(block: str, tag: str) -> Optional[str]:
    m = re.search(rf"<{tag}>(.*?)</{tag}>", block, re.DOTALL)
    return m.group(1).strip() if m else None


def parse_rss(xml_bytes: bytes) -> list[dict]:
    text = xml_bytes.decode("utf-8", errors="replace")
    items = []
    for match in re.finditer(r"<item>(.*?)</item>", text, re.DOTALL):
        block = match.group(1)
        title = _xml_tag(block, "title")
        link = _xml_tag(block, "link")
        if title:
            parts = title.strip().rsplit(" ", 1)
            items.append({
                "name": parts[0] if parts else title.strip(),
                "version": parts[1] if len(parts) > 1 else "",
                "link": link or "",
            })
    return items


def severity_color(s: str) -> str:
    return {"CRITICAL": RED, "HIGH": YEL, "MEDIUM": CYN, "LOW": DIM}.get(s, NC)


# ---------------------------------------------------------------------------
# Package download & extraction
# ---------------------------------------------------------------------------

def _safe_tar_extract(tf: tarfile.TarFile, dest: Path):
    for member in tf.getmembers():
        if member.name.startswith("/") or ".." in member.name:
            continue
        if member.issym() or member.islnk():
            continue
        tf.extract(member, dest)


def download_package(name: str, version: str = "") -> Optional[Path]:
    info = pypi_info(name)
    if not info:
        return None

    urls = info.get("releases", {}).get(version, []) if version else info.get("urls", [])
    if not urls:
        return None

    sdist = next((u for u in urls if u["packagetype"] == "sdist"), None)
    wheel = next((u for u in urls if u["packagetype"] == "bdist_wheel"), None)
    targets = [t for t in [sdist, wheel] if t]
    if not targets:
        return None

    tmpdir = Path(tempfile.mkdtemp(prefix=f"snakebite_{name}_"))

    for target in targets:
        url, filename = target["url"], target["filename"]
        filepath = tmpdir / filename
        try:
            filepath.write_bytes(fetch_url(url, timeout=60))
            extract_dir = tmpdir / "extracted" / filename
            extract_dir.mkdir(parents=True, exist_ok=True)

            if filename.endswith((".tar.gz", ".tgz")):
                with tarfile.open(filepath, "r:gz") as tf:
                    _safe_tar_extract(tf, extract_dir)
            elif filename.endswith(".tar.bz2"):
                with tarfile.open(filepath, "r:bz2") as tf:
                    _safe_tar_extract(tf, extract_dir)
            elif filename.endswith((".zip", ".whl")):
                with zipfile.ZipFile(filepath, "r") as zf:
                    zf.extractall(extract_dir)
        except Exception as e:
            log(f"  Download/extract failed for {filename}: {e}", "ERR")
            continue

    return tmpdir


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan_directory(pkg_dir: Path) -> list[Hit]:
    hits = []

    for fpath in pkg_dir.rglob("*"):
        if not fpath.is_file() or fpath.stat().st_size > MAX_FILE_SIZE:
            continue

        rel = str(fpath.relative_to(pkg_dir))
        suffix = fpath.suffix.lower()
        basename = fpath.name.lower()

        if suffix not in INTERESTING_EXTENSIONS and basename not in INTERESTING_FILES:
            continue

        try:
            content = fpath.read_text(errors="replace")
        except Exception:
            continue

        # Special .pth check
        if suffix == ".pth":
            for i, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if re.search(r"\b(import|exec|eval|subprocess|os\.|sys\.)\b", stripped):
                    hits.append(Hit(
                        rule="PTH_EXEC", severity="CRITICAL",
                        file=rel, line_no=i, line=stripped[:200],
                        context=content[:2000],
                    ))

        # Pattern rules
        for rule in RULES:
            file_match = rule.get("file_match")
            if file_match and not file_match(rel):
                continue

            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith(">>>"):
                    continue
                if rule["pattern"].search(line):
                    start = max(0, i - 3)
                    end = min(len(lines), i + 3)
                    ctx = "\n".join(lines[start:end])
                    hits.append(Hit(
                        rule=rule["id"], severity=rule["severity"],
                        file=rel, line_no=i, line=stripped[:200],
                        context=ctx[:2000],
                    ))

    # Deduplicate
    seen = set()
    unique = []
    for h in hits:
        key = (h.rule, h.file, h.line_no)
        if key not in seen:
            seen.add(key)
            unique.append(h)
    return unique


# ---------------------------------------------------------------------------
# LLM backends
# ---------------------------------------------------------------------------

LLM_PROMPT = """You are a security analyst specializing in supply chain attacks on Python packages.

Analyze the following suspicious code found in package "{pkg_name}" (version {version}).
The heuristic scanner flagged these issues:

{hits_summary}

Source code excerpts:
```
{code_excerpts}
```

Your task:
1. Determine if each flagged pattern is a TRUE POSITIVE (genuinely malicious/suspicious) or a FALSE POSITIVE (benign/legitimate use).
2. For true positives, explain what the code does and the potential impact.
3. Give an overall threat level: CRITICAL, HIGH, MEDIUM, LOW, or CLEAN.

Respond ONLY with valid JSON in this exact format:
{{
    "threat_level": "CRITICAL|HIGH|MEDIUM|LOW|CLEAN",
    "summary": "one-line summary",
    "findings": [
        {{
            "rule": "rule_id",
            "verdict": "TRUE_POSITIVE|FALSE_POSITIVE",
            "explanation": "why"
        }}
    ]
}}"""


def _build_prompt(pkg_name: str, version: str, hits: list[Hit]) -> str:
    hits_summary = "\n".join(
        f"- [{h.severity}] {h.rule}: {h.file}:{h.line_no} -> {h.line[:120]}"
        for h in hits
    )
    seen_ctx = set()
    excerpts = []
    for h in hits:
        if h.context and h.context not in seen_ctx:
            seen_ctx.add(h.context)
            excerpts.append(f"--- {h.file}:{h.line_no} (rule: {h.rule}) ---\n{h.context}")

    return LLM_PROMPT.format(
        pkg_name=pkg_name,
        version=version,
        hits_summary=hits_summary,
        code_excerpts="\n\n".join(excerpts[:10]),
    )


def _parse_json(text: str) -> Optional[dict]:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass
    return None


def _llm_claude_code(prompt: str) -> Optional[str]:
    """Claude Code CLI (subscription)."""
    import subprocess as sp
    try:
        r = sp.run(
            ["claude", "-p", "--max-turns", "1", prompt],
            capture_output=True, text=True, timeout=180,
        )
        if r.returncode != 0:
            log(f"  Claude Code CLI error: {(r.stderr or 'unknown')[:200]}", "ERR")
            return None
        return r.stdout.strip()
    except FileNotFoundError:
        log("  'claude' not found. Install Claude Code: https://claude.ai/code", "ERR")
        return None
    except sp.TimeoutExpired:
        log("  Claude Code CLI timeout (180s)", "ERR")
        return None
    except Exception as e:
        log(f"  Claude Code failed: {e}", "ERR")
        return None


def _llm_claude_api(prompt: str, model: str = "claude-sonnet-4-6") -> Optional[str]:
    """Anthropic Claude API (needs ANTHROPIC_API_KEY)."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        log("  ANTHROPIC_API_KEY not set. Export it or use a different backend.", "ERR")
        return None

    payload = json.dumps({
        "model": model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
    }).encode()

    try:
        req = request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        with request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
        return result["content"][0]["text"]
    except Exception as e:
        log(f"  Claude API failed: {e}", "ERR")
        return None


def _llm_chatgpt(prompt: str, model: str = "gpt-4o") -> Optional[str]:
    """OpenAI ChatGPT API (needs OPENAI_API_KEY)."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        log("  OPENAI_API_KEY not set. Export it or use a different backend.", "ERR")
        return None

    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 1024,
    }).encode()

    try:
        req = request.Request(
            OPENAI_API, data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        with request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
        return result["choices"][0]["message"]["content"]
    except Exception as e:
        log(f"  ChatGPT API failed: {e}", "ERR")
        return None


def _llm_ollama(prompt: str, model: str) -> Optional[str]:
    """Ollama local API."""
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 1024},
    }).encode()

    try:
        req = request.Request(
            OLLAMA_API, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req, timeout=300) as resp:
            result = json.loads(resp.read())
        return result.get("response", "")
    except Exception as e:
        log(f"  Ollama failed: {e}", "ERR")
        return None


# Model name aliases
MODEL_ALIASES = {
    "claude": "claude",
    "claude-code": "claude-code",
    "claude_code": "claude-code",
    "chatgpt": "chatgpt:gpt-4o",
    "gpt4": "chatgpt:gpt-4o",
    "gpt4o": "chatgpt:gpt-4o",
    "gpt-4o": "chatgpt:gpt-4o",
    "gpt-4o-mini": "chatgpt:gpt-4o-mini",
}


def ask_model() -> str:
    """Interactive model selection when --model is not provided."""
    print(f"\n{BOLD}  Select LLM backend for false positive filtering:{NC}\n")
    print(f"  {CYN}1{NC}) claude-code   Claude Code CLI (subscription)")
    print(f"  {CYN}2{NC}) claude        Anthropic API (ANTHROPIC_API_KEY)")
    print(f"  {CYN}3{NC}) chatgpt       OpenAI API (OPENAI_API_KEY)")
    print(f"  {CYN}4{NC}) ollama        Ollama local model")
    print(f"  {CYN}5{NC}) none          Heuristics only, no LLM\n")

    choices = {
        "1": "claude-code", "claude-code": "claude-code", "claude_code": "claude-code",
        "2": "claude", "claude": "claude",
        "3": "chatgpt", "chatgpt": "chatgpt",
        "4": "ollama", "ollama": "ollama",
        "5": "none", "none": "none",
    }

    while True:
        try:
            choice = input(f"  {BOLD}>{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)

        if choice in choices:
            selected = choices[choice]
            if selected == "ollama":
                model_name = input(f"  Ollama model name (e.g. qwen2.5:32b): ").strip()
                if not model_name:
                    print(f"  {RED}Model name required.{NC}")
                    continue
                return f"ollama:{model_name}"
            return selected

        print(f"  {RED}Invalid choice. Pick 1-5.{NC}")


def llm_analyze(pkg_name: str, version: str, hits: list[Hit], model: str) -> Optional[dict]:
    """Route to the right LLM backend.

    Formats:
        claude-code             -> Claude Code CLI (subscription)
        claude                  -> Anthropic API (ANTHROPIC_API_KEY)
        claude:<model>          -> Anthropic API specific model
        chatgpt                 -> OpenAI gpt-4o
        chatgpt:<model>         -> OpenAI specific model
        ollama:<model>          -> Ollama local
    """
    prompt = _build_prompt(pkg_name, version or "latest", hits)

    # Resolve aliases
    resolved = MODEL_ALIASES.get(model, model)

    if resolved == "claude-code":
        text = _llm_claude_code(prompt)
    elif resolved == "claude" or resolved.startswith("claude:"):
        api_model = resolved.split(":", 1)[1] if ":" in resolved else "claude-sonnet-4-6"
        text = _llm_claude_api(prompt, api_model)
    elif resolved.startswith("chatgpt"):
        oai_model = resolved.split(":", 1)[1] if ":" in resolved else "gpt-4o"
        text = _llm_chatgpt(prompt, oai_model)
    elif resolved.startswith("ollama:"):
        text = _llm_ollama(prompt, resolved[7:])
    else:
        # Bare name = ollama
        text = _llm_ollama(prompt, resolved)

    return _parse_json(text) if text else None


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    name: str
    version: str
    hits: list[Hit] = field(default_factory=list)
    llm: Optional[dict] = None
    error: Optional[str] = None


def print_result(r: ScanResult, verbose: bool = False):
    if r.error:
        log(f"{BOLD}{r.name}{NC} {r.version} - {RED}ERROR: {r.error}{NC}", "ERR")
        return

    if not r.hits:
        if verbose:
            log(f"{BOLD}{r.name}{NC} {r.version} - {GRN}CLEAN{NC}", "OK")
        return

    if r.llm:
        level = r.llm.get("threat_level", "UNKNOWN")
        summary = r.llm.get("summary", "")

        if level in ("CLEAN", "LOW"):
            label = GRN + "CLEAN" if level == "CLEAN" else DIM + "LOW"
            log(f"{BOLD}{r.name}{NC} {r.version} - {label}{NC} (LLM: {summary})", "OK")
            return

        color = severity_color(level)
        print(f"\n{'='*70}")
        print(f"{color}{BOLD}  [{level}] {r.name} {r.version}{NC}")
        print(f"  LLM: {summary}")
        print(f"{'='*70}")

        fp_rules = {
            f["rule"] for f in r.llm.get("findings", [])
            if f.get("verdict") == "FALSE_POSITIVE"
        }
        for finding in r.llm.get("findings", []):
            if finding.get("verdict") == "TRUE_POSITIVE":
                print(f"  {RED}! {finding['rule']}: {finding['explanation']}{NC}")
            elif verbose:
                print(f"  {DIM}  {finding['rule']}: (false positive) {finding['explanation']}{NC}")
    else:
        max_sev = max(r.hits, key=lambda h: {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(h.severity, 0))
        print(f"\n{'='*70}")
        print(f"{severity_color(max_sev.severity)}{BOLD}  [{max_sev.severity}] {r.name} {r.version}{NC}")
        print(f"  {len(r.hits)} heuristic hit(s) - no LLM verification")
        print(f"{'='*70}")

    for h in r.hits:
        show = True
        if r.llm:
            fp_rules = {f["rule"] for f in r.llm.get("findings", []) if f.get("verdict") == "FALSE_POSITIVE"}
            if h.rule in fp_rules:
                show = verbose
        if show:
            print(f"  {severity_color(h.severity)}[{h.severity}]{NC} {h.rule} in {h.file}:{h.line_no}")
            print(f"         {DIM}{h.line[:120]}{NC}")
    print()


# ---------------------------------------------------------------------------
# Scan pipeline
# ---------------------------------------------------------------------------

def scan_package(name: str, version: str = "", use_llm: bool = True,
                 model: str = "", verbose: bool = False) -> ScanResult:
    result = ScanResult(name=name, version=version)
    log(f"Scanning {BOLD}{name}{NC} {version}...")

    pkg_dir = download_package(name, version)
    if not pkg_dir:
        result.error = "Failed to download package"
        return result

    try:
        hits = scan_directory(pkg_dir)
        result.hits = hits

        if not hits:
            if verbose:
                log(f"  {GRN}No suspicious patterns{NC}", "OK")
            return result

        log(f"  {YEL}{len(hits)} suspicious pattern(s){NC}", "WARN")

        if use_llm:
            log(f"  Sending to LLM ({model}) for analysis...", "INFO")
            llm_result = llm_analyze(name, version or "latest", hits, model)
            result.llm = llm_result

            if llm_result:
                level = llm_result.get("threat_level", "UNKNOWN")
                color = severity_color(level) if level not in ("CLEAN", "LOW") else GRN
                log(f"  LLM verdict: {color}{level}{NC}", "INFO")
            else:
                log(f"  LLM failed, showing raw heuristics", "WARN")
    finally:
        shutil.rmtree(pkg_dir, ignore_errors=True)

    return result


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def _resolve_model(args) -> tuple[bool, str]:
    """Resolve model from args, prompting interactively if needed."""
    if args.no_llm:
        return False, ""
    if not args.model:
        chosen = ask_model()
        if chosen == "none":
            return False, ""
        return True, chosen
    return True, args.model


def mode_feed(args):
    seen = set()
    use_llm, model = _resolve_model(args)

    print(BANNER.format(version=VERSION))
    print(f"  Mode: {BOLD}RSS Feed Monitor{NC}")
    print(f"  LLM:  {model if use_llm else 'disabled'}")
    print(f"  Loop: {'every ' + str(args.loop) + 's' if args.loop else 'single run'}\n")

    while True:
        try:
            log("Fetching PyPI RSS feeds...", "INFO")
            new_items = parse_rss(fetch_url(PYPI_RSS_NEWEST))
            upd_items = parse_rss(fetch_url(PYPI_RSS_UPDATES))

            batch = []
            for item in new_items + upd_items:
                key = f"{item['name']}=={item['version']}"
                if key not in seen:
                    seen.add(key)
                    batch.append(item)

            if not batch:
                log("No new packages to scan", "OK")
            else:
                log(f"Found {len(batch)} package(s) to scan", "INFO")
                for item in batch:
                    r = scan_package(
                        item["name"], item["version"],
                        use_llm=use_llm,
                        model=model, verbose=args.verbose,
                    )
                    print_result(r, args.verbose)

        except KeyboardInterrupt:
            print(f"\n{GRN}Stopped.{NC}")
            return
        except Exception as e:
            log(f"Feed error: {e}", "ERR")

        if not args.loop:
            break

        log(f"Next scan in {args.loop}s... (Ctrl+C to stop)", "INFO")
        try:
            time.sleep(args.loop)
        except KeyboardInterrupt:
            print(f"\n{GRN}Stopped.{NC}")
            return


def mode_local(args):
    import subprocess as sp
    use_llm, model = _resolve_model(args)

    print(BANNER.format(version=VERSION))
    print(f"  Mode: {BOLD}Local Package Scanner{NC}")
    print(f"  LLM:  {model if use_llm else 'disabled'}\n")

    if args.packages:
        packages = [{"name": p, "version": ""} for p in args.packages]
        log(f"Scanning {len(packages)} specified package(s)...", "INFO")
    else:
        try:
            out = sp.check_output(
                [sys.executable, "-m", "pip", "list", "--format=json"],
                stderr=sp.DEVNULL, text=True,
            )
            packages = json.loads(out)
        except Exception:
            packages = []
        log(f"Found {len(packages)} installed package(s)", "INFO")

    stats = {"clean": 0, "flagged": 0, "errors": 0, "fp_filtered": 0}

    for pkg in packages:
        r = scan_package(
            pkg["name"], pkg.get("version", ""),
            use_llm=use_llm,
            model=model, verbose=args.verbose,
        )
        print_result(r, args.verbose)

        if r.error:
            stats["errors"] += 1
        elif not r.hits:
            stats["clean"] += 1
        elif r.llm and r.llm.get("threat_level") in ("CLEAN", "LOW"):
            stats["fp_filtered"] += 1
            stats["clean"] += 1
        else:
            stats["flagged"] += 1

    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"  {BOLD}Scan complete{NC}")
    print(f"  {GRN}Clean: {stats['clean']}{NC}  "
          f"{YEL}Flagged: {stats['flagged']}{NC}  "
          f"{DIM}FP filtered: {stats['fp_filtered']}{NC}  "
          f"{RED}Errors: {stats['errors']}{NC}")
    print(f"{BOLD}{'='*60}{NC}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog=NAME,
        description="PyPI Supply Chain Attack Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show clean packages and false positives")
    parser.add_argument("--no-llm", action="store_true",
                        help="Heuristics only, skip LLM analysis")
    parser.add_argument("--model", "-m", default="",
                        help="LLM backend. Options: "
                             "claude-code (CLI subscription), "
                             "claude (Anthropic API), "
                             "chatgpt (OpenAI API), "
                             "ollama:<model>. "
                             "If omitted, you'll be asked interactively.")
    parser.add_argument("--version", action="version", version=f"{NAME} {VERSION}")

    sub = parser.add_subparsers(dest="mode", required=True)

    feed_p = sub.add_parser("feed", help="Monitor PyPI RSS feed")
    feed_p.add_argument("--loop", type=int, default=0,
                        help="Loop interval in seconds (0 = single run)")

    local_p = sub.add_parser("local", help="Scan locally installed packages")
    local_p.add_argument("packages", nargs="*",
                         help="Specific packages (default: all installed)")

    args = parser.parse_args()

    if args.mode == "feed":
        mode_feed(args)
    elif args.mode == "local":
        mode_local(args)


if __name__ == "__main__":
    main()
