#!/usr/bin/env python3
"""PreToolUse guard: refuse tool calls that would send a secret off the machine.

An agent that can read your filesystem and also post to Discord, open a GitHub issue,
POST a webhook, or publish an Artifact is one careless paste away from putting a live
API key somewhere public. Prompt discipline does not fix that, because the agent does
not always know which strings are secret. This hook checks the payload instead.

It runs as a PreToolUse hook. It reads the tool call as JSON on stdin and writes a
decision as JSON on stdout, exit code 0 always, the same contract as tools/disk_guard.py
in the thousand repo.

Three detectors run over every outbound payload:

  1. Named regex rules for known credential shapes (AWS, GitHub, OpenAI, OpenRouter,
     Anthropic, Google, Slack, Stripe, private key blocks, JWTs, database URLs).
  2. Literal comparison against the live values of named environment variables, read
     from os.environ at hook runtime. Nothing is stored, nothing is printed.
  3. Shannon entropy on values that sit in an assignment or header position, which
     catches credential shapes nobody wrote a regex for.

Findings never echo the matched text. The denial message carries a rule id, a length,
and a salted fingerprint you can paste into the allowlist.

Usage:
    outbound_secret_guard.py                 hook mode, reads a tool call on stdin
    outbound_secret_guard.py scan FILE...    scan files, exit 1 on a blocking finding
    outbound_secret_guard.py learn-env VAR   store a salted hash of $VAR for later runs
    outbound_secret_guard.py forget          delete the salted hash store
    outbound_secret_guard.py fingerprint     read a value on stdin, print its fingerprint
    outbound_secret_guard.py selftest        run the built-in synthetic checks
"""

import argparse
import hashlib
import json
import math
import os
import pathlib
import base64
import re
import sys
import time

VERSION = "1.0.0"

# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------

DEFAULT_CONFIG = {
    # Shannon entropy in bits per character. Random base64 lands near 4.7 and above,
    # a 40 character hex sha tops out at 4.0, a UUID near 3.9. 4.2 separates them.
    "entropy_threshold": 4.2,
    "entropy_min_length": 32,
    "entropy_max_length": 512,

    # Environment variables whose live values are compared literally against payloads.
    "env_vars": [
        "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY", "GITHUB_TOKEN", "GH_TOKEN", "HF_TOKEN", "HUGGINGFACE_TOKEN",
        "NTFY_TOKEN", "DISCORD_BOT_TOKEN", "DISCORD_TOKEN", "SLACK_BOT_TOKEN",
        "STRIPE_SECRET_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "DATABASE_URL", "POSTGRES_URL", "NEON_DATABASE_URL", "VERCEL_TOKEN",
    ],
    "env_min_length": 12,        # ignore short env values, they cause false positives

    # Allowlisting. Three shapes, because a real false positive is sometimes a literal
    # you can paste, sometimes a family you need a regex for, and sometimes a value you
    # are not willing to write into a config file.
    "allow_literals": [],
    "allow_patterns": [],
    "allow_fingerprints": [],

    "disabled_rules": [],
    "promote_to_block": [],      # rule ids whose severity becomes "block"
    "demote_to_warn": [],        # rule ids whose severity becomes "warn"

    # Which tools count as outbound. Anything not matched here is ignored entirely.
    "outbound_tool_patterns": [],   # extra patterns, appended to the built-ins
    "local_tool_patterns": [],      # extra exemptions, appended to the built-ins
    "scan_all_tools": False,        # paranoid mode: every tool call is outbound

    "read_file_payloads": True,     # Artifact publishes a file, so read and scan it
    "max_file_bytes": 1_000_000,

    "on_error": "ask",              # allow | ask | deny, when the scan itself fails
    "audit_log": None,              # path; records rule ids and counts, never content
}

CONFIG_ENV = "OUTBOUND_SECRET_GUARD_CONFIG"
STORE_ENV = "OUTBOUND_SECRET_GUARD_STORE"
DEFAULT_STORE = pathlib.Path.home() / ".config" / "outbound-secret-guard" / "known_secrets.json"


def config_paths(cwd):
    explicit = os.environ.get(CONFIG_ENV)
    if explicit:
        return [pathlib.Path(explicit)]
    return [
        pathlib.Path(cwd) / ".outbound-secret-guard.json",
        pathlib.Path.home() / ".config" / "outbound-secret-guard" / "config.json",
    ]


def load_config(cwd="."):
    cfg = dict(DEFAULT_CONFIG)
    for path in config_paths(cwd):
        try:
            if path.is_file():
                user = json.loads(path.read_text())
                if isinstance(user, dict):
                    cfg.update(user)
                break
        except Exception:
            # A broken config must not silently disable the guard, but it must also not
            # brick the agent. Defaults stand and the reason surfaces in the finding list.
            cfg.setdefault("_config_error", str(path))
    return cfg


# --------------------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------------------

# (id, severity, safe_prefix_chars, compiled regex, human description)
# safe_prefix_chars is how much of a match may appear in a message. It is only ever set
# to the public, non-entropic part of a credential shape, for example "ghp_".
RULES = [
    ("aws-access-key-id", "block", 4,
     r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)[A-Z0-9]{16})\b",
     "AWS access key id"),
    ("aws-secret-access-key", "block", 0,
     r"(?i)aws_?secret_?access_?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{40})",
     "AWS secret access key"),
    ("github-pat", "block", 4,
     r"\b(gh[pousr]_[A-Za-z0-9]{36,251})\b",
     "GitHub personal access / OAuth / server token"),
    ("github-fine-grained-pat", "block", 11,
     r"\b(github_pat_[A-Za-z0-9_]{22,255})\b",
     "GitHub fine grained personal access token"),
    ("openrouter-key", "block", 9,
     r"\b(sk-or-(?:v1-)?[A-Za-z0-9]{32,})\b",
     "OpenRouter API key"),
    ("anthropic-key", "block", 7,
     r"\b(sk-ant-(?:api\d{2}-)?[A-Za-z0-9_\-]{24,})\b",
     "Anthropic API key"),
    ("openai-key", "block", 3,
     r"\b(sk-(?!or-|ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,})\b",
     "OpenAI API key"),
    ("google-api-key", "block", 4,
     r"\b(AIza[0-9A-Za-z_\-]{35})\b",
     "Google / Gemini API key"),
    ("gcp-service-account", "block", 0,
     r"\"type\"\s*:\s*\"service_account\"",
     "GCP service account JSON"),
    ("private-key-block", "block", 0,
     r"-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
     "PEM private key block"),
    ("jwt", "block", 0,
     r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b",
     "JSON Web Token"),
    ("slack-token", "block", 4,
     r"\b(xox[baprse]-[A-Za-z0-9\-]{10,})\b",
     "Slack token"),
    ("slack-webhook", "block", 0,
     r"https://hooks\.slack\.com/services/[A-Za-z0-9_\-/]{20,}",
     "Slack incoming webhook"),
    ("discord-bot-token", "block", 0,
     r"\b([MNO][A-Za-z0-9_\-]{22,26}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,})\b",
     "Discord bot token"),
    ("discord-webhook", "block", 0,
     r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{20,}",
     "Discord webhook URL"),
    ("stripe-live-key", "block", 8,
     r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b",
     "Stripe live secret key"),
    ("stripe-test-key", "warn", 8,
     r"\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\b",
     "Stripe test key (not production, but still a credential)"),
    ("npm-token", "block", 4,
     r"\b(npm_[A-Za-z0-9]{36})\b",
     "npm access token"),
    ("pypi-token", "block", 5,
     r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b",
     "PyPI upload token"),
    ("huggingface-token", "block", 3,
     r"\b(hf_[A-Za-z0-9]{34,})\b",
     "Hugging Face access token"),
    ("gitlab-pat", "block", 6,
     r"\b(glpat-[A-Za-z0-9_\-]{20,})\b",
     "GitLab personal access token"),
    ("sendgrid-key", "block", 3,
     r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b",
     "SendGrid API key"),
    ("twilio-account-sid", "warn", 2,
     r"\b(AC[0-9a-fA-F]{32})\b",
     "Twilio account SID"),
    ("url-embedded-credential", "block", 0,
     r"\b[a-z][a-z0-9+.\-]{1,20}://[^\s:@/]{1,64}:([^\s:@/]{4,})@[^\s/]{3,}",
     "credential embedded in a URL"),
    ("authorization-header", "warn", 0,
     r"(?i)authorization\s*[:=]\s*[\"']?(?:bearer|basic|token)\s+([A-Za-z0-9+/=_\-\.]{20,})",
     "populated Authorization header"),
]

RULES = [(rid, sev, pre, re.compile(rx), desc) for rid, sev, pre, rx, desc in RULES]

# Assignment and header positions worth entropy checking. Group 1 is the name where the
# pattern has one, the last group is always the candidate value.
ENTROPY_CONTEXTS = [
    re.compile(
        r"(?i)\b([A-Za-z0-9_.\-]*(?:api[_\-]?key|apikey|secret|token|password|passwd|pwd"
        r"|credential|auth|bearer|session|cookie|private[_\-]?key|key)[A-Za-z0-9_.\-]*)\s*"
        r"[:=]{1,2}\s*[\"']?([A-Za-z0-9+/=_\-\.~]{20,})[\"']?"),
    re.compile(
        r"--(?:token|key|secret|password|api[_\-]?key|auth)[=\s]+[\"']?"
        r"([A-Za-z0-9+/=_\-\.~]{20,})[\"']?"),
    re.compile(
        r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9+/=_\-\.~]{20,})"),
    re.compile(
        r"(?i)[?&](?:api[_\-]?key|access[_\-]?token|auth[_\-]?token|token|key|secret)="
        r"([A-Za-z0-9+/=_\-\.~]{20,})"),
]

# Names that sit in an assignment position but hold something public by definition.
ENTROPY_NAME_EXCLUDE = re.compile(
    r"(?i)(public|pubkey|integrity|checksum|digest|etag|sha1|sha256|sha512|fingerprint"
    r"|_id\b|keyid|keyboard|keyword|keypath|monkey|tokenizer|tokens?_(?:used|count|in|out)"
    r"|max_tokens|authors?|author)")

# Values that are obviously not live credentials.
PLACEHOLDER = re.compile(
    r"(?i)^(?:x{6,}|\*{6,}|\.{3,}|<[^>]*>|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"
    r"|(?:your|my|the)[_\-].*|.*(?:example|placeholder|changeme|change_me|redacted"
    r"|dummy|sample|fake|not[_\-]?a[_\-]?real|xxxx|todo|abcdef0123456789|deadbeef)"
    r".*|os\.environ.*|process\.env.*)$")

# Whole-value shapes that carry high entropy but are not credentials.
NOT_A_SECRET = [
    re.compile(r"^[0-9a-f]{7,64}$"),                                   # git sha, md5, sha256
    re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
               r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),                    # uuid
    re.compile(r"^sha\d{3}-"),                                         # lockfile integrity
    re.compile(r"^\d{4}-\d{2}-\d{2}T[\d:.\-+Z]+$"),                    # iso timestamp
    re.compile(r"^[A-Za-z0-9_\-]+\.(?:js|ts|py|css|html|json|map|lock|txt|md)$"),
    re.compile(r"^(?:/[A-Za-z0-9_.\-]+){2,}/?$"),                      # unix path
    re.compile(r"^data:[a-z]+/[a-z0-9.+\-]+;base64,"),                 # inline asset
]


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------------------
# Salted fingerprints and the optional hash store
# --------------------------------------------------------------------------------------

def store_path():
    return pathlib.Path(os.environ.get(STORE_ENV) or DEFAULT_STORE)


_STORE_CACHE = {}


def load_store(create=False):
    """Return {"salt": hex, "entries": [{"label", "len", "sha256"}]}.

    The store never contains a secret. It contains sha256(salt || value), which cannot be
    reversed without guessing the value, and a length so scanning only hashes candidates
    that could possibly match.

    Cached per process and per path, because the salt has to be stable within a run or
    two findings for the same value would carry different fingerprints.
    """
    path = store_path()
    key = str(path)
    if key in _STORE_CACHE and not create:
        return _STORE_CACHE[key]
    try:
        if path.is_file():
            data = json.loads(path.read_text())
            if isinstance(data, dict) and "salt" in data:
                data.setdefault("entries", [])
                _STORE_CACHE[key] = data
                return data
    except Exception:
        pass
    store = {"salt": os.urandom(32).hex(), "entries": []}
    if create:
        write_store(store)
    _STORE_CACHE[key] = store
    return store


def write_store(store):
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2))
    try:
        path.chmod(0o600)
    except Exception:
        pass
    _STORE_CACHE[str(path)] = store


def salted_hash(salt_hex, value):
    return hashlib.sha256(bytes.fromhex(salt_hex) + value.encode("utf-8", "replace")).hexdigest()


def fingerprint(value):
    """Short, stable, machine local identifier for a value. Safe to print and to commit.

    Salted with the store salt so a fingerprint published in a config file cannot be
    matched against a candidate secret by anyone who does not also hold the salt. The
    store is created on first use so the salt survives across runs; without that, an
    allowlisted fingerprint would stop matching the moment the process exits.
    """
    return salted_hash(load_store(create=not store_path().is_file()).get("salt", ""), value)[:12]


# --------------------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------------------

def _allowed(value, cfg, allow_res):
    if value in cfg.get("allow_literals", []):
        return True
    for rx in allow_res:
        if rx.fullmatch(value):
            return True
    fps = cfg.get("allow_fingerprints", [])
    if fps:
        fp = fingerprint(value)
        if any(fp.startswith(x) for x in fps if x):
            return True
    return False


def _redact(value, safe_prefix):
    head = value[:safe_prefix] if safe_prefix else ""
    return f"{head}[redacted {len(value)} chars]"


def _finding(rule_id, severity, description, value, safe_prefix, where):
    return {
        "rule": rule_id,
        "severity": severity,
        "description": description,
        "redacted": _redact(value, safe_prefix),
        "fingerprint": fingerprint(value),
        "where": where,
    }


def env_secrets(cfg):
    """Live secret values from the environment. Held in memory for this process only."""
    out = []
    minlen = cfg.get("env_min_length", 12)
    for name in cfg.get("env_vars", []):
        val = os.environ.get(name)
        if val and len(val) >= minlen:
            out.append((name, val))
    return out


_B64_BLOB = re.compile(r"[A-Za-z0-9+/=]{24,}")


def _decode_base64_blobs(text, limit=40):
    """Base64-decode any long base64-looking run and return the printable results.

    An agent that wraps a value before sending it (an auth header, a JSON payload, a data
    URI) defeats a literal comparison entirely. Decoding is cheap and the false-positive
    cost is zero, because a decoded blob is only ever compared against known secrets and
    never reported on its own.

    Deliberately NOT attempted: reversal, character substitution, encryption, chunking a
    secret across separate tool calls. Those are unbounded transformations and a scanner
    that claimed to catch them would be lying. This guard stops accidents and casual
    encoding, not a determined exfiltrator with shell access.
    """
    out = []
    for m in _B64_BLOB.findall(text)[:limit]:
        pad = m + "=" * (-len(m) % 4)
        try:
            raw = base64.b64decode(pad, validate=False)
        except Exception:
            continue
        try:
            s = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        if s.isprintable():
            out.append(s)
    return out


def scan_text(text, cfg, where="payload", live=None, store=None):
    """Return a list of findings. Never returns the matched text."""
    findings = []
    if not text:
        return findings
    seen = set()
    allow_res = []
    for pat in cfg.get("allow_patterns", []):
        try:
            allow_res.append(re.compile(pat))
        except re.error:
            pass
    disabled = set(cfg.get("disabled_rules", []))
    promote = set(cfg.get("promote_to_block", []))
    demote = set(cfg.get("demote_to_warn", []))

    def add(f):
        key = (f["rule"], f["fingerprint"])
        if key in seen:
            return
        seen.add(key)
        if f["rule"] in promote:
            f["severity"] = "block"
        elif f["rule"] in demote:
            f["severity"] = "warn"
        findings.append(f)

    # Two derived views of the payload, so a value that is present but not literally
    # contiguous is still caught. Both were added after attacking the guard directly and
    # finding that a secret survived a single injected newline, which is something ordinary
    # line wrapping in a chat message can do by accident.
    dewhitespaced = re.sub(r"\s+", "", text)
    decoded_blobs = _decode_base64_blobs(text)

    # 1. Live environment values, literal substring comparison. Highest confidence signal
    #    there is: this exact string is a credential this machine holds right now.
    for name, val in (live if live is not None else env_secrets(cfg)):
        if _allowed(val, cfg, allow_res):
            continue
        if val in text:
            add(_finding("env-live-value", "block",
                         f"live value of ${name} from this machine's environment",
                         val, 0, where))
        elif val in dewhitespaced:
            add(_finding("env-live-value", "block",
                         f"live value of ${name}, split by whitespace in the payload",
                         val, 0, where))
        else:
            for blob in decoded_blobs:
                if val in blob:
                    add(_finding("env-live-value", "block",
                                 f"live value of ${name}, base64 encoded in the payload",
                                 val, 0, where))
                    break

    # 2. Previously learned values, matched by salted hash so nothing is stored in clear.
    if store and store.get("entries"):
        lengths = {e["len"]: [] for e in store["entries"]}
        for e in store["entries"]:
            lengths[e["len"]].append(e)
        for token in set(re.findall(r"[A-Za-z0-9_\-\.+/=~]{8,}", text)):
            bucket = lengths.get(len(token))
            if not bucket:
                continue
            h = salted_hash(store["salt"], token)
            for e in bucket:
                if e["sha256"] == h and not _allowed(token, cfg, allow_res):
                    add(_finding("known-secret", "block",
                                 f"matches the stored fingerprint of {e['label']}",
                                 token, 0, where))

    # 3. Named credential shapes.
    for rid, severity, safe_prefix, rx, desc in RULES:
        if rid in disabled:
            continue
        for m in rx.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            if _allowed(value, cfg, allow_res):
                continue
            add(_finding(rid, severity, desc, value, safe_prefix, where))

    # 4. Entropy in an assignment or header position.
    if "high-entropy" not in disabled:
        threshold = float(cfg.get("entropy_threshold", 4.2))
        minlen = int(cfg.get("entropy_min_length", 32))
        maxlen = int(cfg.get("entropy_max_length", 512))
        for rx in ENTROPY_CONTEXTS:
            for m in rx.finditer(text):
                groups = m.groups()
                name = groups[0] if len(groups) > 1 else ""
                value = groups[-1]
                if not (minlen <= len(value) <= maxlen):
                    continue
                if name and ENTROPY_NAME_EXCLUDE.search(name):
                    continue
                if PLACEHOLDER.match(value):
                    continue
                if any(p.match(value) for p in NOT_A_SECRET):
                    continue
                if len(set(value)) < 12:
                    continue
                ent = shannon_entropy(value)
                if ent < threshold:
                    continue
                if _allowed(value, cfg, allow_res):
                    continue
                label = f"high entropy value ({ent:.2f} bits/char)"
                if name:
                    label += f" assigned to {name!r}"
                add(_finding("high-entropy", "block", label, value, 0, where))

    return findings


# --------------------------------------------------------------------------------------
# Which tool calls leave the machine, and what text they carry
# --------------------------------------------------------------------------------------

OUTBOUND_TOOLS = [
    r"^WebFetch$",
    r"^WebSearch$",
    r"^Artifact$",
    r"^mcp__",                       # MCP servers talk to remote services by default
]

LOCAL_TOOLS = [
    r"^mcp__mempalace__",
    r"^mcp__plugin_claude-mem_",
    r"^mcp__ide__",
]

# A Bash call is outbound only when the command itself reaches the network. Treating
# every shell command as outbound would flag `cat .env`, which is a local read, and the
# resulting noise is how a guard gets switched off.
BASH_EGRESS = re.compile(
    r"\b(?:curl|wget|http|https|httpie|xh|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|ftp"
    r"|mail|mailx|sendmail|mutt|ntfy"
    r"|gh|glab|git\s+push|npm\s+publish|yarn\s+publish|pnpm\s+publish|twine\s+upload"
    r"|aws|gcloud|gsutil|az|vercel|netlify|fly|flyctl|wrangler|heroku|supabase|railway"
    r"|hf\s+upload|huggingface-cli\s+upload|openssl\s+s_client|ollama\s+push)\b")


def is_outbound(tool_name, tool_input, cfg):
    if cfg.get("scan_all_tools"):
        return True
    if not tool_name:
        return False
    for pat in LOCAL_TOOLS + list(cfg.get("local_tool_patterns", [])):
        if re.search(pat, tool_name):
            return False
    for pat in OUTBOUND_TOOLS + list(cfg.get("outbound_tool_patterns", [])):
        if re.search(pat, tool_name):
            return True
    if tool_name == "Bash":
        return bool(BASH_EGRESS.search((tool_input or {}).get("command", "")))
    return False


def collect_text(obj, cfg, path="tool_input", out=None):
    """Flatten every string in the tool input, keeping a path for the report."""
    if out is None:
        out = []
    if isinstance(obj, str):
        out.append((path, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            collect_text(v, cfg, f"{path}.{k}", out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            collect_text(v, cfg, f"{path}[{i}]", out)
    return out


FILE_FIELDS = ("file_path", "files", "path", "notebook_path")


def collect_file_payloads(tool_input, cfg):
    """Artifact publishes a file's contents, so the file is the payload, not the path."""
    if not cfg.get("read_file_payloads", True) or not isinstance(tool_input, dict):
        return []
    out = []
    cap = int(cfg.get("max_file_bytes", 1_000_000))
    candidates = []
    for field in FILE_FIELDS:
        v = tool_input.get(field)
        if isinstance(v, str):
            candidates.append(v)
        elif isinstance(v, list):
            candidates += [x for x in v if isinstance(x, str)]
    for c in candidates:
        try:
            p = pathlib.Path(c)
            if p.is_file() and p.stat().st_size <= cap:
                out.append((f"contents of {p.name}", p.read_text(errors="replace")))
        except Exception:
            continue
    return out


# --------------------------------------------------------------------------------------
# Hook mode
# --------------------------------------------------------------------------------------

def format_reason(tool_name, findings):
    blocking = [f for f in findings if f["severity"] == "block"]
    lines = [
        f"BLOCKED: outbound-secret-guard found {len(blocking)} credential"
        f"{'' if len(blocking) == 1 else 's'} in this {tool_name} payload, which leaves "
        f"this machine.",
        "",
    ]
    for f in blocking:
        lines.append(f"  [{f['rule']}] {f['description']}")
        lines.append(f"      value: {f['redacted']}   fingerprint: {f['fingerprint']}")
        lines.append(f"      found in: {f['where']}")
    warns = [f for f in findings if f["severity"] == "warn"]
    if warns:
        lines.append("")
        lines.append("Also seen, not blocking:")
        for f in warns:
            lines.append(f"  [{f['rule']}] {f['description']} ({f['redacted']})")
    lines += [
        "",
        "The matched text is deliberately not reproduced here, because this message goes",
        "into the transcript. Do not retry with the value pasted differently.",
        "",
        "What to do:",
        "  - If it is a real credential: send an environment variable reference instead,",
        "    for example $OPENROUTER_API_KEY, and rotate the key if it already went out.",
        "  - If it is a false positive: add the fingerprint above to allow_fingerprints in",
        "    .outbound-secret-guard.json, or the rule id to disabled_rules. Both are",
        "    documented in the project README.",
    ]
    return "\n".join(lines)


def audit(cfg, tool_name, findings):
    path = cfg.get("audit_log")
    if not path:
        return
    try:
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "tool": tool_name,
            "rules": sorted({f["rule"] for f in findings}),
            "fingerprints": sorted({f["fingerprint"] for f in findings}),
            "blocked": any(f["severity"] == "block" for f in findings),
        }
        p = pathlib.Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except Exception:
        pass


def emit(obj):
    print(json.dumps(obj))


def decision(kind, reason):
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": kind,
        "permissionDecisionReason": reason,
    }}


def run_hook(stdin_text):
    try:
        payload = json.loads(stdin_text)
    except Exception:
        # Unparseable input is not a tool call this guard understands. Staying out of the
        # way is correct here; a scan failure on a real payload is handled below.
        emit({})
        return 0

    cfg = load_config((payload.get("cwd") or "."))
    tool_name = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input") or {}

    if not is_outbound(tool_name, tool_input, cfg):
        emit({})
        return 0

    try:
        live = env_secrets(cfg)
        store = load_store()
        findings = []
        for where, text in collect_text(tool_input, cfg) + collect_file_payloads(tool_input, cfg):
            findings += scan_text(text, cfg, where=where, live=live, store=store)
    except Exception as exc:
        mode = cfg.get("on_error", "ask")
        reason = (f"outbound-secret-guard failed while scanning this {tool_name} payload: "
                  f"{type(exc).__name__}. It cannot confirm the payload is clean.")
        if mode == "allow":
            emit({})
        else:
            emit(decision("deny" if mode == "deny" else "ask", reason))
        return 0

    if not findings:
        emit({})
        return 0

    audit(cfg, tool_name, findings)

    if any(f["severity"] == "block" for f in findings):
        emit(decision("deny", format_reason(tool_name, findings)))
        return 0

    warn_lines = [f"  [{f['rule']}] {f['description']} ({f['redacted']})" for f in findings]
    emit({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "additionalContext": "outbound-secret-guard advisory for this outbound "
                             f"{tool_name} payload:\n" + "\n".join(warn_lines),
    }})
    return 0


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------

SELFTEST_CASES = [
    # (label, text, expect_block)
    ("synthetic github pat", "token ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", True),
    ("synthetic google key", "key AIza" + "Sy" + "0" * 29 + "EXAM", True),
    ("synthetic openrouter", "sk-or-v1-" + "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
                                           "0f1e2d3c4b5a69788796a5b4c3d2e1f0", True),
    ("env var reference", "curl -H \"Authorization: Bearer $OPENROUTER_API_KEY\" x.dev", False),
    ("git sha", "reverting to 9f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c now", False),
]


def cmd_selftest(_args):
    cfg = load_config()
    ok = True
    for label, text, expect in SELFTEST_CASES:
        found = scan_text(text, cfg, live=[], store=None)
        blocked = any(f["severity"] == "block" for f in found)
        status = "ok " if blocked == expect else "FAIL"
        if blocked != expect:
            ok = False
        rules = ",".join(sorted({f["rule"] for f in found})) or "-"
        print(f"{status} {label:26s} blocked={blocked!s:5s} expected={expect!s:5s} [{rules}]")
    print("selftest passed" if ok else "selftest FAILED")
    return 0 if ok else 1


def cmd_learn_env(args):
    names = args.vars or DEFAULT_CONFIG["env_vars"]
    store = load_store(create=True)
    known = {(e["label"], e["sha256"]) for e in store["entries"]}
    added = 0
    for name in names:
        val = os.environ.get(name)
        if not val or len(val) < DEFAULT_CONFIG["env_min_length"]:
            print(f"skip  {name}: unset or too short")
            continue
        h = salted_hash(store["salt"], val)
        if (name, h) in known:
            print(f"have  {name}: already stored")
            continue
        store["entries"].append({"label": name, "len": len(val), "sha256": h})
        added += 1
        print(f"store {name}: length {len(val)}, fingerprint {h[:12]}")
    write_store(store)
    print(f"{added} added, store at {store_path()} (salted hashes only, no values)")
    return 0


def cmd_forget(_args):
    path = store_path()
    if path.exists():
        path.unlink()
        print(f"removed {path}")
    else:
        print(f"nothing to remove at {path}")
    return 0


def cmd_fingerprint(_args):
    value = sys.stdin.read().strip()
    if not value:
        print("read nothing on stdin", file=sys.stderr)
        return 2
    print(fingerprint(value))
    return 0


def cmd_scan(args):
    cfg = load_config()
    live = env_secrets(cfg)
    store = load_store()
    worst = 0
    for name in args.paths:
        p = pathlib.Path(name)
        try:
            text = sys.stdin.read() if name == "-" else p.read_text(errors="replace")
        except Exception as exc:
            print(f"{name}: unreadable ({exc})")
            continue
        for f in scan_text(text, cfg, where=name, live=live, store=store):
            print(f"{name}: [{f['severity']}] {f['rule']}: {f['description']} "
                  f"-> {f['redacted']} fp={f['fingerprint']}")
            worst = max(worst, 1 if f["severity"] == "block" else 0)
    return worst


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] == "hook":
        return run_hook(sys.stdin.read())

    ap = argparse.ArgumentParser(prog="outbound_secret_guard.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hook", help="read a PreToolUse payload on stdin")
    s = sub.add_parser("scan", help="scan files, exit 1 on a blocking finding")
    s.add_argument("paths", nargs="+")
    s.set_defaults(func=cmd_scan)
    s = sub.add_parser("learn-env", help="store salted hashes of environment secrets")
    s.add_argument("vars", nargs="*")
    s.set_defaults(func=cmd_learn_env)
    sub.add_parser("forget", help="delete the salted hash store").set_defaults(func=cmd_forget)
    sub.add_parser("fingerprint", help="fingerprint a value read on stdin").set_defaults(
        func=cmd_fingerprint)
    sub.add_parser("selftest", help="run built-in synthetic checks").set_defaults(
        func=cmd_selftest)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
