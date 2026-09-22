#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PII Guard - a UserPromptSubmit hook for Claude Code.

Scans the prompt locally before it is sent to the model and blocks it when it
contains credentials or personal data. Nothing leaves the machine: no network
calls, no telemetry, no dependencies beyond the standard library.

Claude Code's UserPromptSubmit event cannot rewrite the prompt (updatedInput is
not supported there), so a detection blocks the turn instead. The original text
is saved locally for recovery and a masked copy is placed on the clipboard so
the user can paste it straight back.

Usage (as a hook):   echo '<event json>' | python3 pii_guard.py
Usage (self-test):   python3 pii_guard.py --selftest
Usage (one-off):     python3 pii_guard.py --scan "text to check"
"""

import json
import os
import platform
import re
import subprocess
import sys
import time

VERSION = "0.1.0"
HOME = os.path.expanduser("~")
PLUGIN_ROOT = os.environ.get(
    "CLAUDE_PLUGIN_ROOT", os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
DATA_DIR = os.environ.get(
    "CLAUDE_PLUGIN_DATA", os.path.join(HOME, ".claude", "pii-guard")
)
STORE_DIR = os.path.join(DATA_DIR, "blocked")

BUILTIN_CONFIG = {
    "enabled": True,
    "bypass_marker": "#pii-ok",
    "rules": {
        "private_key": "block",
        "api_key": "block",
        "jwt": "block",
        "password": "block",
        "credit_card": "block",
        "my_number": "block",
        "bank_account": "block",
        "passport": "block",
        "email": "block",
        "phone": "block",
        "postal": "block",
        "address": "block",
    },
    "allow_patterns": [
        r"@(example|test|invalid|localhost)\.",
        r"^(noreply|no-reply)@",
        r"^(foo|bar|hoge|fuga|test|dummy|sample)@",
    ],
    "save_blocked_prompt": True,
    "copy_masked_to_clipboard": True,
    "retention_days": 7,
}

LABELS = {
    "private_key": ("秘密鍵", "private key"),
    "api_key": ("APIキー/トークン", "API key / token"),
    "jwt": ("JWT", "JWT"),
    "password": ("パスワード/認証情報", "password / credential"),
    "credit_card": ("クレジットカード番号", "credit card number"),
    "my_number": ("マイナンバー", "My Number"),
    "bank_account": ("口座番号", "bank account number"),
    "passport": ("パスポート番号", "passport number"),
    "email": ("メールアドレス", "email address"),
    "phone": ("電話番号", "phone number"),
    "postal": ("郵便番号", "postal code"),
    "address": ("住所", "street address"),
}


def label(rule):
    ja, en = LABELS.get(rule, (rule, rule))
    return ja if lang() == "ja" else en


def lang():
    return "en" if os.environ.get("PII_GUARD_LANG", "ja").lower().startswith("en") else "ja"


# ------------------------------------------------------------------ config

def _merge(base, overlay):
    out = dict(base)
    for k, v in overlay.items():
        if k == "rules" and isinstance(v, dict) and isinstance(out.get(k), dict):
            merged = dict(out[k])
            merged.update(v)
            out[k] = merged
        else:
            out[k] = v
    return out


def config_paths():
    """Lowest precedence first."""
    paths = [os.path.join(PLUGIN_ROOT, "config.default.json"),
             os.path.join(HOME, ".claude", "pii-guard.config.json")]
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    if project:
        paths.append(os.path.join(project, ".claude", "pii-guard.json"))
    override = os.environ.get("PII_GUARD_CONFIG")
    if override:
        paths.append(override)
    return paths


def load_config():
    cfg = json.loads(json.dumps(BUILTIN_CONFIG))
    for path in config_paths():
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = _merge(cfg, json.load(f))
        except (IOError, OSError):
            continue
        except ValueError as exc:
            sys.stderr.write("PII Guard: ignoring invalid config {}: {}\n".format(path, exc))
    return cfg


# --------------------------------------------------------------- detectors

SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("api_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}")),
    ("api_key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("api_key", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("api_key", re.compile(r"github_pat_[A-Za-z0-9_]{40,}")),
    ("api_key", re.compile(r"A(?:KIA|SIA)[0-9A-Z]{16}")),
    ("api_key", re.compile(r"xox[abopsr]-[A-Za-z0-9\-]{10,}")),
    ("api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("api_key", re.compile(r"glpat-[A-Za-z0-9_\-]{16,}")),
    ("api_key", re.compile(r"(?:r8_|hf_|sk_live_|pk_live_|rk_live_)[A-Za-z0-9]{20,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<![0-9\-+])(?:\+81[ \-]?\d{1,4}|0\d{1,4})[ \-]?\d{1,4}[ \-]?\d{3,4}(?![0-9\-])")
DIGITS12_RE = re.compile(r"(?<![0-9])\d{4}[ \-]?\d{4}[ \-]?\d{4}(?![0-9])")
CARD_RE = re.compile(r"(?<![0-9\-])(?:\d[ \-]?){12,18}\d(?![0-9\-])")
POSTAL_RE = re.compile(r"〒\s*[0-9０-９]{3}[\-‐ー－−]?[0-9０-９]{4}")
ADDRESS_RE = re.compile(
    r"[一-鿿]{2,5}[都道府県][^\n]{0,15}?[市区町村][^\n]{0,25}?"
    r"[0-9０-９]+[\-ー－−‐丁目][0-9０-９]+(?:[\-ー－−‐番地号][0-9０-９]+)*"
)
DIGITS7_RE = re.compile(r"(?<![0-9])\d{7}(?![0-9])")
PASSPORT_RE = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{7}(?![A-Z0-9])")
CRED_KV_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|api[_\- ]?key|access[_\- ]?token|auth[_\- ]?token"
    r"|client[_\- ]?secret|パスワード|暗証番号)\s*(?:[:=：]|は)\s*[\"'`]?([^\s\"'`,;]{6,})"
)
PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:\*+|x+|\.+|-+|<.*>|\{.*\}|\$\{?\w+\}?|os\.|process\.|None|null|undefined|true|false"
    r"|your[_\-]|my[_\-]|dummy|sample|example|placeholder|changeme|password|secret|redacted|\[)"
)
BANK_KEYWORD_RE = re.compile(r"口座番号|振込先|支店番号|普通預金|当座預金|account number")
MYNUM_KEYWORD_RE = re.compile(r"マイナンバー|個人番号")
PASSPORT_KEYWORD_RE = re.compile(r"パスポート|旅券|passport")


def luhn_ok(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def mynumber_check_ok(digits):
    """Japanese My Number (個人番号) check-digit validation."""
    if len(digits) != 12:
        return False
    body = [int(c) for c in digits[:11]]
    total = 0
    for n in range(1, 12):
        q = n + 1 if n <= 6 else n - 5
        total += body[11 - n] * q
    r = total % 11
    return int(digits[11]) == (0 if r <= 1 else 11 - r)


def detect(text):
    """Return [(start, end, rule)] for every candidate in `text`."""
    found = []

    for rule, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            found.append((m.start(), m.end(), rule))

    for m in CRED_KV_RE.finditer(text):
        if not PLACEHOLDER_RE.match(m.group(1)):
            found.append((m.start(1), m.end(1), "password"))

    for m in EMAIL_RE.finditer(text):
        found.append((m.start(), m.end(), "email"))

    for m in PHONE_RE.finditer(text):
        raw = m.group(0)
        d = re.sub(r"\D", "", raw)
        if raw.startswith("+81"):
            d = "0" + d[2:]
        if len(d) in (10, 11) and d.startswith("0"):
            found.append((m.start(), m.end(), "phone"))

    has_mynum_kw = bool(MYNUM_KEYWORD_RE.search(text))
    for m in DIGITS12_RE.finditer(text):
        d = re.sub(r"\D", "", m.group(0))
        if has_mynum_kw or mynumber_check_ok(d):
            found.append((m.start(), m.end(), "my_number"))

    for m in CARD_RE.finditer(text):
        d = re.sub(r"\D", "", m.group(0))
        if len(d) in (13, 14, 15, 16, 19) and d[0] in "23456" and luhn_ok(d):
            found.append((m.start(), m.end(), "credit_card"))

    for m in POSTAL_RE.finditer(text):
        found.append((m.start(), m.end(), "postal"))

    for m in ADDRESS_RE.finditer(text):
        found.append((m.start(), m.end(), "address"))

    if BANK_KEYWORD_RE.search(text):
        for m in DIGITS7_RE.finditer(text):
            found.append((m.start(), m.end(), "bank_account"))

    if PASSPORT_KEYWORD_RE.search(text):
        for m in PASSPORT_RE.finditer(text):
            found.append((m.start(), m.end(), "passport"))

    return found


def apply_policy(text, found, cfg):
    """Drop allow-listed and disabled hits, then resolve overlaps."""
    allows = []
    for p in cfg.get("allow_patterns", []):
        try:
            allows.append(re.compile(p))
        except re.error:
            sys.stderr.write("PII Guard: skipping invalid allow_pattern {!r}\n".format(p))

    rules = cfg.get("rules", {})
    kept = []
    for start, end, rule in found:
        if rules.get(rule, "block") == "off":
            continue
        frag = text[start:end]
        if any(a.search(frag) for a in allows):
            continue
        kept.append((start, end, rule))

    kept.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    merged = []
    last_end = -1
    for start, end, rule in kept:
        if start < last_end:
            continue
        merged.append((start, end, rule))
        last_end = end
    return merged


def scan(text, cfg):
    return apply_policy(text, detect(text), cfg)


# ------------------------------------------------------------------ output

def hint(s):
    s = s.replace("\n", " ").strip()
    if len(s) <= 3:
        return s[0] + "*" * (len(s) - 1)
    keep = 2 if len(s) < 12 else 3
    return s[:keep] + "*" * min(len(s) - keep * 2, 8) + s[-keep:]


def mask(text, findings):
    out = []
    pos = 0
    for start, end, rule in findings:
        out.append(text[pos:start])
        out.append("[{}を削除]".format(label(rule)) if lang() == "ja"
                   else "[{} removed]".format(label(rule)))
        pos = end
    out.append(text[pos:])
    return "".join(out)


def save_original(text, cfg):
    if not cfg.get("save_blocked_prompt", True):
        return None
    try:
        if not os.path.isdir(STORE_DIR):
            os.makedirs(STORE_DIR, 0o700)
        cutoff = time.time() - float(cfg.get("retention_days", 7)) * 86400
        for name in os.listdir(STORE_DIR):
            p = os.path.join(STORE_DIR, name)
            if os.path.isfile(p) and os.path.getmtime(p) < cutoff:
                os.remove(p)
        path = os.path.join(STORE_DIR, time.strftime("%Y%m%d-%H%M%S") + ".txt")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        return path
    except (IOError, OSError):
        return None


def clipboard_command():
    system = platform.system()
    if system == "Darwin":
        return ["pbcopy"]
    if system == "Windows":
        return ["clip"]
    for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]):
        if _which(cmd[0]):
            return cmd
    return None


def _which(name):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def to_clipboard(text, cfg):
    if not cfg.get("copy_masked_to_clipboard", True):
        return False
    cmd = clipboard_command()
    if not cmd:
        return False
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        p.communicate(text.encode("utf-8"))
        return p.returncode == 0
    except (IOError, OSError):
        return False


def block_message(text, blocking, findings, cfg):
    counts, samples = {}, {}
    for start, end, rule in blocking:
        counts[rule] = counts.get(rule, 0) + 1
        samples.setdefault(rule, hint(text[start:end]))

    ja = lang() == "ja"
    lines = ["🛑 個人情報の可能性があるため、Claude への送信を止めました（PII Guard）" if ja
             else "🛑 Blocked before sending to Claude: possible sensitive data (PII Guard)", ""]
    for rule in sorted(counts, key=lambda r: -counts[r]):
        lines.append("  ・{}: {}{}  {}: {}".format(
            label(rule), counts[rule], "件" if ja else "", "例" if ja else "e.g.", samples[rule]))
    lines.append("")

    if to_clipboard(mask(text, findings), cfg):
        lines.append("マスク済みの本文をクリップボードにコピーしました（貼り直せます）" if ja
                     else "A masked copy is on your clipboard - paste it back and resend.")
    path = save_original(text, cfg)
    if path:
        lines.append(("元の本文の退避先: " if ja else "Original saved to: ") + path.replace(HOME, "~"))
    marker = cfg.get("bypass_marker", "#pii-ok")
    if marker:
        lines.append(("意図的に送る場合は、本文のどこかに {} を書いて再送してください" if ja
                      else "To send anyway, include {} anywhere in the prompt.").format(marker))
    return "\n".join(lines)


def warn_message(warning):
    names = sorted(set(label(r) for _, _, r in warning))
    if lang() == "ja":
        return ("[PII Guard] ユーザーのプロンプトに個人情報の可能性がある記述を検出しました: "
                + "、".join(names) + "。作業を続ける前に、送って問題ないか一言確認してください。")
    return ("[PII Guard] The user's prompt may contain sensitive data: "
            + ", ".join(names) + ". Check with them before continuing.")


# -------------------------------------------------------------------- main

def run_hook():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except ValueError:
        payload = {}
    text = payload.get("prompt_text") or payload.get("prompt") or ""
    if not text.strip():
        return 0

    cfg = load_config()
    if not cfg.get("enabled", True):
        return 0
    marker = cfg.get("bypass_marker", "#pii-ok")
    if marker and marker in text:
        return 0

    findings = scan(text, cfg)
    if not findings:
        return 0

    rules = cfg.get("rules", {})
    blocking = [f for f in findings if rules.get(f[2], "block") == "block"]
    warning = [f for f in findings if rules.get(f[2], "block") == "warn"]

    if not blocking:
        note = warn_message(warning)
        print(json.dumps({"systemMessage": note,
                          "hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                                 "additionalContext": note}},
                         ensure_ascii=False))
        return 0

    message = block_message(text, blocking, findings, cfg)
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                             "blockReason": message}},
                     ensure_ascii=False))
    sys.stderr.write(message + "\n")
    return 2


# Synthetic credentials used by --selftest. They are assembled at runtime so
# that this repository never contains a literal secret-shaped string: storing
# one would trip GitHub push protection and every credential scanner in CI.
SELFTEST_FIXTURES = {
    "slack": "xox" + "b-123456789012-abcdefghijklmnop",
    "github": "gh" + "p_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    "anthropic": "sk-" + "ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "aws": "AK" + "IAIOSFODNN7EXAMPLE",
    "jwt": ("eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            + "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0."
            + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
}


def expand_fixtures(text):
    for key, value in SELFTEST_FIXTURES.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def run_selftest():
    path = os.path.join(PLUGIN_ROOT, "tests", "cases.json")
    with open(path, "r", encoding="utf-8") as f:
        cases = json.load(f)
    cfg = load_config()
    failures = 0
    for case in cases:
        findings = scan(expand_fixtures(case["text"]), cfg)
        rules = sorted(set(r for _, _, r in findings))
        expected = sorted(case["expect"])
        ok = rules == expected
        if not ok:
            failures += 1
        print("{}  {:<22} expected={:<28} got={}".format(
            "PASS" if ok else "FAIL", case["name"],
            ",".join(expected) or "(none)", ",".join(rules) or "(none)"))
    total = len(cases)
    print("\n{}/{} passed".format(total - failures, total))
    return 1 if failures else 0


def main(argv):
    if "--version" in argv:
        print("pii-guard " + VERSION)
        return 0
    if "--selftest" in argv:
        return run_selftest()
    if "--scan" in argv:
        text = argv[argv.index("--scan") + 1]
        cfg = load_config()
        findings = scan(text, cfg)
        for start, end, rule in findings:
            print("{:<14} {}".format(rule, hint(text[start:end])))
        print("---\n" + mask(text, findings))
        return 2 if findings else 0
    return run_hook()


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:  # never break the user's workflow (fail-open)
        sys.stderr.write("PII Guard internal error: {}\n".format(exc))
        sys.exit(1)
