"""
cloudaudit.intelligence.local_ai — Local Intelligence Engine (v1.3.0)

Everything in this module runs offline: no API key, no network call, no data
leaving the machine. It is what powers CloudAudit when no AI provider is
configured, and it also runs alongside a configured provider so that a bad
key, an exhausted quota or a network outage never degrades the audit.

Algorithms implemented here:
  1. TokenClassifier      — statistical secret-vs-noise classifier (normalised
                            entropy, English-bigram language model, character
                            class transitions, known benign formats)
  2. Semantic assignments — key/value extraction across env/YAML/JSON/INI/XML/
                            code with sensitive-key semantics and placeholder
                            awareness (finds secrets no regex rule knows about)
  3. ConfigAuditor        — security-misconfiguration rules for IaC, container,
                            web-server, database and application config
  4. JWT inspection       — decodes header/payload (never verifies or uses the
                            token) to flag unsigned / non-expiring / expired
  5. Calibration          — context-aware confidence + severity adjustment
  6. Aggregation          — collapses high-volume noise into single findings
  7. Correlation          — compound-exposure detection across findings
  8. File risk ranking    — which files drive the risk
  9. Executive summary    — data-driven narrative, remediation plan and
                            compliance impact, generated locally

All output is defensive: it describes exposure and remediation only.
"""

from __future__ import annotations

import base64
import json
import math
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from cloudaudit.core.models import FileType, Finding, FindingCategory, Severity
from cloudaudit.utils.helpers import calculate_entropy, redact, secret_hash, url_filename

ENGINE_NAME    = "local-intelligence"
ENGINE_VERSION = "2.0"

# Content beyond this size is analysed by the regex scanner only — the
# semantic passes are line-oriented and gain nothing from huge blobs.
MAX_SEMANTIC_BYTES = 2 * 1024 * 1024
MAX_SEMANTIC_FINDINGS_PER_FILE = 25


# ══════════════════════════════════════════════════════════════════════════════
# 1. Placeholder / benign-value recognition
# ══════════════════════════════════════════════════════════════════════════════

_PLACEHOLDER_WORD_LIST = (
    "your my the some a an insert enter put add replace change example sample dummy fake "
    "test testing demo placeholder redacted removed hidden masked secret password passwd "
    "token apikey key value string none null nil undefined true false todo tbd fixme "
    "changeme changeit default empty foo bar baz xxx here own real actual api access "
    "private auth client pass id goes this me it name user username not set unset "
    "required optional go"
).split()
# Longest alternative first + possessive quantifiers: the match is linear-time
# (no catastrophic backtracking on long digit or repeated-word inputs).
_PLACEHOLDER_WORDS = "|".join(sorted(set(_PLACEHOLDER_WORD_LIST), key=len, reverse=True))
_PLACEHOLDER_RE = re.compile(
    rf"^(?:{_PLACEHOLDER_WORDS})(?:[\W_]*+(?:{_PLACEHOLDER_WORDS}|\d{{1,4}}+(?!\d)))*+[\W_]*+$",
    re.IGNORECASE,
)
_FILLER_RE = re.compile(
    r"^(?:x{4,}|\*{3,}|\.{3,}|-{3,}|_{3,}|#{3,}|0{6,}|1234567890?|123456(?:78)?|"
    r"abc(?:d(?:e(?:f\w*)?)?)?(?:123\w*)?|qwerty\w*|asdf\w*|password\d*|letmein\d*)$",
    re.IGNORECASE,
)
_TEMPLATE_RE = re.compile(
    r"""(?ix)
      ^<[^>]*>$ | ^\[[^\]]*\]$ | \{\{.*\}\} | \$\{[^}]*\} | ^\$[A-Za-z_]\w*$
    | ^%[A-Za-z_]\w*%$ | \$\([^)]*\) | \#\{[^}]*\} | ^@[A-Za-z_][\w.]*@$ | ^\{[A-Za-z_]\w*\}$
    | ^(?:os\.environ|process\.env|env\[|system\.getenv|getenv\(|env\(|secrets\.|vars\.|var\.
        |local\.|data\.|module\.|aws_|ref:|!ref|!getatt|!sub|fn::|vault:|ssm:|arn:aws|file:
        |op://|sm://|projects/|secretsmanager|keyvault|sops:|enc\[)
    """
)
_PLACEHOLDER_SUBSTRINGS = (
    "example", "placeholder", "changeme", "change_me", "dummy", "redacted",
    "your_", "your-", "<your", "xxxxx", "*****",
)
_BENIGN_LITERALS = frozenset({
    "true", "false", "yes", "no", "on", "off", "none", "null", "nil", "undefined",
    "required", "optional", "enabled", "disabled", "string", "str", "int", "integer",
    "bool", "boolean", "text", "varchar", "default", "auto", "disable", "enable",
    "prompt", "ask", "env", "file", "plain", "basic", "bearer", "oauth", "oauth2",
    "token", "password", "secret", "key", "apikey", "jwt", "saml", "ldap", "local",
})


def looks_like_placeholder(value: str) -> bool:
    """True when ``value`` is obviously documentation / template filler, not a secret."""
    v = (value or "").strip().strip("\"'`")
    if not v:
        return True
    low = v.lower()
    if low in _BENIGN_LITERALS:
        return True
    if _FILLER_RE.match(v) or _PLACEHOLDER_RE.match(v) or _TEMPLATE_RE.search(v):
        return True
    if any(s in low for s in _PLACEHOLDER_SUBSTRINGS):
        return True
    if len(v) >= 4 and len(set(low)) <= 2:
        return True
    return False


# Benign value shapes. ``wordy`` formats only count as benign when the token
# also reads like language, because random base64 can accidentally look like a
# path ("a/b/c") or a dotted name ("x.y.z").
_BENIGN_FORMATS: List[Tuple[str, "re.Pattern[str]", bool]] = [
    ("uuid",      re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"), False),
    ("integrity", re.compile(r"^(?:sha(?:1|256|384|512)|md5)[-:=]", re.I), False),
    ("number",    re.compile(r"^[+-]?[\d.,_]+(?:e[+-]?\d+)?[a-zA-Z%]{0,3}$"), False),
    ("version",   re.compile(r"^[v^~<>=]*\d+(?:\.\d+){1,3}(?:[-+.][\w.]+)?$"), False),
    ("datetime",  re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?$"), False),
    ("url",       re.compile(r"^(?:[a-z][a-z0-9+.\-]*:)?//[^\s:@/]+(?::\d+)?(?:[/?#]\S*)?$", re.I), False),
    ("email",     re.compile(r"^[\w.%+\-]+@[\w.\-]+\.[A-Za-z]{2,}$"), False),
    ("data_uri",  re.compile(r"^data:[\w/+.\-]+[;,]", re.I), False),
    ("color",     re.compile(r"^#[0-9a-fA-F]{3,8}$"), False),
    ("ip",        re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/\d+)?$"), False),
    ("arn",       re.compile(r"^arn:[\w\-]+:", re.I), False),
    ("constant",  re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$"), False),
    ("mime",      re.compile(r"^[a-z]+/[\w.+\-]+$"), True),
    ("path",      re.compile(r"^(?:[A-Za-z]:)?[./\\~]*(?:[\w.\-@]+[/\\])+[\w.\-@]*$"), True),
    ("dotted",    re.compile(r"^[A-Za-z_][\w\-]*(?:\.[A-Za-z_][\w\-]*){1,}$"), True),
    ("identifier", re.compile(r"^[A-Za-z_][A-Za-z_\-]*$"), True),
]
_HEX_HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{56}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})$")


# ══════════════════════════════════════════════════════════════════════════════
# 2. Token classifier
# ══════════════════════════════════════════════════════════════════════════════

# The ~230 most frequent English letter bigrams. Natural-language identifiers
# hit this table ~85% of the time; uniformly random letters hit it ~34%.
_COMMON_BIGRAMS = frozenset("""
th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me
de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot
il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai
sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag
if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr cl du ga qu ue ff ba
ey ls va um pp ua up lu go ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki
rk ys ob mm fu ph og ms ye ud mb ip ub oi rl gu dr hr cc oa dd nf nk ok nn ft sk sy lf ps nv sq eq
ws ks aw ze iz az gs ja jo je ju ya xt xp
""".split())

_ALPHA_RUN_RE = re.compile(r"[A-Za-z]{3,}")


def wordiness(token: str) -> float:
    """
    0..1 estimate of how much ``token`` reads like natural-language words.

    Product of (a) the share of the token covered by alphabetic runs and
    (b) the share of bigrams in those runs that are common English bigrams,
    penalised by erratic case flipping (which random base62 has and
    camelCase identifiers do not).
    """
    if not token:
        return 0.0
    runs = _ALPHA_RUN_RE.findall(token)
    if not runs:
        return 0.0
    covered = sum(len(r) for r in runs)
    hits = total = flips = pairs = 0
    for run in runs:
        low = run.lower()
        for i in range(len(low) - 1):
            total += 1
            if low[i:i + 2] in _COMMON_BIGRAMS:
                hits += 1
            pairs += 1
            if run[i].isupper() != run[i + 1].isupper():
                flips += 1
    if total == 0:
        return 0.0
    bigram_rate = hits / total
    flip_rate   = flips / pairs if pairs else 0.0
    # Rescale so random text (~0.34) maps near 0 and English (~0.85) near 1.
    lang = max(0.0, min(1.0, (bigram_rate - 0.38) / 0.42))
    case_penalty = max(0.0, 1.0 - max(0.0, flip_rate - 0.22) * 2.5)
    return round(lang * (covered / len(token)) * case_penalty, 3)


def _char_class(c: str) -> int:
    if c.islower():
        return 0
    if c.isupper():
        return 1
    if c.isdigit():
        return 2
    return 3


def randomness_score(token: str) -> float:
    """0..1 — how much ``token`` looks machine-generated rather than authored."""
    n = len(token)
    if n < 4:
        return 0.0
    ent = calculate_entropy(token)
    if re.fullmatch(r"[0-9a-fA-F]+", token):
        alphabet = 16
    elif re.fullmatch(r"[A-Za-z0-9+/=_\-]+", token):
        alphabet = 64
    else:
        alphabet = 94
    max_ent = math.log2(min(n, alphabet)) or 1.0
    norm = min(ent / max_ent, 1.0)
    norm_adj = max(0.0, min(1.0, (norm - 0.60) / 0.35))

    transitions = sum(
        1 for i in range(n - 1) if _char_class(token[i]) != _char_class(token[i + 1])
    ) / (n - 1)
    trans_adj = min(transitions / 0.45, 1.0)

    score = 0.40 * norm_adj + 0.35 * (1.0 - wordiness(token)) + 0.25 * trans_adj
    return round(max(0.0, min(1.0, score)), 3)


@dataclass
class TokenVerdict:
    label:   str            # "secret" | "uncertain" | "benign" | "placeholder"
    score:   float          # 0..1 likelihood of being a real secret
    reasons: List[str] = field(default_factory=list)

    @property
    def is_secret(self) -> bool:
        return self.label == "secret"


class TokenClassifier:
    """Decides whether an opaque string is a credible secret, noise, or filler."""

    SECRET_THRESHOLD    = 0.62
    UNCERTAIN_THRESHOLD = 0.50

    def classify(self, token: str, key_hint: str = "") -> TokenVerdict:
        tok = (token or "").strip().strip("\"'`")
        if not tok:
            return TokenVerdict("benign", 0.0, ["empty"])
        if looks_like_placeholder(tok):
            return TokenVerdict("placeholder", 0.02, ["placeholder/template value"])

        strength = key_sensitivity(key_hint) if key_hint else 0
        if " " in tok and strength < 2:
            return TokenVerdict("benign", 0.05, ["contains whitespace — prose, not a token"])

        words = wordiness(tok)
        if _HEX_HASH_RE.match(tok) and strength == 0:
            return TokenVerdict("benign", 0.15, ["hex digest shape with no secret-bearing key name"])
        for name, rx, needs_words in _BENIGN_FORMATS:
            if rx.match(tok) and (not needs_words or words >= 0.45):
                return TokenVerdict("benign", 0.05, [f"benign format: {name}"])

        rand = randomness_score(tok)
        score = rand
        reasons = [f"randomness={rand:.2f}", f"wordiness={words:.2f}"]

        n = len(tok)
        if n < 12:
            score -= 0.25
            reasons.append("short")
        elif n >= 32:
            score += 0.05
        if strength == 2:
            score += 0.22
            reasons.append("strong secret-bearing key name")
        elif strength == 1:
            score += 0.10
            reasons.append("weak secret-bearing key name")
        elif strength < 0:
            score -= 0.30
            reasons.append("key name indicates a reference/metadata, not a value")

        score = round(max(0.0, min(1.0, score)), 3)
        if score >= self.SECRET_THRESHOLD:
            label = "secret"
        elif score >= self.UNCERTAIN_THRESHOLD:
            label = "uncertain"
        else:
            label = "benign"
        return TokenVerdict(label, score, reasons)


# ══════════════════════════════════════════════════════════════════════════════
# 3. Key-name semantics
# ══════════════════════════════════════════════════════════════════════════════

_STRONG_KEY_RE = re.compile(
    r"(?:^|_)(?:pass(?:word|wd|phrase)?|pwd|secret|secrets|token|api_?key|apikey|auth_?key|"
    r"auth_?token|credentials?|private_?key|priv_?key|access_?key|secret_?key|client_?secret|"
    r"app_?secret|signing_?key|sign_?key|encryption_?key|enc_?key|master_?key|session_?key|"
    r"license_?key|consumer_?secret|shared_?key|account_?key|storage_?key|sas_?token)(?:_|$|\d)"
)
_WEAK_KEY_RE = re.compile(r"(?:^|_)(?:key|auth|salt|jwt|oauth|bearer|sas|cred|otp|pin|seed|nonce)(?:_|$|\d)")
_NEGATIVE_KEY_RE = re.compile(
    r"""(?x)
      public | (?:^|_)pub(?:_|$)
    | (?:^|_)(?:primary|foreign|partition|sort|cache|hash|row|map|object|bucket|s3|file|dict|json
              |index|idempotency|group|shard|routing|lookup|sso|kms|ssh_host|host|sort)_keys?(?:_|$)
    | key_(?:id|ids|name|names|path|file|size|length|len|type|vault|ring|spec|usage|prefix|alias
            |code|down|up|press|event|word|words|frame|board|bindings?|map|pair_name|arn|version
            |algorithm|format|exchange|rotation|store|label)
    | token_(?:type|url|uri|endpoint|expir\w*|ttl|limit|count|name|file|path|length|len|budget
              |usage|lifetime|header|prefix|kind|auth_method)
    | (?:max|min|num|total|input|output|prompt|completion)_tokens? | tokeniz
    | pass(?:word)?_(?:policy|length|len|min\w*|max\w*|field|hint|reset\w*|expir\w*|file|path
              |prompt|url|regex|pattern|strength|age|history|required|enabled|change\w*
              |confirm\w*|label|placeholder|input|type|attempts|complexity|hash\w*|encoder|salt)
    | auth_(?:type|url|uri|method|mode|provider|endpoint|domain|enabled|header|scheme|plugin
             |source|db|database|mechanism|required|strategy|server|host|port|backend|user
             |username|name)
    | (?:^|_)authors? | authoriz(?:ed|er|ation_(?:url|uri|endpoint))
    | secret_(?:name|names|id|arn|path|ref|manager|version|store|type|key_ref|mount|engine|backend)
    | (?:^|_)(?:file|filename|path|dir|url|uri|endpoint|enabled|timeout|ttl|expiry|expires?
               |expiration|name|id|type|arn|ref|label|title|description|desc|comment|hint|help
               |text|message|msg|error|regex|pattern|format|algorithm|algo|length|len|size|count
               |required|field|column|header|param|var|env|version|status|mode|class|role|policy
               |location|region|hash|hashed|digest|fingerprint|checksum|encrypted|cipher|prefix
               |suffix|placeholder|example|sample|template|rotation|manager|provider|store)$
    | passthrough | passive | compass | bypass | keyword | keyboard | monkey | hotkey | turkey
    | keynote | keyframe | passenger | passport_(?:no|number)
    """
)


def normalise_key(key: str) -> str:
    """camelCase / kebab-case / dotted → snake_case for semantic matching."""
    k = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key or "")
    return re.sub(r"[\s.\-]+", "_", k).lower().strip("_")


def key_sensitivity(key: str) -> int:
    """2 = strong secret-bearing name, 1 = weak, 0 = neutral, -1 = reference/metadata."""
    k = normalise_key(key)
    if not k:
        return 0
    if _NEGATIVE_KEY_RE.search(k):
        return -1
    if _STRONG_KEY_RE.search(k):
        return 2
    if _WEAK_KEY_RE.search(k):
        return 1
    return 0


# ══════════════════════════════════════════════════════════════════════════════
# 4. Assignment extraction
# ══════════════════════════════════════════════════════════════════════════════

_ASSIGN_RE = re.compile(
    r"""
    (?P<q>["']?)(?P<key>[A-Za-z_][\w.\-]{1,79})(?P=q)
    [ \t]*(?:=>|:=|=|:)[ \t]*
    (?:"(?P<dq>[^"\n]{1,512})"|'(?P<sq>[^'\n]{1,512})'|(?P<bare>[^\s,;"'<>(){}\[\]]{1,512}))
    """,
    re.VERBOSE,
)
_XML_TAG_RE  = re.compile(r"<(?P<key>[A-Za-z_][\w.\-]{1,79})>(?P<val>[^<>\n]{1,512})</(?P=key)>")
_XML_KV_RE   = re.compile(
    r"""(?:key|name)\s*=\s*["'](?P<key>[\w.\-:]{2,80})["']\s+(?:value|connectionString)\s*=\s*["'](?P<val>[^"'\n]{1,512})["']""",
    re.IGNORECASE,
)


@dataclass
class Assignment:
    key:    str
    value:  str
    line:   int
    quoted: bool


def extract_assignments(content: str) -> List[Assignment]:
    """Pull ``key = value`` style pairs out of arbitrary config / code / markup."""
    out: List[Assignment] = []
    line_starts = [0]
    for m in re.finditer(r"\n", content):
        line_starts.append(m.end())

    def line_of(pos: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    for m in _ASSIGN_RE.finditer(content):
        val = m.group("dq") or m.group("sq")
        quoted = val is not None
        if val is None:
            val = m.group("bare") or ""
        out.append(Assignment(m.group("key"), val, line_of(m.start()), quoted))
    for rx in (_XML_TAG_RE, _XML_KV_RE):
        for m in rx.finditer(content):
            out.append(Assignment(m.group("key"), m.group("val").strip(), line_of(m.start()), True))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# 5. Config / IaC misconfiguration auditor
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ConfigRule:
    name:           str
    pattern:        str
    severity:       Severity
    description:    str
    recommendation: str
    compliance:     Tuple[str, ...] = ()
    category:       FindingCategory = FindingCategory.COMPLIANCE
    sensitive:      bool = False            # matched text may contain a secret → redact
    path_hint:      Optional[str] = None    # only apply when the path matches
    file_types:     Tuple[FileType, ...] = ()


_CONFIG_RULES: Tuple[ConfigRule, ...] = (
    ConfigRule(
        "DEBUG_MODE_ENABLED",
        r"^[ \t]*(?:export[ \t]+)?[\"']?(?:DEBUG|APP_DEBUG|FLASK_DEBUG|DJANGO_DEBUG|WP_DEBUG)[\"']?[ \t]*[=:,][ \t]*[\"']?(?:true|1|on|yes)\b",
        Severity.MEDIUM,
        "Debug mode is enabled in a publicly exposed configuration file",
        "Disable debug mode outside development. Debug pages disclose stack traces, settings and environment values.",
        ("NIST SI-11", "CIS 2.1.5"),
    ),
    ConfigRule(
        "TLS_VERIFICATION_DISABLED",
        r"\bverify\s*=\s*False\b|ssl_?verify\w*\s*[=:]\s*[\"']?(?:false|0|no|off)\b|rejectUnauthorized[\"']?\s*:\s*false"
        r"|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)"
        r"|sslmode\s*=\s*disable|verify_ssl\s*[=:]\s*[\"']?false|check_hostname\s*=\s*False|insecure_skip_tls_verify\s*[=:]\s*true",
        Severity.MEDIUM,
        "TLS certificate verification is disabled",
        "Re-enable certificate verification. Disabling it allows trivial interception of credentials in transit.",
        ("NIST SC-8", "SOC2 CC6.7", "PCI-DSS Req 4.1"),
    ),
    ConfigRule(
        "OPEN_NETWORK_INGRESS",
        r"cidr_blocks?\s*=\s*\[?\s*\"0\.0\.0\.0/0\"|[\"']?CidrIp[\"']?\s*:\s*[\"']?0\.0\.0\.0/0"
        r"|source_ranges\s*=\s*\[\s*\"0\.0\.0\.0/0\"|source_address_prefix\s*=\s*\"(?:\*|0\.0\.0\.0/0|Internet)\""
        r"|ipv6_cidr_blocks\s*=\s*\[\s*\"::/0\"",
        Severity.HIGH,
        "Network rule allows ingress from any address (0.0.0.0/0)",
        "Restrict security-group / firewall rules to known CIDR ranges and required ports only.",
        ("CIS 5.2", "NIST SC-7", "PCI-DSS Req 1.3"),
    ),
    ConfigRule(
        "IAM_WILDCARD_ACTION",
        r"[\"']Action[\"']\s*:\s*(?:\[\s*)?[\"']\*[\"']|\bactions\s*=\s*\[\s*\"\*\"\s*\]|[\"']Action[\"']\s*:\s*(?:\[\s*)?[\"'][a-z0-9\-]+:\*[\"']",
        Severity.HIGH,
        "IAM policy grants wildcard actions",
        "Replace wildcard actions with the specific actions required (least privilege). Review with IAM Access Analyzer.",
        ("CIS 1.16", "NIST AC-6", "SOC2 CC6.3"),
    ),
    ConfigRule(
        "IAM_PUBLIC_PRINCIPAL",
        r"[\"']Principal[\"']\s*:\s*(?:[\"']\*[\"']|\{\s*[\"']AWS[\"']\s*:\s*[\"']\*[\"']\s*\})|\ballUsers\b|\ballAuthenticatedUsers\b",
        Severity.HIGH,
        "Resource policy grants access to any principal (public)",
        "Scope the policy principal to specific accounts/roles and add conditions. Remove allUsers / allAuthenticatedUsers bindings.",
        ("CIS 2.1", "NIST AC-3", "SOC2 CC6.1"),
        FindingCategory.PUBLIC_ACCESS,
    ),
    ConfigRule(
        "PUBLIC_STORAGE_ACL",
        r"\bacl\s*=\s*\"public-read(?:-write)?\"|[\"']ACL[\"']\s*:\s*[\"']public-read|x-amz-acl\s*[:=]\s*public-read"
        r"|block_public_(?:acls|policy)\s*=\s*false|restrict_public_buckets\s*=\s*false|ignore_public_acls\s*=\s*false"
        r"|allow_(?:nested_items_to_be|blob)_public(?:_access)?\s*=\s*true|container_access_type\s*=\s*\"(?:blob|container)\"",
        Severity.HIGH,
        "Storage is configured for public access in infrastructure code",
        "Enable Block Public Access / private container access and serve public assets through a CDN with origin access control.",
        ("CIS 2.1", "NIST SC-7", "SOC2 CC6.1"),
        FindingCategory.PUBLIC_ACCESS,
    ),
    ConfigRule(
        "ENCRYPTION_DISABLED",
        r"\b(?:storage_)?encrypted\s*=\s*false|[\"']?(?:Storage)?Encrypted[\"']?\s*:\s*false|enable_https_traffic_only\s*=\s*false"
        r"|\bencrypt(?:ion)?(?:_at_rest)?(?:_enabled)?\s*[=:]\s*[\"']?(?:false|off|none|disabled)\b",
        Severity.MEDIUM,
        "Encryption at rest / in transit is explicitly disabled",
        "Enable encryption at rest with a managed KMS key and enforce HTTPS-only access.",
        ("CIS 2.2", "NIST SC-28", "PCI-DSS Req 3.4"),
    ),
    ConfigRule(
        "PUBLIC_DATABASE_ENDPOINT",
        r"publicly_accessible\s*=\s*true|[\"']?PubliclyAccessible[\"']?\s*:\s*true|^\s*bind[-_]?(?:address|ip)?\s*[=:\s]\s*0\.0\.0\.0\b"
        r"|^\s*protected-mode\s+no\b|^\s*listen_addresses\s*=\s*'\*'|^\s*host\s+all\s+all\s+0\.0\.0\.0/0\s+(?:trust|password|md5)",
        Severity.HIGH,
        "Database / cache service is configured to accept connections from the internet",
        "Bind data stores to private interfaces, place them in private subnets and require authenticated, encrypted connections.",
        ("CIS 2.3", "NIST SC-7", "PCI-DSS Req 1.3"),
    ),
    ConfigRule(
        "PRIVILEGED_CONTAINER",
        r"^\s*privileged:\s*true\b|allowPrivilegeEscalation:\s*true|hostNetwork:\s*true|hostPID:\s*true|runAsUser:\s*0\b"
        r"|--privileged\b|/var/run/docker\.sock",
        Severity.HIGH,
        "Container workload runs privileged or with host-level access",
        "Drop privileged mode, run as a non-root user, and never mount the Docker socket into application containers.",
        ("CIS Docker 5.4", "NIST CM-7", "NIST AC-6"),
    ),
    ConfigRule(
        "PERMISSIVE_CORS",
        r"Access-Control-Allow-Origin[\"']?\s*[:=,]\s*[\"']?\*|allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]"
        r"|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|<AllowedOrigin>\s*\*\s*</AllowedOrigin>|[\"']AllowedOrigins[\"']\s*:\s*\[\s*[\"']\*[\"']",
        Severity.MEDIUM,
        "Cross-origin policy allows any origin",
        "Restrict allowed origins to the specific application domains that need access.",
        ("NIST AC-4", "SOC2 CC6.6"),
    ),
    ConfigRule(
        "WEAK_SSH_DAEMON_CONFIG",
        r"^[ \t]*(?:PermitRootLogin[ \t]+yes|PermitEmptyPasswords[ \t]+yes|PasswordAuthentication[ \t]+yes)\b",
        Severity.MEDIUM,
        "SSH daemon allows root or password-based login",
        "Set PermitRootLogin no and PasswordAuthentication no; use key-based access through a bastion.",
        ("CIS 5.2.8", "NIST AC-17"),
    ),
    ConfigRule(
        "AUTHENTICATION_DISABLED",
        r"\b(?:auth(?:entication)?|security|xpack\.security|rbac)[._\-]?enabled[\"']?\s*[=:]\s*[\"']?(?:false|0|no|off)\b"
        r"|^\s*requirepass\s+[\"']{2}|--noauth\b|\banonymous[_\-]?(?:access|auth|enabled?|login)[\"']?\s*[=:]\s*[\"']?(?:true|yes|1|on)\b"
        r"|skip-grant-tables|^\s*auth\s*=\s*(?:none|false)\b|DISABLE_AUTH\w*\s*=\s*[\"']?(?:true|1)",
        Severity.HIGH,
        "Authentication is disabled or anonymous access is enabled for a service",
        "Enable authentication and role-based access control. Never expose unauthenticated admin or data APIs.",
        ("CIS 2.1.5", "NIST IA-2", "SOC2 CC6.1"),
    ),
    ConfigRule(
        "WEAK_CRYPTOGRAPHY",
        r"\b(?:algorithm|cipher\w*|hash(?:ing)?\w*|digest\w*|ssl_?protocols?|SSLProtocol|tls_?(?:min_?)?version|min(?:imum)?_(?:tls|protocol)_version)"
        r"[\"']?\s*[=:(\s]\s*[\"']?[^\"'\n]{0,40}?\b(?:md5|sha-?1|des|rc4|3des|sslv2|sslv3|tlsv?1(?:[._][01])?)(?![.\w])",
        Severity.MEDIUM,
        "Deprecated cryptographic algorithm or protocol version is configured",
        "Use TLS 1.2+ and modern primitives (SHA-256+, AES-GCM, Argon2/bcrypt for passwords).",
        ("NIST SC-13", "PCI-DSS Req 4.1"),
    ),
    ConfigRule(
        "PASSWORD_HASH_EXPOSED",
        r"\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}|\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}|\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}"
        r"|\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}|\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}"
        r"|\$argon2(?:id|i|d)\$v=\d+\$[^\s\"']{20,}|pbkdf2_sha\d+\$\d+\$[^\s\"']{20,}|\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}",
        Severity.HIGH,
        "Password hashes are exposed",
        "Treat every exposed hash as compromised: force password resets, and remove the file. Offline cracking of exposed hashes is practical.",
        ("NIST IA-5", "SOC2 CC6.1", "PCI-DSS Req 8.2"),
        FindingCategory.CREDENTIAL_FILE,
        sensitive=True,
    ),
    ConfigRule(
        "NETRC_CREDENTIALS",
        r"\bmachine\s+\S+\s+login\s+\S+\s+password\s+\S+",
        Severity.CRITICAL,
        "Plain-text machine credentials (.netrc format)",
        "Rotate the credential and remove the file. Use a credential helper or short-lived tokens instead of .netrc.",
        ("NIST IA-5", "CIS 2.1.5"),
        FindingCategory.CREDENTIAL_FILE,
        sensitive=True,
    ),
    ConfigRule(
        "PACKAGE_REGISTRY_AUTH_TOKEN",
        r"_authToken\s*=\s*(?!\$\{)[^\s$]{8,}|^\s*_auth\s*=\s*[A-Za-z0-9+/=]{8,}|^\s*password\s*=\s*[^\s$]{6,}",
        Severity.HIGH,
        "Package-registry authentication token stored in a client config file",
        "Revoke the registry token and use CI-injected, scoped, read-only tokens instead.",
        ("NIST IA-5", "SOC2 CC6.7"),
        FindingCategory.CREDENTIAL_FILE,
        sensitive=True,
        path_hint=r"(?:^|/)\.?(?:npmrc|pypirc|yarnrc(?:\.yml)?|gemrc)$",
    ),
    ConfigRule(
        "KUBERNETES_SECRET_MANIFEST",
        r"^kind:\s*Secret\b",
        Severity.HIGH,
        "Kubernetes Secret manifest is exposed (base64 is encoding, not encryption)",
        "Rotate every value in the manifest. Store secrets with Sealed Secrets, External Secrets or a KMS-backed provider.",
        ("CIS K8s 5.4.1", "NIST IA-5"),
        FindingCategory.CREDENTIAL_FILE,
    ),
    ConfigRule(
        "SECRET_BAKED_INTO_IMAGE",
        r"^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY)\w*(?:\s+|=)(?!\$)\S{6,}",
        Severity.HIGH,
        "Secret passed through a Dockerfile ENV/ARG instruction (persists in image layers)",
        "Use BuildKit secret mounts or runtime-injected secrets; rotate the value that was baked into image history.",
        ("CIS Docker 4.10", "NIST IA-5"),
        FindingCategory.CREDENTIAL_FILE,
        sensitive=True,
        path_hint=r"(?:^|/)(?:[\w.\-]*dockerfile[\w.\-]*|containerfile)$",
    ),
    ConfigRule(
        "DEFAULT_CREDENTIALS",
        r"[\"']?(?:user(?:name)?|login)[\"']?\s*[=:]\s*[\"']?(?:admin|root|administrator|postgres|sa|guest|test)[\"']?\s*[\n,;&]\s*"
        r"[\"']?pass(?:word|wd)?[\"']?\s*[=:]\s*[\"']?(?:admin|root|password|123456|postgres|guest|test|toor|changeme|default|1234|12345678)\b",
        Severity.HIGH,
        "Well-known default username/password pair is configured",
        "Replace default credentials with unique, generated ones stored in a secrets manager.",
        ("CIS 2.1.5", "NIST IA-5", "PCI-DSS Req 2.1"),
        FindingCategory.SECRET_EXPOSURE,
    ),
    ConfigRule(
        "USER_TABLE_DUMP",
        r"INSERT\s+INTO\s+[`\"'\[]?\w*(?:users?|accounts?|members?|customers?|admins?|logins?|credentials|employees?|patients?)\w*[`\"'\]]?",
        Severity.HIGH,
        "Database dump contains rows from a user/account table",
        "Remove the dump, assess the personal data it contains for breach-notification obligations, and reset exposed credentials.",
        ("SOC2 CC6.7", "GDPR Art. 32", "NIST SC-28"),
        FindingCategory.PII_EXPOSURE,
    ),
    ConfigRule(
        "DATABASE_DUMP_EXPOSED",
        r"^-- (?:MySQL dump|PostgreSQL database dump|MariaDB dump|Dump completed)|^-- Dumped (?:from|by)|^PRAGMA foreign_keys",
        Severity.MEDIUM,
        "Full database dump is stored in exposed storage",
        "Move database backups to private, encrypted storage with lifecycle expiry and access logging.",
        ("NIST CP-9", "SOC2 CC6.1", "CIS 2.1.5"),
    ),
    ConfigRule(
        "AUDIT_LOGGING_DISABLED",
        r"\b(?:enable_?logging|access_?logs?(?:_enabled)?|logging_?enabled|audit_?log(?:ging)?(?:_enabled)?|enable_log_file_validation|is_multi_region_trail)"
        r"[\"']?\s*[=:]\s*[\"']?(?:false|0|off|no|none|disabled)\b",
        Severity.LOW,
        "Access / audit logging is explicitly disabled",
        "Enable access logging and log-file validation so that exposure windows can be investigated.",
        ("CIS 2.4", "NIST AU-12", "SOC2 CC7.2"),
    ),
    ConfigRule(
        "MFA_DISABLED",
        r"\bmfa[_\-]?(?:delete|enabled|required)[\"']?\s*[=:]\s*[\"']?(?:false|disabled|off|0)\b|[\"']MFADelete[\"']\s*:\s*[\"']Disabled[\"']",
        Severity.MEDIUM,
        "Multi-factor protection is disabled",
        "Require MFA for privileged identities and enable MFA Delete on versioned buckets.",
        ("CIS 1.5", "NIST IA-2(1)"),
    ),
    ConfigRule(
        "WILDCARD_ALLOWED_HOSTS",
        r"ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']",
        Severity.MEDIUM,
        "Application accepts any Host header (ALLOWED_HOSTS = ['*'])",
        "List the exact production hostnames to prevent Host-header poisoning.",
        ("NIST SI-10",),
    ),
    ConfigRule(
        "INSTANCE_METADATA_V1_ALLOWED",
        r"http_tokens\s*=\s*\"optional\"|[\"']?HttpTokens[\"']?\s*:\s*[\"']?optional",
        Severity.MEDIUM,
        "Instance metadata service v1 is allowed (session tokens not required)",
        "Set http_tokens = \"required\" to enforce IMDSv2.",
        ("CIS 5.6", "NIST AC-3"),
    ),
    ConfigRule(
        "CLEARTEXT_PROTOCOL_ENDPOINT",
        r"\b(?:ftp|telnet|ldap|smtp|redis|amqp|mqtt)://[^\s\"'<>]{4,}",
        Severity.LOW,
        "Service endpoint uses a cleartext protocol",
        "Use the TLS variant of the protocol (ftps/sftp, ldaps, rediss, amqps, mqtts).",
        ("NIST SC-8", "PCI-DSS Req 4.1"),
        FindingCategory.INFRASTRUCTURE_INF,
    ),
    ConfigRule(
        "SHELL_HISTORY_SECRET",
        r"^(?:.*\s)?(?:mysql|psql|mongo(?:sh)?|redis-cli|sshpass|curl|wget|aws|az|gcloud|docker\s+login)\b[^\n]*"
        r"(?:\s-p\s?\S{4,}|--password[= ]\S{4,}|-u\s+\S+:\S{4,}|--token[= ]\S{8,}|PGPASSWORD=\S{4,})",
        Severity.HIGH,
        "Command line containing an inline credential (shell history / script)",
        "Rotate the credential. Pass secrets through environment files or prompts, never on the command line.",
        ("NIST IA-5", "CIS 2.1.5"),
        FindingCategory.SECRET_EXPOSURE,
        sensitive=True,
    ),
)


class ConfigAuditor:
    """Runs the misconfiguration rule set over one file's content."""

    def __init__(self) -> None:
        self._rules = [
            (r, re.compile(r.pattern, re.MULTILINE | re.IGNORECASE),
             re.compile(r.path_hint, re.IGNORECASE) if r.path_hint else None)
            for r in _CONFIG_RULES
        ]

    def audit(self, content: str, file_url: str, file_type: FileType) -> List[Finding]:
        path = file_url.lower()
        fname = url_filename(file_url)
        findings: List[Finding] = []
        for rule, rx, hint in self._rules:
            if hint is not None and not hint.search(path):
                continue
            if rule.name in ("USER_TABLE_DUMP", "DATABASE_DUMP_EXPOSED") and file_type != FileType.SQL \
                    and not path.endswith((".sql", ".dump", ".bak")):
                continue
            first = None
            count = 0
            for m in rx.finditer(content):
                count += 1
                if first is None:
                    first = m
                if count >= 2000:
                    break
            if first is None:
                continue
            raw = first.group(0).strip()
            shown = redact(raw, keep_chars=12) if rule.sensitive else (raw[:80] + ("…" if len(raw) > 80 else ""))
            desc = rule.description
            if count > 1:
                desc += f" ({count} occurrences in this file)"
            findings.append(Finding(
                file_url=file_url,
                file_name=fname,
                file_type=file_type,
                category=rule.category,
                rule_name=rule.name,
                description=desc,
                severity=rule.severity,
                match=shown,
                line_number=content.count("\n", 0, first.start()) + 1,
                recommendation=rule.recommendation,
                compliance_refs=list(rule.compliance),
                confidence=0.85 if rule.severity in (Severity.CRITICAL, Severity.HIGH) else 0.78,
                scanner="LocalIntelligence",
                occurrences=count,
            ))
        return findings


# ══════════════════════════════════════════════════════════════════════════════
# 6. JWT inspection (decode only — tokens are never verified, replayed or used)
# ══════════════════════════════════════════════════════════════════════════════

_JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,})\.(eyJ[A-Za-z0-9_\-]{8,})\.([A-Za-z0-9_\-]*)")


def _b64url_json(segment: str) -> Optional[dict]:
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        data = json.loads(raw.decode("utf-8", "replace"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def inspect_jwt(token: str, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Decode a JWT's header and claims. Returns None if it is not a real JWT."""
    m = _JWT_RE.search(token or "")
    if not m:
        return None
    header, payload = _b64url_json(m.group(1)), _b64url_json(m.group(2))
    if header is None or payload is None or not ("alg" in header or "typ" in header):
        return None
    now = time.time() if now is None else now
    exp = payload.get("exp")
    exp = float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None
    alg = str(header.get("alg", "")).lower()
    return {
        "alg":       alg,
        "unsigned":  alg in ("none", "") or not m.group(3),
        "exp":       exp,
        "expired":   exp is not None and exp < now,
        "no_expiry": exp is None,
        "issuer":    str(payload.get("iss", ""))[:80],
        "claims":    sorted(str(k) for k in payload.keys())[:20],
    }


# ══════════════════════════════════════════════════════════════════════════════
# 7. Path context
# ══════════════════════════════════════════════════════════════════════════════

_NON_PROD_PATH_RE = re.compile(
    r"(?:^|[/\\!])(?:tests?|__tests__|spec|specs|fixtures?|mocks?|__mocks__|examples?|samples?|demo|"
    r"docs?|documentation|testdata|test-data|stubs?)(?:[/\\]|$)"
    r"|\.(?:example|sample|template|dist|tmpl|tpl)(?:\.\w+)?$|(?:^|[/\\])(?:readme|changelog|contributing)[\w.\-]*$"
    r"|[._\-](?:test|spec|example|sample)\.\w+$|\.(?:md|rst|adoc)$",
    re.IGNORECASE,
)
_NOISE_FILE_RE = re.compile(
    r"(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.ya?ml|composer\.lock|"
    r"cargo\.lock|poetry\.lock|pipfile\.lock|gemfile\.lock|go\.sum|flake\.lock|"
    r"\.min\.(?:js|css)|\.bundle\.js|\.chunk\.js|\.map|\.svg|\.snap)$"
    r"|(?:^|[/\\])(?:node_modules|bower_components|vendor|site-packages|dist|\.yarn)[/\\]",
    re.IGNORECASE,
)

# Rules whose match is a strongly-typed provider token — context lowers their
# confidence less than it does for generic "looks like a secret" rules.
_SOFT_RULES = frozenset({
    "GENERIC_API_KEY", "HARDCODED_PASSWORD", "ENV_VARIABLE_SECRET", "HIGH_ENTROPY_STRING",
    "SEMANTIC_SECRET_ASSIGNMENT", "BASIC_AUTH_URL", "EMAIL_ADDRESS", "INTERNAL_IP",
})
_VOLUME_RULES = frozenset({"EMAIL_ADDRESS", "INTERNAL_IP", "HIGH_ENTROPY_STRING", "PHONE_NUMBER"})
_NON_CREDENTIAL_RULES = frozenset({
    "HIGH_ENTROPY_STRING", "EMAIL_ADDRESS", "INTERNAL_IP", "SSH_CONFIG", "CREDIT_CARD",
    "PHONE_NUMBER", "US_SSN", "IBAN",
})


def is_non_production_path(path: str) -> bool:
    return bool(_NON_PROD_PATH_RE.search(path or ""))


def is_noise_file(path: str) -> bool:
    """Lockfiles, minified bundles and vendored trees: high entropy by design."""
    return bool(_NOISE_FILE_RE.search(path or ""))


def is_credential_finding(f: Finding) -> bool:
    """True for findings that represent an actual credential / secret value."""
    if f.category not in (FindingCategory.SECRET_EXPOSURE, FindingCategory.CREDENTIAL_FILE):
        return False
    base = f.rule_name.split(":")[0]
    if base in _NON_CREDENTIAL_RULES or base.startswith(("SENSITIVE_FILE", "COMPOUND_", "SYSTEMIC_",
                                                         "DUPLICATE_SECRET", "CREDENTIAL_REUSE")):
        return False
    return True


_SEV_DOWN = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH:     Severity.MEDIUM,
    Severity.MEDIUM:   Severity.LOW,
    Severity.LOW:      Severity.LOW,
    Severity.INFORMATIONAL: Severity.INFORMATIONAL,
}


# ══════════════════════════════════════════════════════════════════════════════
# 8. Per-file orchestration
# ══════════════════════════════════════════════════════════════════════════════

class LocalIntelligence:
    """Facade used by the engine: one instance per audit run."""

    def __init__(self) -> None:
        self.classifier = TokenClassifier()
        self._auditor   = ConfigAuditor()

    # ── File-level analysis ──────────────────────────────────────────────────

    def analyse_file(
        self,
        content: str,
        file_url: str,
        file_type: FileType,
        existing: Optional[List[Finding]] = None,
    ) -> List[Finding]:
        """
        Run every local semantic pass over one file.

        Returns *new* findings. ``existing`` (the deterministic scanner's
        findings for this file) is used to avoid double-reporting and may be
        enriched in place (e.g. JWT expiry context).
        """
        existing = existing if existing is not None else []
        if not content or not content.strip():
            return []
        text = content[:MAX_SEMANTIC_BYTES]
        new: List[Finding] = []

        try:
            new.extend(self._inspect_jwts(text, file_url, file_type, existing))
        except Exception:
            pass
        try:
            new.extend(self._auditor.audit(text, file_url, file_type))
        except Exception:
            pass
        if not is_noise_file(file_url) and not self._is_minified(text):
            try:
                new.extend(self._semantic_assignments(text, file_url, file_type, existing))
            except Exception:
                pass
        return new

    @staticmethod
    def _is_minified(text: str) -> bool:
        if len(text) < 4000:
            return False
        newlines = text.count("\n") + 1
        return len(text) / newlines > 1200

    def _semantic_assignments(
        self, text: str, file_url: str, file_type: FileType, existing: List[Finding]
    ) -> List[Finding]:
        covered_lines = {f.line_number for f in existing if f.line_number and is_credential_finding(f)}
        fname = url_filename(file_url)
        is_config = file_type in (FileType.ENVIRONMENT, FileType.CONFIG, FileType.JSON, FileType.TERRAFORM)
        out: List[Finding] = []
        seen: set = set()

        for a in extract_assignments(text):
            if a.line in covered_lines:
                continue
            strength = key_sensitivity(a.key)
            if strength <= 0:
                continue
            value = a.value.strip()
            if len(value) < 6 or len(value) > 512:
                continue
            verdict = self.classifier.classify(value, key_hint=a.key)
            if verdict.label in ("placeholder", "benign"):
                continue
            # A bare (unquoted) wordy identifier is a variable reference, not a literal.
            has_digit_or_symbol = bool(re.search(r"[\d!@#$%^&*+=/\\|~?]", value))
            if not has_digit_or_symbol and wordiness(value) >= 0.45:
                continue
            if not a.quoted and re.fullmatch(r"[A-Za-z_][\w.]*", value) and wordiness(value) >= 0.6:
                continue
            if strength == 1 and not verdict.is_secret:
                continue

            vh = secret_hash(value)
            if vh in seen:
                continue
            seen.add(vh)

            confidence = 0.42 + 0.38 * verdict.score + (0.08 if strength == 2 else 0.0) + (0.05 if is_config else 0.0)
            confidence = round(min(confidence, 0.92), 3)
            severity = Severity.HIGH if (strength == 2 and confidence >= 0.70) else Severity.MEDIUM
            out.append(Finding(
                file_url=file_url,
                file_name=fname,
                file_type=file_type,
                category=FindingCategory.SECRET_EXPOSURE,
                rule_name="SEMANTIC_SECRET_ASSIGNMENT",
                description=(
                    f"Secret-bearing setting '{a.key[:60]}' is assigned a literal value "
                    f"(local semantic analysis, secret-likelihood {verdict.score:.0%})"
                ),
                severity=severity,
                match=redact(value),
                line_number=a.line,
                recommendation=(
                    "Rotate this value and load it from a secrets manager or injected environment "
                    "variable instead of a file in cloud storage."
                ),
                compliance_refs=["NIST IA-5", "SOC2 CC6.7", "CIS 2.1.5"],
                confidence=confidence,
                scanner="LocalIntelligence",
                value_hash=vh,
            ))
            if len(out) >= MAX_SEMANTIC_FINDINGS_PER_FILE:
                break
        return out

    def _inspect_jwts(
        self, text: str, file_url: str, file_type: FileType, existing: List[Finding]
    ) -> List[Finding]:
        out: List[Finding] = []
        by_line: Dict[int, Finding] = {
            f.line_number: f for f in existing if f.rule_name == "JWT_TOKEN" and f.line_number
        }
        reported_unsigned = False
        for i, m in enumerate(_JWT_RE.finditer(text)):
            if i >= 50:
                break
            info = inspect_jwt(m.group(0))
            if not info:
                continue
            line = text.count("\n", 0, m.start()) + 1
            base = by_line.get(line)
            if base is not None and "[JWT:" not in base.description:
                if info["expired"]:
                    when = time.strftime("%Y-%m-%d", time.gmtime(info["exp"]))
                    base.severity = Severity.LOW
                    base.description += f" [JWT: expired on {when} — residual risk only]"
                elif info["no_expiry"]:
                    base.severity = Severity.HIGH
                    base.confidence = max(base.confidence, 0.85)
                    base.description += " [JWT: no expiry claim — token never expires]"
                else:
                    when = time.strftime("%Y-%m-%d", time.gmtime(info["exp"]))
                    base.severity = Severity.HIGH
                    base.confidence = max(base.confidence, 0.9)
                    base.description += f" [JWT: still valid until {when}]"
                if info["issuer"]:
                    base.description += f" [issuer: {info['issuer']}]"
            if info["unsigned"] and not reported_unsigned:
                reported_unsigned = True
                out.append(Finding(
                    file_url=file_url,
                    file_name=url_filename(file_url),
                    file_type=file_type,
                    category=FindingCategory.SECRET_EXPOSURE,
                    rule_name="JWT_UNSIGNED_TOKEN",
                    description="JWT uses alg=none / carries no signature — the issuing service may accept forged tokens",
                    severity=Severity.HIGH,
                    match=redact(m.group(0), keep_chars=10),
                    line_number=line,
                    recommendation="Reject unsigned tokens server-side and pin the accepted signing algorithms.",
                    compliance_refs=["NIST IA-5", "NIST SC-13"],
                    confidence=0.9,
                    scanner="LocalIntelligence",
                ))
        return out

    # ── Run-level passes ─────────────────────────────────────────────────────

    @staticmethod
    def calibrate(findings: List[Finding]) -> None:
        """Context-aware confidence / severity adjustment. Mutates in place."""
        for f in findings:
            if getattr(f, "_calibrated", False):
                continue
            path = f.file_url + ("/" + f.archive_path if f.archive_path else "")
            base = f.rule_name.split(":")[0]
            if f.scanner in ("MisconfigAnalyzer", "CorrelationEngine", "SecretDeduplicator"):
                continue
            if is_non_production_path(path):
                soft = base in _SOFT_RULES or f.scanner == "LocalIntelligence"
                f.confidence = round(f.confidence * (0.55 if soft else 0.85), 3)
                if soft:
                    f.severity = _SEV_DOWN[f.severity]
                if "[context:" not in f.description:
                    f.description += " [context: test/example/documentation path — likely non-production]"
            if f.confidence and f.confidence < 0.30 and f.severity != Severity.INFORMATIONAL:
                f.severity = Severity.INFORMATIONAL
            try:
                setattr(f, "_calibrated", True)
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════════════
# 9. Aggregation
# ══════════════════════════════════════════════════════════════════════════════

def aggregate_findings(findings: List[Finding], threshold: int = 5) -> List[Finding]:
    """
    Collapse high-volume, low-signal rules (emails, internal IPs, entropy hits)
    into one finding per file so real issues are not buried — and escalate
    bulk personal data, which is a materially different risk from one address.
    """
    groups: Dict[Tuple[str, str], List[Finding]] = defaultdict(list)
    out: List[Finding] = []
    for f in findings:
        if f.rule_name in _VOLUME_RULES:
            groups[(f.file_url, f.rule_name)].append(f)
        else:
            out.append(f)

    for (_, rule), group in groups.items():
        if len(group) <= threshold:
            out.extend(group)
            continue
        distinct = len({g.value_hash or g.match for g in group})
        total = sum(max(g.occurrences, 1) for g in group)
        head = max(group, key=lambda g: g.confidence)
        merged = replace(head)
        merged.occurrences = total
        merged.match = f"{head.match} (+{len(group) - 1} more)"
        base_desc = head.description.split(" [")[0]
        merged.description = f"{base_desc} — {distinct} distinct values, {total} occurrences in this file"
        merged.line_number = min((g.line_number for g in group if g.line_number), default=head.line_number)
        if rule == "EMAIL_ADDRESS" and distinct >= 50:
            merged.rule_name = "BULK_PII_EXPOSURE"
            merged.severity = Severity.HIGH if distinct >= 500 else Severity.MEDIUM
            merged.confidence = max(head.confidence, 0.85)
            merged.description = (
                f"Bulk personal data: {distinct} distinct email addresses in one publicly exposed file"
            )
            merged.recommendation = (
                "Remove the file from public storage and assess breach-notification obligations "
                "for the personal data it contains."
            )
            merged.compliance_refs = sorted(set(head.compliance_refs) | {"GDPR Art. 32", "SOC2 CC6.7", "NIST SC-28"})
        out.append(merged)
    return out


# ══════════════════════════════════════════════════════════════════════════════
# 10. Correlation — compound exposures
# ══════════════════════════════════════════════════════════════════════════════

def _container_of(file_url: str) -> str:
    return file_url.split("!/")[0]


def correlate_findings(findings: List[Finding]) -> List[Finding]:
    """
    Detect combinations of findings that are materially worse together than
    apart. Each result is a synthetic finding describing the combined exposure.
    """
    by_file: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        if f.scanner in ("CorrelationEngine", "SecretDeduplicator", "MisconfigAnalyzer"):
            continue
        by_file[f.file_url].append(f)

    out: List[Finding] = []

    def emit(anchor: Finding, rule: str, sev: Severity, desc: str, rec: str,
             refs: Sequence[str], conf: float = 0.93,
             cat: FindingCategory = FindingCategory.SECRET_EXPOSURE, name: Optional[str] = None) -> None:
        out.append(Finding(
            file_url=anchor.file_url,
            file_name=name or anchor.file_name,
            file_type=anchor.file_type,
            category=cat,
            rule_name=rule,
            description=desc,
            severity=sev,
            match="[correlated finding — see constituent findings]",
            recommendation=rec,
            compliance_refs=list(refs),
            confidence=conf,
            scanner="CorrelationEngine",
        ))

    all_cred_types: Dict[str, set] = defaultdict(set)
    has_bulk_pii = None
    for url, fs in by_file.items():
        rules = {f.rule_name.split(":")[0] for f in fs if f.confidence >= 0.35}
        creds = {f.rule_name for f in fs if is_credential_finding(f) and f.confidence >= 0.5}
        for r in creds:
            all_cred_types[r].add(url)
        anchor = max(fs, key=lambda f: (f.severity.int_value, f.confidence))

        if "AWS_ACCESS_KEY" in rules and "AWS_SECRET_KEY" in rules:
            emit(anchor, "COMPOUND_AWS_CREDENTIAL_PAIR", Severity.CRITICAL,
                 "A complete AWS credential pair (access key ID and secret access key) is exposed in the same file — "
                 "the pair is directly usable without any further information",
                 "Deactivate the access key in IAM now, issue a replacement through a secrets manager, and review "
                 "CloudTrail for every action taken with this key ID.",
                 ["CIS 1.14", "NIST IA-5", "SOC2 CC6.1"], 0.97)
        if "GCP_SERVICE_ACCOUNT_KEY" in rules and "PRIVATE_KEY" in rules:
            emit(anchor, "COMPOUND_GCP_SERVICE_ACCOUNT_KEY", Severity.CRITICAL,
                 "A complete Google Cloud service-account key file (identity plus private key) is exposed",
                 "Delete the key in IAM, audit the service account's activity logs, and move to workload identity.",
                 ["CIS GCP 1.4", "NIST IA-5"], 0.97)
        if "PRIVATE_KEY" in rules and (rules & {"SSH_CONFIG", "INTERNAL_IP", "WEAK_SSH_DAEMON_CONFIG"}):
            emit(anchor, "COMPOUND_KEY_WITH_HOST_DETAILS", Severity.CRITICAL,
                 "Private key material is exposed together with host / network details that identify where it is used",
                 "Revoke the key pair on every host that trusts it and regenerate. Treat the listed hosts as exposed.",
                 ["NIST IA-5", "NIST SC-7", "SOC2 CC6.1"], 0.9)
        if rules & {"DATABASE_URL", "BASIC_AUTH_URL"} and "INTERNAL_IP" in rules:
            emit(anchor, "COMPOUND_DATASTORE_ACCESS_PATH", Severity.HIGH,
                 "Data-store credentials are exposed together with internal network addressing",
                 "Rotate the database credentials and confirm the data store is unreachable from untrusted networks.",
                 ["NIST IA-5", "NIST SC-7", "PCI-DSS Req 1.3"], 0.85)
        if len(creds) >= 3:
            emit(anchor, "COMPOUND_SECRETS_FILE", Severity.CRITICAL,
                 f"{len(creds)} different credential types are stored together in one exposed file "
                 f"({', '.join(sorted(creds)[:5])}{'…' if len(creds) > 5 else ''})",
                 "Treat every credential in this file as compromised and rotate them all. Replace the file with "
                 "references to a secrets manager.",
                 ["NIST IA-5", "SOC2 CC6.7", "CIS 2.1.5"], 0.92)
        if "BULK_PII_EXPOSURE" in rules or "CREDIT_CARD" in rules or "USER_TABLE_DUMP" in rules:
            has_bulk_pii = has_bulk_pii or anchor

    if all_cred_types:
        files_with_creds = set().union(*all_cred_types.values())
        if len(all_cred_types) >= 4 and len(files_with_creds) >= 3:
            anchor = next(f for f in findings if f.file_url in files_with_creds)
            emit(anchor, "SYSTEMIC_SECRET_SPRAWL", Severity.HIGH,
                 f"{len(all_cred_types)} distinct credential types are spread across {len(files_with_creds)} exposed "
                 "files — this indicates a systemic secret-management gap rather than an isolated mistake",
                 "Adopt a central secrets manager, add secret scanning to CI, and inventory every credential found here for rotation.",
                 ["NIST IA-5", "SOC2 CC6.1", "ISO27001 A.9.2"], 0.88, name="[Multiple Files]")
        if has_bulk_pii is not None:
            emit(has_bulk_pii, "COMPOUND_PERSONAL_DATA_WITH_CREDENTIALS", Severity.HIGH,
                 "Personal / regulated data and working credentials are exposed in the same storage container",
                 "Prioritise this container for incident response: rotate credentials, remove the data, and assess "
                 "notification obligations.",
                 ["GDPR Art. 32", "GDPR Art. 33", "SOC2 CC6.7", "PCI-DSS Req 3.4"], 0.85,
                 cat=FindingCategory.COMPLIANCE, name="[Multiple Files]")
    return out


# ══════════════════════════════════════════════════════════════════════════════
# 11. File risk ranking
# ══════════════════════════════════════════════════════════════════════════════

_SEV_W = {"Critical": 10.0, "High": 5.0, "Medium": 2.0, "Low": 0.5, "Informational": 0.0}
_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}


def rank_files(findings: Iterable[Dict[str, Any]], top: int = 10) -> List[Dict[str, Any]]:
    """Score each file by confidence-weighted severity with diminishing returns per rule."""
    per_file: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for f in findings:
        name = f.get("file_name", "")
        if name.startswith("[") or f.get("scanner") in ("MisconfigAnalyzer", "CorrelationEngine", "SecretDeduplicator"):
            continue
        per_file[f.get("file_url", "")].append(f)

    ranked: List[Dict[str, Any]] = []
    for url, fs in per_file.items():
        by_rule: Dict[str, List[float]] = defaultdict(list)
        for f in fs:
            w = _SEV_W.get(f.get("severity", ""), 0.0) * (0.4 + 0.6 * float(f.get("confidence") or 0.5))
            by_rule[f.get("rule_name", "")].append(w)
        raw = 0.0
        for ws in by_rule.values():
            for i, w in enumerate(sorted(ws, reverse=True)):
                raw += w * (0.5 ** i)
        sev = Counter(f.get("severity", "") for f in fs)
        top_rules = [r for r, _ in sorted(by_rule.items(), key=lambda kv: -max(kv[1]))[:4]]
        ranked.append({
            "file_url":  url,
            "file_name": fs[0].get("archive_path") or fs[0].get("file_name", ""),
            "score":     round(10 * (1 - math.exp(-raw / 12)), 2),
            "findings":  len(fs),
            "critical":  sev.get("Critical", 0),
            "high":      sev.get("High", 0),
            "top_rules": top_rules,
        })
    ranked.sort(key=lambda r: (-r["score"], -r["critical"], -r["high"], r["file_name"]))
    return ranked[:top]


# ══════════════════════════════════════════════════════════════════════════════
# 12. Executive summary + AI digest
# ══════════════════════════════════════════════════════════════════════════════

_PHASES = ("Immediate (0–24 hours)", "Short term (1–7 days)", "Strategic (within 30 days)")

# (rule-name regex, phase, action, effort)
_PLAYBOOK: Tuple[Tuple[str, int, str, str], ...] = (
    (r"^PUBLIC_BUCKET_ACCESS|^PUBLIC_STORAGE_ACL|^IAM_PUBLIC_PRINCIPAL|^AWS_ACL", 0,
     "Remove public access from the container (S3 Block Public Access / Azure private access level / "
     "GCS uniform bucket-level access with allUsers removed) and confirm with an unauthenticated request.", "≈30 min"),
    (r"AWS_(?:ACCESS|SECRET|SESSION)|COMPOUND_AWS", 0,
     "Deactivate and replace the exposed AWS access keys in IAM, then review CloudTrail for activity by those key IDs.", "1–2 h"),
    (r"^GCP_|COMPOUND_GCP", 0,
     "Delete the exposed Google Cloud keys / service-account keys and review Cloud Audit Logs for their use.", "1–2 h"),
    (r"^AZURE_", 0,
     "Regenerate the Azure storage account keys and revoke outstanding SAS tokens.", "1 h"),
    (r"PRIVATE_KEY|SSH_|COMPOUND_KEY|NETRC|AGE_SECRET", 0,
     "Revoke the exposed private keys everywhere they are trusted (authorized_keys, certificates, signing) and issue new key pairs.", "2–4 h"),
    (r"DATABASE_URL|BASIC_AUTH_URL|COMPOUND_DATASTORE|DEFAULT_CREDENTIALS|PASSWORD_HASH|HARDCODED_PASSWORD|USER_TABLE", 0,
     "Rotate database and service passwords found in the files, force resets for any exposed user password hashes, "
     "and review data-store access logs.", "2–4 h"),
    (r"GITHUB|GITLAB|SLACK|STRIPE|TWILIO|SENDGRID|OPENAI|ANTHROPIC|NPM_|PYPI|DISCORD|TELEGRAM|SHOPIFY|"
     r"DIGITALOCEAN|HUGGINGFACE|DATABRICKS|VAULT_|DOCKERHUB|GRAFANA|NEWRELIC|MAILGUN|SQUARE|POSTMAN|"
     r"LINEAR|TERRAFORM_CLOUD|GOOGLE_OAUTH|PACKAGE_REGISTRY|_WEBHOOK", 0,
     "Revoke the exposed third-party service tokens in each provider's console and audit their recent API usage.", "1–3 h"),
    (r"GENERIC_API_KEY|ENV_VARIABLE_SECRET|SEMANTIC_SECRET|JWT|HIGH_ENTROPY|COMPOUND_SECRETS_FILE|KUBERNETES_SECRET|SECRET_BAKED|SHELL_HISTORY", 1,
     "Triage the remaining application secrets and tokens: confirm which are live, rotate them, and replace the files with "
     "references to a secrets manager.", "0.5–1 day"),
    (r"SENSITIVE_FILE_EXPOSED|DATABASE_DUMP|TERRAFORM", 1,
     "Delete configuration files, backups and state files from the container; move required ones to private, encrypted storage.", "2–4 h"),
    (r"BULK_PII|EMAIL_ADDRESS|CREDIT_CARD|US_SSN|IBAN|PHONE|COMPOUND_PERSONAL|EXIF|GPS", 1,
     "Assess the exposed personal data with your privacy / compliance lead to determine notification obligations.", "1–2 days"),
    (r"OPEN_NETWORK_INGRESS|IAM_WILDCARD|PUBLIC_DATABASE|PRIVILEGED_CONTAINER|AUTHENTICATION_DISABLED|"
     r"TLS_VERIFICATION|WEAK_|ENCRYPTION_DISABLED|PERMISSIVE_CORS|DEBUG_MODE|MFA_DISABLED|INSTANCE_METADATA|"
     r"WILDCARD_ALLOWED|AUDIT_LOGGING|CLEARTEXT", 1,
     "Fix the infrastructure and application misconfigurations revealed by the exposed files (network ingress, IAM "
     "wildcards, disabled auth/TLS/encryption) in the source repositories that generated them.", "1–3 days"),
    (r"DUPLICATE_SECRET|CREDENTIAL_REUSE|SYSTEMIC_SECRET_SPRAWL", 2,
     "Eliminate shared credentials: issue one scoped credential per service and prefer workload identity / IAM roles.", "1–2 weeks"),
)

_FRAMEWORK_ORDER = ("CIS", "NIST", "SOC2", "PCI-DSS", "ISO27001", "GDPR", "HIPAA")


def _scan_view(data: Dict[str, Any]) -> Dict[str, Any]:
    scan = data.get("scan", data) if isinstance(data, dict) else {}
    return scan if isinstance(scan, dict) else {}


def _posture(risk: float, sev: Counter, compound: int, cred_critical: int) -> str:
    if risk >= 8.5 or compound > 0 or cred_critical > 0:
        return "CRITICAL"
    if risk >= 6.5 or sev.get("Critical", 0) > 0:
        return "HIGH"
    if risk >= 4.0 or sev.get("High", 0) > 0:
        return "MODERATE"
    return "LOW"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def generate_summary(data: Dict[str, Any], version: str = "") -> str:
    """Build a data-driven executive summary (markdown) entirely offline."""
    scan      = _scan_view(data)
    findings  = [f for f in scan.get("findings", []) if isinstance(f, dict)]
    container = scan.get("container") or {}
    risk      = float(scan.get("risk_score") or 0.0)
    trend     = scan.get("trend_summary") or ""
    cname     = container.get("container_name") or container.get("raw_url") or "the target container"
    ctype     = container.get("container_type") or "cloud storage"
    scanned   = scan.get("scanned_files", 0)
    total_f   = scan.get("total_files", 0)

    sev = Counter(f.get("severity", "Informational") for f in findings)
    compound = [f for f in findings if str(f.get("rule_name", "")).startswith(("COMPOUND_", "SYSTEMIC_"))]
    cred_cats = ("Secret Exposure", "Credential File Exposed")
    creds = [
        f for f in findings
        if f.get("category") in cred_cats
        and f.get("scanner") not in ("CorrelationEngine", "SecretDeduplicator", "MisconfigAnalyzer")
        and str(f.get("rule_name", "")).split(":")[0] not in _NON_CREDENTIAL_RULES
    ]
    cred_critical = sum(1 for f in creds if f.get("severity") == "Critical" and float(f.get("confidence") or 0) >= 0.7)
    posture = _posture(risk, sev, len(compound), cred_critical)
    high_conf = sum(1 for f in findings if float(f.get("confidence") or 0) >= 0.75)

    lines: List[str] = ["## Executive Summary", ""]
    if not findings:
        lines += [
            f"The CloudAudit assessment of **{cname}** ({ctype}) analysed {scanned} of {total_f} discovered "
            f"files and recorded **no findings** at or above the reporting threshold. The composite risk score "
            f"is **{risk:.1f}/10**.",
            "",
            "No credentials, personal data or sensitive configuration were detected in the readable content. "
            "Keep the container private by default and re-run this audit after each deployment change.",
            "",
        ]
    else:
        lines += [
            f"The CloudAudit assessment of **{cname}** ({ctype}) analysed {scanned} of {total_f} discovered files "
            f"and recorded **{_plural(len(findings), 'finding')}** — {sev.get('Critical', 0)} critical, "
            f"{sev.get('High', 0)} high, {sev.get('Medium', 0)} medium and {sev.get('Low', 0)} low. "
            f"Overall risk posture is **{posture}** with a composite risk score of **{risk:.1f}/10**. "
            f"{high_conf} of the {len(findings)} findings are high-confidence (≥75%).",
            "",
        ]

        # ── Key risk drivers ────────────────────────────────────────────────
        drivers: List[str] = []
        for f in sorted(compound, key=lambda x: -_SEV_RANK.get(x.get("severity", ""), 0))[:3]:
            drivers.append(f"**Compound exposure** — {f.get('description', '')}.")
        if container.get("is_public") and any(str(f.get("rule_name", "")).startswith("PUBLIC_BUCKET") for f in findings):
            drivers.append(
                f"**Public listing** — the {ctype} container can be enumerated and downloaded without authentication, "
                "so every other finding in this report is reachable by anyone on the internet."
            )
        by_rule: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in creds:
            if f.get("severity") in ("Critical", "High") and float(f.get("confidence") or 0) >= 0.5:
                by_rule[str(f.get("rule_name"))].append(f)
        for rule, fs in sorted(by_rule.items(),
                               key=lambda kv: (-max(_SEV_RANK.get(x.get("severity", ""), 0) for x in kv[1]), -len(kv[1])))[:5]:
            files = sorted({x.get("archive_path") or x.get("file_name", "") for x in fs})
            label = str(fs[0].get("description", rule)).split(" [")[0].split(" (")[0]
            drivers.append(
                f"**{label}** — {_plural(len(fs), 'instance')} in {_plural(len(files), 'file')} "
                f"(e.g. `{files[0]}`)."
            )
        if drivers:
            lines += ["### Key Risk Drivers", ""] + [f"- {d}" for d in drivers[:7]] + [""]

        # ── Exposure breakdown ──────────────────────────────────────────────
        cat = Counter(f.get("category", "Unknown") for f in findings)
        cred_types = sorted({str(f.get("rule_name")) for f in creds})
        lines += ["### Exposure Breakdown", ""]
        lines.append("- **By category:** " + ", ".join(f"{c} ({n})" for c, n in cat.most_common(5)) + ".")
        if cred_types:
            shown = ", ".join(cred_types[:8]) + ("…" if len(cred_types) > 8 else "")
            lines.append(f"- **Credential types exposed ({len(cred_types)}):** {shown}.")
        pii = [f for f in findings if f.get("category") == "PII / Personal Data"]
        if pii:
            lines.append(f"- **Personal data:** {_plural(len(pii), 'finding')} across "
                         f"{_plural(len({f.get('file_url') for f in pii}), 'file')}.")
        misconf = [f for f in findings if f.get("scanner") == "LocalIntelligence"
                   and f.get("category") in ("Compliance Gap", "Public Access Misconfiguration")]
        if misconf:
            names = sorted({str(f.get("rule_name")) for f in misconf})
            lines.append(f"- **Configuration weaknesses revealed by exposed files:** {', '.join(names[:6])}"
                         f"{'…' if len(names) > 6 else ''}.")
        lines.append("")

        # ── Highest-risk files ──────────────────────────────────────────────
        ranked = scan.get("file_risk") or rank_files(findings, top=5)
        ranked = [r for r in ranked if r.get("score", 0) > 0][:5]
        if ranked:
            lines += ["### Highest-Risk Files", ""]
            for r in ranked:
                lines.append(
                    f"- `{r['file_name']}` — file risk {r['score']:.1f}/10, {_plural(r['findings'], 'finding')} "
                    f"({r['critical']} critical, {r['high']} high): {', '.join(r['top_rules'][:3])}"
                )
            lines.append("")

        # ── Remediation plan ────────────────────────────────────────────────
        rule_names = [str(f.get("rule_name", "")) for f in findings]
        plan: Dict[int, List[str]] = defaultdict(list)
        for pattern, phase, action, effort in _PLAYBOOK:
            rx = re.compile(pattern)
            n = sum(1 for r in rule_names if rx.search(r))
            if n:
                plan[phase].append(f"{action} *(covers {_plural(n, 'finding')}; effort {effort})*")
        if creds:
            plan[2].append("Add secret scanning to CI and pre-commit so credentials are blocked before they reach "
                           "any artifact or bucket. *(effort ≈1 day)*")
            plan[2].append("Move all application secrets to a managed secrets store with automatic rotation. *(effort 1–2 weeks)*")
        plan[2].append("Enable storage access logging and schedule this audit (e.g. `--interval` or `cloudaudit init-ci`) "
                       "to detect regressions. *(effort ≈2 h)*")
        lines += ["### Prioritised Remediation Plan", ""]
        step = 1
        for phase in sorted(plan):
            lines.append(f"**{_PHASES[phase]}**")
            for action in plan[phase]:
                lines.append(f"{step}. {action}")
                step += 1
            lines.append("")

        # ── Compliance impact ───────────────────────────────────────────────
        controls: Dict[str, Counter] = defaultdict(Counter)
        for f in findings:
            for ref in f.get("compliance_refs") or []:
                fw = str(ref).split(" ")[0]
                controls[fw][str(ref)] += 1
        if controls:
            lines += ["### Compliance Impact", ""]
            ordered = [fw for fw in _FRAMEWORK_ORDER if fw in controls] + \
                      sorted(fw for fw in controls if fw not in _FRAMEWORK_ORDER)
            for fw in ordered[:7]:
                top = ", ".join(f"{ref} ({n})" for ref, n in controls[fw].most_common(4))
                lines.append(f"- **{fw}:** {_plural(sum(controls[fw].values()), 'mapped finding')} — {top}")
            lines.append("")

    if trend:
        lines += [f"**Trend vs. previous scan:** {trend}", ""]

    suppressed = scan.get("suppressed_count") or 0
    if suppressed:
        lines += [f"*{_plural(suppressed, 'finding')} suppressed by the accepted-risk baseline are not included above.*", ""]

    lines.append(
        f"*Generated offline by the CloudAudit Local Intelligence Engine v{ENGINE_VERSION}"
        + (f" (CloudAudit v{version})" if version else "")
        + " — no scan data left this machine. Powered by xtawb — https://linktr.ee/xtawb*"
    )
    return "\n".join(lines)


def build_ai_digest(data: Dict[str, Any], max_chars: int = 9000) -> str:
    """
    Compact, always-valid JSON digest of a scan for sending to a remote model.

    Replaces naive string truncation (which produced invalid JSON and silently
    dropped the most important findings). Contains only redacted metadata —
    no ``match`` or ``context`` values are included.
    """
    scan = _scan_view(data)
    findings = [f for f in scan.get("findings", []) if isinstance(f, dict)]
    findings.sort(key=lambda f: (-_SEV_RANK.get(f.get("severity", ""), 0), -float(f.get("confidence") or 0)))
    digest: Dict[str, Any] = {
        "container":       scan.get("container") or {},
        "total_files":     scan.get("total_files", 0),
        "scanned_files":   scan.get("scanned_files", 0),
        "risk_score":      scan.get("risk_score", 0),
        "total_findings":  len(findings),
        "severity_counts": dict(Counter(f.get("severity", "") for f in findings)),
        "category_counts": dict(Counter(f.get("category", "") for f in findings)),
        "rule_counts":     dict(Counter(str(f.get("rule_name", "")) for f in findings).most_common(30)),
        "highest_risk_files": [
            {k: r[k] for k in ("file_name", "score", "critical", "high", "top_rules") if k in r}
            for r in (scan.get("file_risk") or rank_files(findings, top=5))[:5]
        ],
        "top_findings": [],
    }
    if scan.get("trend_summary"):
        digest["trend_summary"] = scan["trend_summary"]
    if isinstance(digest["container"], dict):
        digest["container"] = {k: v for k, v in digest["container"].items() if k != "notes"}

    for f in findings:
        item = {
            "rule":        f.get("rule_name"),
            "severity":    f.get("severity"),
            "category":    f.get("category"),
            "file":        f.get("archive_path") or f.get("file_name"),
            "description": str(f.get("description", ""))[:180],
            "confidence":  f.get("confidence"),
            "compliance":  (f.get("compliance_refs") or [])[:4],
        }
        digest["top_findings"].append(item)
        if len(json.dumps(digest, default=str)) > max_chars:
            digest["top_findings"].pop()
            break
    digest["findings_omitted"] = len(findings) - len(digest["top_findings"])
    return json.dumps(digest, indent=1, default=str)


def analyse_content_as_json(filename: str, filetype: str, content: str) -> str:
    """Local equivalent of the remote file-analysis prompt, same JSON contract."""
    try:
        ft = FileType(filetype)
    except ValueError:
        ft = FileType.OTHER
    found = LocalIntelligence().analyse_file(content, filename, ft, [])
    return json.dumps({"findings": [
        {
            "type":           f.rule_name,
            "description":    f.description,
            "severity":       f.severity.value.lower(),
            "line_hint":      f"line {f.line_number}" if f.line_number else "",
            "confidence":     f.confidence,
            "recommendation": f.recommendation,
        }
        for f in found
    ]})
