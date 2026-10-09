"""
cloudaudit.intelligence.benchmark — detection accuracy benchmark (`cloudaudit benchmark`)

Measures precision and recall of the secret-detection pipeline on a labelled,
synthetic corpus, so that "is detection better or worse after this change?"
has a number instead of an opinion.

  * positives — files with one planted secret on a known line
  * negatives — files that look secret-ish but contain none: placeholders,
    references, hashes, UUIDs, public keys, certificates, lockfiles, …

Scoring is per finding:
    TP  a planted secret was reported (any secret-class finding on its line)
    FN  a planted secret was not reported
    FP  a secret-class finding anywhere a secret was not planted

Every secret-shaped value is generated at runtime from a seeded PRNG — no
credential literal exists in this file — and the corpus is deterministic.

Limits, stated plainly: the corpus is synthetic and was written alongside the
rules, so typed-token recall is close to "does the regex match its own
format". The numbers are most meaningful for the generic / semantic cases and
for the negative set, and as a regression gate. They are not a claim about
accuracy on arbitrary real-world data.
"""

from __future__ import annotations

import base64
import json
import random
import string
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from cloudaudit.core.models import FileType, Finding, FindingCategory, Severity
from cloudaudit.core.pipeline import ContentAnalyzer
from cloudaudit.intelligence.local_ai import LocalIntelligence
from cloudaudit.scanners.file_classifier import FileClassifier

SEED = 20261009
_B62 = string.ascii_letters + string.digits
_HEX = "0123456789abcdef"
_B64 = _B62 + "+/"
_MARK = "@@SECRET@@"


@dataclass
class Sample:
    name:         str
    path:         str
    content:      str
    secret_lines: frozenset = frozenset()     # empty → negative sample
    kind:         str = ""                    # "typed" | "generic" | "semantic" | "entropy" | "negative"


# ── Value generators ───────────────────────────────────────────────────────────

class _Gen:
    def __init__(self, seed: int = SEED) -> None:
        self.r = random.Random(seed)

    def of(self, alphabet: str, n: int) -> str:
        return "".join(self.r.choice(alphabet) for _ in range(n))

    def b62(self, n: int) -> str:
        return self.of(_B62, n)

    def hex(self, n: int) -> str:
        return self.of(_HEX, n)

    def b64(self, n: int) -> str:
        return self.of(_B64, n)

    def upper(self, n: int) -> str:
        return self.of(string.ascii_uppercase + string.digits, n)

    def digits(self, n: int) -> str:
        return self.of(string.digits, n)

    def password(self) -> str:
        """A human-chosen-looking but strong password: syllables + digits + symbol."""
        syl = ["ko", "va", "tu", "mi", "re", "zan", "pel", "dor", "qui", "bex", "lum", "fy", "gra", "ne", "sho"]
        word = "".join(self.r.choice(syl) for _ in range(self.r.randint(2, 4)))
        word = word.capitalize() if self.r.random() < 0.7 else word
        return f"{word}{self.digits(self.r.randint(2, 4))}{self.r.choice('!@#%&*?')}{self.b62(self.r.randint(2, 5))}"

    def uuid(self) -> str:
        h = self.hex(32)
        return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:]}"


def _typed_tokens(g: _Gen) -> Dict[str, str]:
    """Synthetic values in each provider's documented format (assembled, never literal)."""
    jwt_h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    jwt_p = base64.urlsafe_b64encode(json.dumps({"sub": g.b62(8), "role": "svc"}).encode()).rstrip(b"=").decode()
    return {
        "aws_access_key":  "AK" + "IA" + g.upper(16),
        "github_pat":      "gh" + "p_" + g.b62(36),
        "gitlab_pat":      "gl" + "pat-" + g.b62(20),
        "slack_token":     "xo" + "xb-" + g.digits(11) + "-" + g.digits(12) + "-" + g.b62(24),
        "stripe_key":      "sk" + "_live_" + g.b62(24),
        "sendgrid_key":    "S" + "G." + g.b62(22) + "." + g.b62(43),
        "openai_key":      "sk" + "-proj-" + g.b62(48),
        "anthropic_key":   "sk" + "-ant-api03-" + g.b62(48),
        "npm_token":       "np" + "m_" + g.b62(36),
        "hf_token":        "h" + "f_" + g.b62(34),
        "vault_token":     "hv" + "s." + g.b62(28),
        "do_token":        "do" + "p_v1_" + g.hex(64),
        "gcp_api_key":     "AI" + "za" + g.b62(35),
        "dockerhub_token": "dc" + "kr_pat_" + g.b62(27),
        "databricks":      "da" + "pi" + g.hex(32),
        "jwt":             f"{jwt_h}.{jwt_p}.{g.b62(43)}",
    }


# ── Corpus ─────────────────────────────────────────────────────────────────────

def _place(name: str, path: str, template: str, secret: str, kind: str) -> Sample:
    """Build a positive sample; the line containing the marker is the labelled line."""
    lines = template.split("\n")
    marked = frozenset(i + 1 for i, line in enumerate(lines) if _MARK in line)
    return Sample(name, path, template.replace(_MARK, secret), marked, kind)


def build_corpus(seed: int = SEED) -> List[Sample]:
    g = _Gen(seed)
    samples: List[Sample] = []

    # ── Positives: typed provider tokens, each in a different host format ─────
    contexts: List[Tuple[str, str]] = [
        ("config/.env",            "APP_ENV=production\nLOG_LEVEL=info\nSERVICE_CREDENTIAL={m}\nPORT=8080\n"),
        ("deploy/values.yaml",     "replicaCount: 2\nimage:\n  tag: stable\nintegration:\n  credential: {m}\n"),
        ("app/settings.json",      '{{\n  "region": "eu-west-1",\n  "integration": {{ "credential": "{m}" }},\n  "retries": 3\n}}\n'),
        ("src/client.py",          'import requests\n\nTIMEOUT = 30\nCREDENTIAL = "{m}"\n\ndef call():\n    return requests.get(URL, timeout=TIMEOUT)\n'),
        ("web/api.js",             "const base = '/v1';\nconst credential = '{m}';\nexport default {{ base, credential }};\n"),
    ]
    for i, (rule, token) in enumerate(sorted(_typed_tokens(g).items())):
        path, tpl = contexts[i % len(contexts)]
        samples.append(_place(f"typed:{rule}", path, tpl.format(m=_MARK), token, "typed"))

    # ── Positives: generic credentials in the shapes regex rules were written for ──
    pw = g.password
    generic: List[Tuple[str, str, str, str]] = [
        ("py-quoted-password",  "app/db.py",            'HOST = "db.internal"\npassword = "{m}"\n', pw()),
        ("js-quoted-password",  "srv/config.js",        "module.exports = {{\n  user: 'svc',\n  password: '{m}',\n}};\n", pw()),
        ("env-db-password",     ".env.production",      "DB_HOST=10.4.2.17\nDB_PASSWORD={m}\n", pw()),
        ("env-api-token",       "deploy/.env",          "API_URL=https://api.acme.io\nSERVICE_API_TOKEN={m}\n", g.b62(40)),
        ("postgres-url",        "config/database.yml",  "production:\n  url: postgres://app:{m}@db.acme.internal:5432/main\n", pw().replace("@", "x").replace("#", "x").replace("?", "x").replace("%", "x")),
        ("mongodb-url",         "srv/store.js",         "const uri = 'mongodb+srv://svc:{m}@cluster0.acme.mongodb.net/prod';\n", g.b62(20)),
        ("basic-auth-url",      ".git-credentials",     "https://deploy:{m}@git.acme.io\n", g.b62(24)),
        ("dotnet-conn-string",  "web.config",           '<add name="Main" connectionString="Server=sql01;Database=app;User Id=sa;Password={m};" />\n', g.b62(16)),
        ("private-key",         "keys/service.pem",     "{m}\n" + "\n".join(g.b64(64) for _ in range(6)) + "\n-----END RSA PRIVATE KEY-----\n", "-----BEGIN RSA " + "PRIVATE KEY-----"),
        ("aws-secret-key",      "infra/credentials",    "[default]\nregion = eu-west-1\naws_secret_access_key = {m}\n", g.b62(40)),
        ("generic-api-key",     "mobile/config.xml",    '<config>\n  <entry api_key="{m}"/>\n</config>\n', g.b62(32)),
    ]
    for name, path, tpl, secret in generic:
        samples.append(_place(f"generic:{name}", path, tpl.format(m=_MARK), secret, "generic"))

    # ── Positives: only semantic analysis can find these (no rule matches the shape) ──
    semantic: List[Tuple[str, str, str, str]] = [
        ("yaml-unquoted-password",  "config/app.yml",          "database:\n  host: db.internal\n  password: {m}\n", pw()),
        ("yaml-camel-secret",       "k8s/values.yaml",         "auth:\n  clientId: web-portal\n  clientSecret: {m}\n", g.b62(32)),
        ("json-signing-key",        "config/jwt.json",         '{{\n  "issuer": "acme",\n  "signingKey": "{m}"\n}}\n', g.b64(44)),
        ("ini-unquoted-password",   "etc/app.ini",             "[database]\nhost = db.internal\npassword = {m}\n", pw()),
        ("xml-element-password",    "conf/datasource.xml",     "<datasource>\n  <user>app</user>\n  <password>{m}</password>\n</datasource>\n", pw()),
        ("properties-password",     "application.properties",  "spring.datasource.url=jdbc:postgresql://db/app\nspring.datasource.password={m}\n", pw()),
        ("php-variable",            "inc/config.php",          "<?php\n$db_user = 'app';\n$db_pass = '{m}';\n", pw()),
        ("compose-environment",     "docker-compose.yml",      "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: {m}\n", pw()),
        ("toml-encryption-key",     "config/prod.toml",        '[crypto]\nalgorithm = "aes-256-gcm"\nencryption_key = "{m}"\n', g.hex(64)),
        ("hex-key-under-api-key",   "config/partner.yaml",     "partner:\n  endpoint: https://partner.example.net\n  api_key: {m}\n", g.hex(32)),
        ("json-auth-token",         "tools/cli-config.json",   '{{ "profile": "default", "auth_token": "{m}" }}\n', g.b62(40)),
        ("webhook-secret",          "config/hooks.yml",        "hooks:\n  events: [push]\n  webhook_secret: {m}\n", g.b62(32)),
        ("ruby-session-secret",     "config/secrets.rb",       "Rails.application.config.secret_key_base = '{m}'\n", g.hex(128)),
        ("go-const",                "internal/auth/keys.go",   'package auth\n\nconst masterKey = "{m}"\n', g.b64(43)),
    ]
    for name, path, tpl, secret in semantic:
        samples.append(_place(f"semantic:{name}", path, tpl.format(m=_MARK), secret, "semantic"))

    # ── Positives: random secret with no naming hint at all (entropy only) ────
    entropy: List[Tuple[str, str, str, str]] = [
        ("bare-b64-blob",   "data/bootstrap.txt",  "# bootstrap material\n{m}\n", g.b64(48)),
        ("unnamed-const",   "lib/consts.py",       'RETRIES = 3\nX1 = "{m}"\n', g.b62(40)),
        ("yaml-opaque",     "config/extra.yaml",   "extra:\n  blob: {m}\n", g.b62(44)),
    ]
    for name, path, tpl, secret in entropy:
        samples.append(_place(f"entropy:{name}", path, tpl.format(m=_MARK), secret, "entropy"))

    # ── Positives: deliberately awkward cases (the ones a rule author forgets) ──
    basic = base64.b64encode(f"deploy:{pw()}".encode()).decode()
    hard: List[Tuple[str, str, str, str]] = [
        ("weak-short-password",    "config/legacy.ini",       "[ftp]\nuser = backup\npassword = {m}\n", "hunter" + g.digits(2)),
        ("secret-in-comment",      "src/payments.py",         "def charge():\n    # TODO remove: old live key was {m}\n    return client.charge()\n", g.b62(32)),
        ("url-query-token",        "scripts/sync.sh",         "#!/bin/sh\ncurl -s 'https://api.acme.io/v1/export?access_token={m}&format=csv'\n", g.b62(30)),
        ("bearer-header",          "scripts/deploy.sh",       '#!/bin/sh\ncurl -H "Authorization: Bearer {m}" https://api.acme.io/deploy\n', g.b62(40)),
        ("docker-config-auth",     "home/.docker/config.json", '{{\n  "auths": {{ "registry.acme.io": {{ "auth": "{m}" }} }}\n}}\n', basic),
        ("passphrase-with-spaces", "config/backup.yml",       'backup:\n  target: s3\n  passphrase: "{m}"\n', "violet tundra anchor 41 maple!"),
        ("windows-batch-set",      "deploy/run.bat",          "@echo off\nset DB_PASS={m}\napp.exe\n", pw()),
        ("k8s-secret-data",        "k8s/secret.yaml",         "apiVersion: v1\nkind: ConfigMap\ndata:\n  password: {m}\n", base64.b64encode(pw().encode()).decode()),
        ("python-header-dict",     "tools/fetch.py",          'HEADERS = {{"Authorization": "Token {m}"}}\n', g.hex(40)),
        ("jwk-private-key",        "keys/signing.jwk",        '{{"kty": "oct", "kid": "sig-1", "alg": "HS256", {m}}}\n', '"k": "' + g.b62(43) + '"'),
        ("tfvars",                 "infra/prod.tfvars",       'region      = "eu-west-1"\ndb_password = "{m}"\n', pw()),
    ]
    for name, path, tpl, secret in hard:
        samples.append(_place(f"hard:{name}", path, tpl.format(m=_MARK), secret, "hard"))

    # ── Negatives ─────────────────────────────────────────────────────────────
    cert_body = "\n".join(g.b64(64) for _ in range(14))
    b64_text = base64.b64encode(("CloudAudit sample configuration notes. " * 4).encode()).decode()
    negatives: List[Tuple[str, str, str]] = [
        ("placeholders-env", ".env.example",
         "API_KEY=your_api_key_here\nDB_PASSWORD=changeme\nSECRET_KEY=<generate-me>\nTOKEN=xxxxxxxxxxxxxxxxxxxx\nJWT_SECRET=replace-this-value\n"),
        ("placeholders-prod-path", "config/defaults.env",
         "API_KEY=your_api_key_here\nDB_PASSWORD=\nSECRET_KEY=${SECRET_KEY}\nSMTP_PASSWORD=$SMTP_PASSWORD\nAUTH_TOKEN={{ auth_token }}\n"),
        ("env-references-code", "app/settings.py",
         'import os\nSECRET_KEY = os.environ["SECRET_KEY"]\nDB_PASSWORD = os.getenv("DB_PASSWORD", "")\nAPI_TOKEN = config.get("api_token")\npassword = getpass.getpass()\n'),
        ("js-references", "src/auth.js",
         "const token = req.headers.authorization;\nconst password = form.password.value;\nconst apiKey = process.env.API_KEY;\nconst secret = props.clientSecret;\nlet accessToken = null;\n"),
        ("config-metadata-keys", "config/auth.yml",
         "auth:\n  token_url: https://login.acme.io/oauth/token\n  token_ttl: 3600\n  password_min_length: 12\n  password_policy: strong\n  secret_name: prod/app/database\n  key_id: alias/app-signing\n  auth_method: oidc\n  client_id: web-portal-7731\n"),
        ("i18n-labels", "locales/fr.json",
         '{\n  "password": "Mot de passe",\n  "token": "Jeton",\n  "secret": "Secret",\n  "api_key": "Clé API",\n  "password_hint": "Au moins douze caractères",\n  "secret": "Keep it secret, keep it safe 24/7!",\n  "password_rule": "At least 12 characters & 1 symbol"\n}\n'),
        ("uuids", "data/ids.yaml",
         "tenants:\n" + "".join(f"  - id: {g.uuid()}\n" for _ in range(8))),
        ("git-shas", "RELEASES.txt",
         "".join(f"{g.hex(40)} release {i}.{i + 1}.0\n" for i in range(8))),
        ("sha256-checksums", "dist/SHA256SUMS",
         "".join(f"{g.hex(64)}  app-{i}.tar.gz\n" for i in range(6))),
        ("lockfile", "web/package-lock.json",
         json.dumps({"packages": {f"node_modules/p{i}": {"version": f"1.{i}.0", "integrity": "sha512-" + g.b64(86) + "=="} for i in range(12)}}, indent=2)),
        ("sri-html", "public/index.html",
         f'<link rel="stylesheet" href="/a.css" integrity="sha384-{g.b64(64)}" crossorigin="anonymous">\n<script src="/a.js" integrity="sha384-{g.b64(64)}"></script>\n'),
        ("data-uri", "public/site.css",
         f".logo {{ background: url(data:image/png;base64,{g.b64(400)}==); }}\n.x {{ color: #1a2b3c; }}\n"),
        ("ssh-public-key", "home/.ssh/authorized_keys",
         f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ{g.b64(340)} deploy@build-01\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{g.b64(42)} ops@laptop\n"),
        ("x509-certificate", "tls/server.crt",
         f"-----BEGIN CERTIFICATE-----\n{cert_body}\n-----END CERTIFICATE-----\n"),
        ("pgp-public-key", "keys/release.asc",
         f"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{cert_body}\n=AbCd\n-----END PGP PUBLIC KEY BLOCK-----\n"),
        ("requirements", "requirements.txt",
         "aiohttp==3.9.5\ncryptography>=41.0\nrich~=13.7\npyyaml==6.0.1 --hash=sha256:" + g.hex(64) + "\n"),
        ("paths-and-arns", "config/paths.yaml",
         "paths:\n  key_file: /etc/ssl/private/service.key\n  secret_path: /run/secrets/db_password\n  token_file: /var/run/secrets/kubernetes.io/serviceaccount/token\n"
         "aws:\n  role: arn:aws:iam::123456789012:role/app-deploy-role\n  secret_arn: arn:aws:secretsmanager:eu-west-1:123456789012:secret:prod/db-AbCdEf\n"),
        ("aws-docs-example", "docs/setup.md",
         "Configure the CLI:\n\n    aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n    aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
        ("long-identifiers", "src/Handlers.java",
         "public class AuthenticationTokenRefreshRequestHandlerFactory {\n  private static final String DEFAULT_PASSWORD_ENCODER_BEAN_NAME = \"passwordEncoder\";\n  void handleUserAuthenticationTokenFromRequestContext() {}\n}\n"),
        ("sql-schema", "db/schema.sql",
         "CREATE TABLE users (\n  id BIGINT PRIMARY KEY,\n  email VARCHAR(255) NOT NULL,\n  password VARCHAR(255) NOT NULL,\n  api_token CHAR(64),\n  token_expires_at TIMESTAMP\n);\n"),
        ("terraform-references", "infra/rds.tf",
         'resource "aws_db_instance" "main" {\n  username = var.db_username\n  password = var.db_password\n  kms_key_id = aws_kms_key.rds.arn\n}\nvariable "db_password" {\n  type      = string\n  sensitive = true\n}\n'),
        ("k8s-secret-refs", "k8s/deployment.yaml",
         "env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password\n  - name: API_TOKEN\n    valueFrom:\n      secretKeyRef:\n        name: api\n        key: token\n"),
        ("ci-secret-refs", ".github/workflows/deploy.yml",
         "jobs:\n  deploy:\n    steps:\n      - run: ./deploy.sh\n        env:\n          API_TOKEN: ${{ secrets.API_TOKEN }}\n          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n"),
        ("public-identifiers", "web/analytics.js",
         f"const stripePublishable = 'pk_" + f"live_{g.b62(24)}';\nconst gaId = 'G-{g.upper(10)}';\nconst sentryDsn = 'https://{g.hex(32)}@o{g.digits(6)}.ingest.sentry.io/{g.digits(7)}';\n"),
        ("docker-digests", "deploy/images.yaml",
         "".join(f"- image: registry.acme.io/app@sha256:{g.hex(64)}\n" for _ in range(4))),
        ("hashed-assets", "public/manifest.json",
         json.dumps({f"chunk{i}.js": f"/static/chunk{i}.{g.hex(20)}.js" for i in range(6)}, indent=2)),
        ("prose", "docs/security.md",
         "# Password policy\n\nPasswords must be at least twelve characters. Never share your token or secret with anyone.\n"
         "Rotate the API key every ninety days and store the private key in the hardware module.\n"),
        ("form-fields", "templates/login.html",
         '<form>\n  <input type="password" name="password" placeholder="Password">\n  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">\n</form>\n'),
        ("test-vectors-md5", "tests/vectors.json",
         json.dumps({"md5": [g.hex(32) for _ in range(4)], "sha1": [g.hex(40) for _ in range(3)]}, indent=2)),
        ("etags-and-ids", "logs/access.log",
         "".join(f'10.0.0.{i} GET /obj/{g.hex(24)} 200 etag="{g.hex(32)}" req={g.uuid()}\n' for i in range(5))),
        ("base64-text-blob", "config/notes.yaml",
         f"notes:\n  encoded: {b64_text}\n"),
        ("minified-js", "public/app.min.js",
         "!function(e,t){" + ";".join(f"var {g.of(string.ascii_lowercase, 2)}={g.b62(12)!r}" for _ in range(300)) + "}();\n"),
        ("jwt-public-jwks", "public/.well-known/jwks.json",
         json.dumps({"keys": [{"kty": "RSA", "use": "sig", "kid": g.b62(27), "alg": "RS256", "e": "AQAB", "n": g.b62(342)}]}, indent=2)),
        ("timestamps-versions", "CHANGELOG.txt",
         "2026-09-30T10:15:00Z release v3.14.159-rc.2+build.20260930\n2026-10-02T08:00:00Z release v3.15.0\n"),
        ("key-name-traps", "config/cache.yaml",
         "cache_key: user:profile:{id}:v2\nsort_key: created_at#desc\nidempotency_key: " + g.uuid() + "\n"
         "token_type: Bearer\nkeyboard: qwerty-us\nsession_key_prefix: sess_\ncsrf_token_header: X-CSRF-Token\n"
         "api_key_header: X-API-Key\nprimary_key: order_id\npassword_reset_url: https://acme.io/reset\n"
         "public_key: " + g.b64(44) + "\nkey: en-US\nsecret_santa_budget: 25usd\n"),
        ("generated-at-runtime", "app/security.py",
         "import secrets, hashlib\nSECRET_KEY = get_random_secret_key()\ntoken = secrets.token_hex(32)\n"
         "password_digest = hashlib.sha256(raw).hexdigest()\napi_key = settings.API_KEY\n"
         "password = input('Password: ')\nauth_token = self._refresh_token()\n"),
        ("shell-substitution", "scripts/bootstrap.sh",
         "#!/bin/sh\nPASSWORD=$(openssl rand -base64 32)\nTOKEN=$(cat /run/secrets/token)\n"
         'export AWS_SECRET_ACCESS_KEY="$1"\nDB_PASSWORD="${DB_PASSWORD:-}"\nAPI_KEY=`vault kv get -field=key secret/app`\n'),
        ("dummy-values", "tests/conftest.py",
         'password = "password123"\ntoken = "abc123"\nsecret = "s3cr3t"\napi_key = "test"\nDB_PASSWORD = "postgres"\n'),
        ("openapi-schema", "api/openapi.yaml",
         "components:\n  schemas:\n    Login:\n      properties:\n        password:\n          type: string\n          format: password\n"
         "          minLength: 12\n        token:\n          type: string\n          description: Opaque bearer token\n"),
    ]
    for name, path, content in negatives:
        samples.append(Sample(f"negative:{name}", path, content, frozenset(), "negative"))

    # ── Hold-out set ──────────────────────────────────────────────────────────
    # Written AFTER the rules were tuned on everything above, and scored once
    # before any further change (result recorded in docs/detection-algorithms.md).
    # Use a separate generator so adding cases here never shifts the values above.
    h = _Gen(seed + 7919)
    hpw = h.password
    holdout_pos: List[Tuple[str, str, str, str]] = [
        ("npmrc-token",         "home/.npmrc",              "//registry.npmjs.org/:_authToken={m}\n", "np" + "m_" + h.b62(36)),
        ("dotted-property",     "conf/security.properties", "jwt.issuer=acme\njwt.secret={m}\n", h.b64(32)),
        ("ansible-vars",        "group_vars/prod.yml",      'vault_db_user: app\nvault_db_password: "{m}"\n', hpw()),
        ("helm-admin-password", "charts/values-prod.yaml",  "grafana:\n  adminUser: admin\n  adminPassword: {m}\n", hpw()),
        ("requests-auth-tuple", "jobs/export.py",           'resp = requests.get(URL, auth=("svc-export", "{m}"))\n', hpw()),
        ("sshpass-inline",      "ops/push.sh",              "#!/bin/sh\nsshpass -p '{m}' ssh deploy@10.1.2.3 uptime\n", hpw()),
        ("lowercase-env",       "mail/.env",                "smtp_host=mail.acme.io\nsmtp_pass={m}\n", hpw()),
        ("makefile-assign",     "Makefile",                 "IMAGE := acme/app\nDOCKER_PASSWORD := {m}\n", hpw()),
        ("minified-json",       "cfg/services.json",        '[{{"name":"db","port":5432}},{{"name":"queue","secret":"{m}"}}]\n', h.b62(24)),
        ("go-struct-literal",   "cmd/server/main.go",       'cfg := Config{{\n\tUser:     "app",\n\tPassword: "{m}",\n}}\n', hpw()),
        ("powershell-secure",   "deploy/setup.ps1",         '$sec = ConvertTo-SecureString "{m}" -AsPlainText -Force\n', hpw()),
        ("ini-section-key",     "etc/replication.cnf",      "[client]\nuser=repl\npassword={m}\n", hpw()),
    ]
    for name, path, tpl, secret in holdout_pos:
        samples.append(_place(f"holdout:{name}", path, tpl.format(m=_MARK), secret, "holdout"))

    holdout_neg: List[Tuple[str, str, str]] = [
        ("go-sum", "go.sum",
         "".join(f"github.com/acme/lib{i} v1.{i}.0 h1:{h.b64(43)}=\n" for i in range(6))),
        ("python-hash-table", "tools/verify.py",
         "HASHES = {\n" + "".join(f'    "pkg{i}.whl": "{h.hex(64)}",\n' for i in range(4)) + "}\n"),
        ("source-map", "public/app.js.map",
         '{"version":3,"sources":["a.ts"],"mappings":"' + ";".join(h.of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop,", 40) for _ in range(20)) + '"}\n'),
        ("svg-path", "public/icon.svg",
         '<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15h2v2h-2z"/></svg>\n'),
        ("order-ids-csv", "exports/orders.csv",
         "order_id,amount,currency\n" + "".join(f"{h.b62(16)},{h.digits(3)}.00,EUR\n" for _ in range(8))),
        ("nginx-key-paths", "etc/nginx.conf",
         "ssl_certificate /etc/nginx/tls/fullchain.pem;\nssl_certificate_key /etc/nginx/tls/privkey.pem;\nssl_session_ticket_key /etc/nginx/ticket.key;\n"),
        ("graphql-selection", "web/queries.graphql",
         "query Session {\n  viewer {\n    id\n    token\n    apiKey { id prefix }\n  }\n}\n"),
        ("git-packed-refs", "repo/packed-refs",
         "# pack-refs with: peeled fully-peeled sorted\n" + "".join(f"{h.hex(40)} refs/tags/v1.{i}.0\n" for i in range(5))),
        ("crypto-addresses", "docs/donate.md",
         f"Donations: `1{h.of('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', 33)}`\n"),
        ("pagination-cursor", "docs/api-example.json",
         '{\n  "items": [],\n  "next_page_token": "' + h.b64(48) + '"\n}\n'),
        ("css-modules", "public/main.css",
         "".join(f".Button_root__{h.b62(5)} {{ color: #333; }}\n.Card_title__{h.b62(5)} {{ margin: 0; }}\n" for _ in range(4))),
        ("k8s-configmap", "k8s/configmap.yaml",
         "kind: ConfigMap\ndata:\n  LOG_TOKENIZER: whitespace\n  AUTH_MODE: oidc\n  KEY_ROTATION_DAYS: \"90\"\n  PASSWORD_MIN_LENGTH: \"14\"\n"),
    ]
    for name, path, content in holdout_neg:
        samples.append(Sample(f"holdout-negative:{name}", path, content, frozenset(), "negative"))
    return samples


# ── Scoring ────────────────────────────────────────────────────────────────────

def is_secret_class(f: Finding) -> bool:
    """A finding that asserts 'this is a secret / credential'."""
    return (
        f.category in (FindingCategory.SECRET_EXPOSURE, FindingCategory.CREDENTIAL_FILE)
        and f.severity != Severity.INFORMATIONAL
    )


@dataclass
class BenchmarkResult:
    mode:     str
    tp:       int = 0
    fp:       int = 0
    fn:       int = 0
    by_kind:  Dict[str, List[int]] = field(default_factory=dict)      # kind → [detected, total]
    missed:   List[str] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> Dict[str, object]:
        return {
            "mode": self.mode, "tp": self.tp, "fp": self.fp, "fn": self.fn,
            "precision": round(self.precision, 4), "recall": round(self.recall, 4), "f1": round(self.f1, 4),
            "recall_by_kind": {k: {"detected": v[0], "total": v[1]} for k, v in sorted(self.by_kind.items())},
            "missed": self.missed, "false_positives": self.false_positives,
        }


def run_benchmark(
    deep: bool = True,
    corpus: Optional[List[Sample]] = None,
    analyzer: Optional[ContentAnalyzer] = None,
) -> BenchmarkResult:
    """
    Score the pipeline on the corpus.

    ``deep=True``  — the full pipeline (rules + local intelligence + classified entropy)
    ``deep=False`` — the pattern rules alone
    """
    corpus = corpus if corpus is not None else build_corpus()
    analyzer = analyzer or ContentAnalyzer()
    result = BenchmarkResult(mode="full pipeline" if deep else "pattern rules only")

    for s in corpus:
        ft = FileClassifier.classify(s.path)
        findings = analyzer.analyse(s.content, f"https://benchmark.invalid/{s.path}", ft, deep=deep)
        LocalIntelligence.calibrate(findings)
        hits = [f for f in findings if is_secret_class(f)]

        if s.secret_lines:
            bucket = result.by_kind.setdefault(s.kind, [0, 0])
            bucket[1] += 1
            if any(f.line_number in s.secret_lines for f in hits):
                result.tp += 1
                bucket[0] += 1
            else:
                result.fn += 1
                result.missed.append(s.name)
        for f in hits:
            if f.line_number not in s.secret_lines:
                result.fp += 1
                result.false_positives.append(f"{s.name} -> {f.rule_name} (line {f.line_number})")
    return result


def format_report(results: List[BenchmarkResult], corpus_size: Tuple[int, int], verbose: bool = False) -> str:
    pos, neg = corpus_size
    lines = [
        f"Corpus: {pos} planted secrets, {neg} secret-free files (synthetic, seed {SEED})",
        "",
        f"  {'Mode':<22} {'Precision':>9} {'Recall':>8} {'F1':>7}   {'TP':>3} {'FP':>3} {'FN':>3}",
        f"  {'-' * 22} {'-' * 9} {'-' * 8} {'-' * 7}   {'-' * 3} {'-' * 3} {'-' * 3}",
    ]
    for r in results:
        lines.append(f"  {r.mode:<22} {r.precision:>8.1%} {r.recall:>8.1%} {r.f1:>7.1%}   {r.tp:>3} {r.fp:>3} {r.fn:>3}")
    full = results[-1]
    lines += ["", f"  Recall by secret type ({full.mode}):"]
    for kind, (hit, total) in sorted(full.by_kind.items()):
        lines.append(f"    {kind:<10} {hit}/{total}")
    if verbose or full.missed or full.false_positives:
        if full.missed:
            lines += ["", "  Missed:"] + [f"    - {m}" for m in full.missed]
        if full.false_positives:
            lines += ["", "  False positives:"] + [f"    - {m}" for m in full.false_positives]
    lines += ["", "  Synthetic corpus — a regression gate and a relative measure, not a real-world accuracy claim."]
    return "\n".join(lines)
