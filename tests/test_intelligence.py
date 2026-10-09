"""
Local intelligence engine + scanner accuracy tests (no network, no API key).

Every credential-shaped value below is synthetic and assembled from fragments
at runtime, so no complete token literal exists in this file.
"""

import base64
import json
import time
import unittest

from cloudaudit.core.models import ContainerInfo, FileType, Finding, FindingCategory, Severity
from cloudaudit.intelligence import local_ai as L
from cloudaudit.intelligence.advanced import EntropyHunter, MisconfigAnalyzer, SecretDeduplicator
from cloudaudit.intelligence.risk_scorer import RiskScorer
from cloudaudit.scanners.secret_scanner import SecretScanner

AWS_ID     = "AKIA" + "Q7ZP2MXL4RT9VB6N"
AWS_SECRET = "wJq8Lm2Zx9Pk4Rt6" + "Vb1Nc5Hf0Jg3Ua7Yd8Se2Qw+"
RANDOM_32  = "Zx9Qm2Lk8Pz4Rt6V" + "w1Yb5Nc7Hf0Jg3Ua"


def jwt(payload: dict, alg: str = "HS256", sig: str = "c2lnbmF0dXJlX2J5dGVzXzEyMzQ1") -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': alg, 'typ': 'JWT'})}.{enc(payload)}.{sig}"


def rules(findings):
    return {f.rule_name for f in findings}


class PlaceholderTests(unittest.TestCase):
    def test_placeholders(self):
        for v in ("your_api_key_here", "changeme", "<password>", "${DB_PASS}", "{{ secret }}", "xxxxxxxxxxxx",
                  "test1234", "EXAMPLEKEY123", "process.env.TOKEN", "REPLACE_ME", ""):
            self.assertTrue(L.looks_like_placeholder(v), v)

    def test_real_values_are_not_placeholders(self):
        for v in ("Tr0ub4dor&3xQ9", RANDOM_32, AWS_SECRET, "Summer2024!"):
            self.assertFalse(L.looks_like_placeholder(v), v)

    def test_pathological_input_is_fast(self):
        t0 = time.perf_counter()
        L.looks_like_placeholder("1234" * 5000 + "x")
        L.looks_like_placeholder("test" * 5000 + "!")
        self.assertLess(time.perf_counter() - t0, 1.0)


class ClassifierTests(unittest.TestCase):
    def setUp(self):
        self.c = L.TokenClassifier()

    def test_random_tokens_are_secrets(self):
        self.assertTrue(self.c.classify(RANDOM_32).is_secret)
        self.assertTrue(self.c.classify(AWS_SECRET).is_secret)

    def test_benign_shapes(self):
        for tok in ("database_connection_timeout", "550e8400-e29b-41d4-a716-446655440000",
                    "com.example.service.UserController", "/usr/local/share/applications/config",
                    "d41d8cd98f00b204e9800998ecf8427e", "2024-05-01T10:00:00Z", "https://example.org/a/b?c=d",
                    "sha512-" + "Ab1+" * 20, "internationalization", "getUserAuthenticationTokenFromRequest"):
            self.assertIn(self.c.classify(tok).label, ("benign", "placeholder"), tok)

    def test_key_name_semantics(self):
        self.assertEqual(L.key_sensitivity("dbPassword"), 2)
        self.assertEqual(L.key_sensitivity("client-secret"), 2)
        self.assertEqual(L.key_sensitivity("API_KEY"), 2)
        for neutral_or_ref in ("public_key", "password_min_length", "token_url", "max_tokens", "key_id",
                               "secret_name", "author", "primary_key", "keyboard_layout", "password_hash"):
            self.assertLessEqual(L.key_sensitivity(neutral_or_ref), 0, neutral_or_ref)
        # A hex digest is benign on its own but a credible key under a secret-bearing name.
        self.assertEqual(self.c.classify("9f86d081884c7d659a2feaa0c55ad015").label, "benign")
        self.assertNotEqual(self.c.classify("9f86d081884c7d659a2feaa0c55ad015", key_hint="api_key").label, "benign")


class SemanticAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.li = L.LocalIntelligence()

    def test_finds_secrets_no_regex_rule_knows(self):
        content = (
            "service:\n"
            "  dbPassword: Tr0ub4dor&3xQ9\n"                       # unquoted YAML — HARDCODED_PASSWORD needs quotes
            f'  "clientSecret": "{RANDOM_32}",\n'
            "<signingKey>Qm7#pLx92!vRt4zK</signingKey>\n"
        )
        found = [f for f in self.li.analyse_file(content, "https://b/app.yml", FileType.CONFIG, [])
                 if f.rule_name == "SEMANTIC_SECRET_ASSIGNMENT"]
        self.assertEqual(len(found), 3)
        for f in found:
            self.assertTrue(f.match.endswith("***"))
            self.assertNotIn("Tr0ub4dor&3xQ9", f.match + f.description)

    def test_ignores_references_placeholders_and_prose(self):
        content = (
            "password: ${DB_PASSWORD}\n"
            "api_key = os.environ['API_KEY']\n"
            "token = accessToken\n"
            "secret_name: prod/database/credentials\n"
            "password_min_length: 12\n"
            'password: "Mot de passe"\n'
            "token_url: https://auth.example.org/oauth/token\n"
            "api_key: your_api_key_here\n"
            "public_key: " + RANDOM_32 + "\n"
        )
        found = self.li.analyse_file(content, "https://b/settings.yml", FileType.CONFIG, [])
        self.assertEqual([f for f in found if f.rule_name == "SEMANTIC_SECRET_ASSIGNMENT"], [])

    def test_config_auditor(self):
        content = (
            'resource "aws_security_group_rule" "x" {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
            'acl = "public-read"\n'
            "publicly_accessible = true\n"
            "requests.get(url, verify=False)\n"
            '"Action": "*",\n'
            "ssl_protocols TLSv1 TLSv1.1;\n"
            "DEBUG = True\n"
        )
        got = rules(self.li.analyse_file(content, "https://b/main.tf", FileType.TERRAFORM, []))
        for expected in ("OPEN_NETWORK_INGRESS", "PUBLIC_STORAGE_ACL", "PUBLIC_DATABASE_ENDPOINT",
                         "TLS_VERIFICATION_DISABLED", "IAM_WILDCARD_ACTION", "WEAK_CRYPTOGRAPHY",
                         "DEBUG_MODE_ENABLED"):
            self.assertIn(expected, got)

    def test_modern_tls_is_not_flagged(self):
        got = rules(self.li.analyse_file("ssl_protocols TLSv1.2 TLSv1.3;\nmin_tls_version = \"TLS1_2\"\n",
                                         "https://b/nginx.conf", FileType.CONFIG, []))
        self.assertNotIn("WEAK_CRYPTOGRAPHY", got)

    def test_password_hashes_are_redacted(self):
        bcrypt = "$2b$12$" + "N9qo8uLOickgx2ZMRZoMye" + "IjZAgcfl7p92ldGxad68LJZdL17lhWy"
        out = self.li.analyse_file(f"admin:{bcrypt}\n", "https://b/users.txt", FileType.OTHER, [])
        hit = [f for f in out if f.rule_name == "PASSWORD_HASH_EXPOSED"]
        self.assertEqual(len(hit), 1)
        self.assertNotIn(bcrypt[-20:], hit[0].match)

    def test_jwt_context(self):
        now = time.time()
        scanner = SecretScanner(min_entropy=4.5)
        cases = (
            ({"sub": "1", "exp": int(now - 86400)}, Severity.LOW, "expired"),
            ({"sub": "1", "exp": int(now + 86400), "iss": "auth.acme.io"}, Severity.HIGH, "still valid"),
            ({"sub": "1"}, Severity.HIGH, "never expires"),
        )
        for payload, sev, phrase in cases:
            content = f"token = {jwt(payload)}\n"
            det = scanner.scan(content, "https://b/a.txt", FileType.OTHER)
            self.li.analyse_file(content, "https://b/a.txt", FileType.OTHER, det)
            j = [f for f in det if f.rule_name == "JWT_TOKEN"]
            self.assertEqual(len(j), 1, phrase)
            self.assertEqual(j[0].severity, sev, phrase)
            self.assertIn(phrase, j[0].description)
        unsigned = f"t = {jwt({'sub': '1'}, alg='none', sig='')}\n"
        self.assertIn("JWT_UNSIGNED_TOKEN", rules(self.li.analyse_file(unsigned, "https://b/a.txt", FileType.OTHER, [])))

    def test_not_a_jwt(self):
        self.assertIsNone(L.inspect_jwt("eyJub3RfanNvbg.eyJub3RfanNvbg.abc"))


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.s = SecretScanner(min_entropy=4.5)

    def scan(self, text, name="https://b/file.txt"):
        return self.s.scan(text, name, FileType.OTHER)

    def test_typed_tokens(self):
        samples = {
            "STRIPE_SECRET_KEY":  "sk_" + "live_" + "9aK2mQ7xL4pR8tY1wZ6nC3vB",
            "SLACK_TOKEN":        "xox" + "b-" + "2048161234-" + "7Hq2LmN9pRsT4vWx",
            "SENDGRID_API_KEY":   "SG." + "aB3xK9mQ2pL7vR4tY8wZ1n" + "." + "C6dE0fG5hJ2kM8nP4qS7tV1xY3zA9bD6eF0gH5jK2mN",
            "ANTHROPIC_API_KEY":  "sk-" + "ant-" + "api03-" + "aB3xK9mQ2pL7vR4tY8wZ1nC6dE0fG5hJ2kM8nP4qS7tV",
            "OPENAI_API_KEY":     "sk-" + "proj-" + "aB3xK9mQ2pL7vR4tY8wZ1nC6dE0fG5hJ2kM8nP4qS7tV1x",
            "NPM_ACCESS_TOKEN":   "npm_" + "aB3xK9mQ2pL7vR4tY8wZ1nC6dE0fG5hJ2kM8",
            "HUGGINGFACE_TOKEN":  "hf_" + "aB3xK9mQ2pL7vR4tY8wZ1nC6dE0fG5hJ2k",
            "VAULT_TOKEN":        "hvs." + "aB3xK9mQ2pL7vR4tY8wZ1nC6dE0fG5",
            "DIGITALOCEAN_TOKEN": "dop_" + "v1_" + "0a1b2c3d4e5f6071" * 4,
            "GITHUB_PAT":         "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
        }
        for rule, token in samples.items():
            found = self.scan(f"value: {token}\n")
            self.assertIn(rule, rules(found), rule)
            hit = next(f for f in found if f.rule_name == rule)
            self.assertNotIn(token, hit.match + hit.context, rule)      # never stored raw
            self.assertGreaterEqual(hit.confidence, 0.8, rule)

    def test_structured_rules_fire_under_default_entropy(self):
        # Regression: the entropy gate silently disabled these rules entirely.
        self.assertIn("INTERNAL_IP", rules(self.scan("upstream 10.20.30.40:8080;\n")))
        self.assertIn("SSH_CONFIG", rules(self.scan("Host bastion\n  IdentityFile ~/.ssh/id_rsa\n")))
        self.assertNotIn("INTERNAL_IP", rules(self.scan("version 10.999.1.300\n")))

    def test_ssh_rule_no_longer_matches_prose(self):
        self.assertNotIn("SSH_CONFIG", rules(self.scan("Please host your files on a server.\n")))

    def test_env_secret_reports_value_not_name(self):
        f = [x for x in self.scan(f"SERVICE_TOKEN={RANDOM_32}\n") if x.rule_name == "ENV_VARIABLE_SECRET"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].match, RANDOM_32[:6] + "***")              # used to be "SERVIC***"

    def test_placeholders_do_not_fire(self):
        text = ('password = "changeme"\nAPI_KEY=your_api_key_here\napi_key: "xxxxxxxxxxxxxxxxxxxxxxxx"\n'
                "DB_PASSWORD=${DB_PASSWORD}\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                "postgres://user:password@localhost/db\n")
        self.assertEqual(self.scan(text), [])

    def test_specific_rule_wins_over_generic(self):
        found = self.scan(f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}\n")
        self.assertEqual(rules(found), {"AWS_SECRET_KEY"})

    def test_repeated_value_is_one_finding_with_count(self):
        found = self.scan("\n".join(f"key{i} = {AWS_ID}" for i in range(4)))
        aws = [f for f in found if f.rule_name == "AWS_ACCESS_KEY"]
        self.assertEqual(len(aws), 1)
        self.assertEqual(aws[0].occurrences, 4)

    def test_credit_card_requires_luhn(self):
        self.assertIn("CREDIT_CARD", rules(self.scan("card 4539578763621486\n")))
        self.assertNotIn("CREDIT_CARD", rules(self.scan("order 4539578763621487\n")))

    def test_email_noise_filtered(self):
        got = self.scan("icon@2x.png user@example.com real.person@acme-corp.io\n")
        self.assertEqual([f.match for f in got if f.rule_name == "EMAIL_ADDRESS"], ["real.p***"])

    def test_context_never_contains_the_secret(self):
        pw = "Qm7pLx92vRt4zK"
        found = self.scan(f'password = "{pw}"\nmysql://root:{pw}Zz@db.internal:3306/app\n')
        self.assertTrue(found)
        for f in found:
            self.assertNotIn(pw, f.context)

    def test_line_numbers(self):
        found = self.scan("a\nb\n" + f"k = {AWS_ID}\n")
        self.assertEqual(found[0].line_number, 3)


class EntropyTests(unittest.TestCase):
    def test_classifier_filters_noise(self):
        content = (
            f"blob = {RANDOM_32}\n"
            'integrity "sha512-' + "Ab1+" * 20 + '"\n'
            "id: 550e8400-e29b-41d4-a716-446655440000\n"
            "handler = getUserAuthenticationTokenFromRequestContext\n"
        )
        plain = EntropyHunter().scan(content, threshold=3.5)
        smart = EntropyHunter().scan(content, threshold=3.5, classifier=L.TokenClassifier())
        self.assertGreater(len(plain), len(smart))
        self.assertEqual([h.line_number for h in smart], [1])


class DedupTests(unittest.TestCase):
    def test_shared_prefix_is_not_a_duplicate(self):
        # Regression: every JWT ("eyJhbG…") and every AKIA key used to be flagged
        # as the "same secret" because the redacted prefix was hashed.
        s, d = SecretScanner(), SecretDeduplicator()
        a = s.scan("k = AKIA" + "Q7ZP2MXL4RT9VB6N", "https://b/one.env", FileType.ENVIRONMENT)
        b = s.scan("k = AKIA" + "Q7ZP2MXL4RT9VB6M", "https://b/two.env", FileType.ENVIRONMENT)
        self.assertEqual(a[0].match, b[0].match)                       # identical once redacted
        for f in a + b:
            d.register(f)
        self.assertEqual(d.get_duplicate_findings(), [])

    def test_real_duplicate_detected_across_files_only(self):
        s, d = SecretScanner(), SecretDeduplicator()
        for name in ("one.env", "two.env"):
            for f in s.scan(f"k = {AWS_ID}\nagain = {AWS_ID}\n", f"https://b/{name}", FileType.ENVIRONMENT):
                d.register(f)
        self.assertEqual(len(d.get_duplicate_findings()), 1)
        d2 = SecretDeduplicator()
        for f in s.scan(f"k = {AWS_ID}\n", "https://b/one.env", FileType.ENVIRONMENT):
            d2.register(f)
            d2.register(f)
        self.assertEqual(d2.get_duplicate_findings(), [])

    def test_emails_are_not_credential_reuse(self):
        s, d = SecretScanner(), SecretDeduplicator()
        for i in range(5):
            for f in s.scan(f"contact: person{i}@acme-corp.io", f"https://b/{i}.txt", FileType.OTHER):
                d.register(f)
        self.assertEqual(d.get_reuse_findings(min_files=3), [])


def make(rule, sev, url="https://b/.env", cat=FindingCategory.SECRET_EXPOSURE, conf=0.9, match="x***", scanner="SecretScanner"):
    return Finding(file_url=url, file_name=url.rsplit("/", 1)[-1], file_type=FileType.OTHER, category=cat,
                   rule_name=rule, description=rule.title(), severity=sev, match=match, confidence=conf,
                   scanner=scanner, line_number=1)


class RunLevelTests(unittest.TestCase):
    def test_calibration_lowers_non_production_generic_findings(self):
        prod = make("HARDCODED_PASSWORD", Severity.HIGH, "https://b/config/app.py")
        test = make("HARDCODED_PASSWORD", Severity.HIGH, "https://b/tests/fixtures/app.py")
        typed = make("STRIPE_SECRET_KEY", Severity.CRITICAL, "https://b/examples/pay.py")
        L.LocalIntelligence.calibrate([prod, test, typed])
        self.assertEqual((prod.severity, prod.confidence), (Severity.HIGH, 0.9))
        self.assertEqual(test.severity, Severity.MEDIUM)
        self.assertLess(test.confidence, 0.6)
        self.assertEqual(typed.severity, Severity.CRITICAL)             # typed tokens keep severity
        L.LocalIntelligence.calibrate([test])                           # idempotent
        self.assertEqual(test.severity, Severity.MEDIUM)

    def test_aggregation_collapses_bulk_and_escalates_pii(self):
        emails = [make("EMAIL_ADDRESS", Severity.LOW, "https://b/users.csv", FindingCategory.PII_EXPOSURE, 0.7, f"u{i}***")
                  for i in range(600)]
        ips = [make("INTERNAL_IP", Severity.LOW, "https://b/hosts", FindingCategory.INFRASTRUCTURE_INF, 0.7, f"10.0.{i}***")
               for i in range(3)]
        key = make("AWS_ACCESS_KEY", Severity.CRITICAL)
        out = L.aggregate_findings(emails + ips + [key])
        self.assertEqual(len(out), 1 + 3 + 1)
        bulk = next(f for f in out if f.rule_name == "BULK_PII_EXPOSURE")
        self.assertEqual(bulk.severity, Severity.HIGH)
        self.assertIn("600 distinct", bulk.description)

    def test_correlation(self):
        fs = [
            make("AWS_ACCESS_KEY", Severity.CRITICAL), make("AWS_SECRET_KEY", Severity.CRITICAL),
            make("DATABASE_URL", Severity.CRITICAL), make("INTERNAL_IP", Severity.LOW, cat=FindingCategory.INFRASTRUCTURE_INF),
            make("GITHUB_PAT", Severity.CRITICAL, "https://b/ci.yml"), make("SLACK_TOKEN", Severity.HIGH, "https://b/notify.js"),
            make("BULK_PII_EXPOSURE", Severity.HIGH, "https://b/users.csv", FindingCategory.PII_EXPOSURE),
        ]
        got = rules(L.correlate_findings(fs))
        self.assertEqual(got, {
            "COMPOUND_AWS_CREDENTIAL_PAIR", "COMPOUND_DATASTORE_ACCESS_PATH", "COMPOUND_SECRETS_FILE",
            "SYSTEMIC_SECRET_SPRAWL", "COMPOUND_PERSONAL_DATA_WITH_CREDENTIALS",
        })
        self.assertEqual(L.correlate_findings([make("AWS_ACCESS_KEY", Severity.CRITICAL)]), [])

    def test_risk_score(self):
        pub = ContainerInfo(raw_url="https://b/", is_public=True)
        sc = RiskScorer()
        self.assertEqual(sc.compute([], pub), 2.0)
        noise = [make("EMAIL_ADDRESS", Severity.LOW, cat=FindingCategory.PII_EXPOSURE, conf=0.7) for _ in range(2000)]
        self.assertLessEqual(sc.compute(noise, pub), 3.5)               # volume alone is not high risk
        one_key = [make("AWS_ACCESS_KEY", Severity.CRITICAL, conf=0.9)]
        self.assertGreaterEqual(sc.compute(one_key, pub), 8.5)
        guess = [make("HARDCODED_PASSWORD", Severity.CRITICAL, conf=0.25)]
        self.assertLess(sc.compute(guess, pub), sc.compute(one_key, pub))
        pair = one_key + [make("COMPOUND_AWS_CREDENTIAL_PAIR", Severity.CRITICAL, scanner="CorrelationEngine")]
        self.assertGreaterEqual(sc.compute(pair, pub), 9.0)

    def test_inventory_rules_keep_legacy_names(self):
        names = {f.name for f in MisconfigAnalyzer().analyse_file_inventory(
            ["prod/.env", "db/backup.sql.gz", "k8s/secrets.yaml", "home/.ssh/id_ed25519", ".git/config"])}
        self.assertIn(r"SENSITIVE_FILE_EXPOSED:\.env", names)           # unchanged → baselines still match
        for slug in ("database-dump", "secrets-file", "ssh-private-key", "git-metadata"):
            self.assertIn(f"SENSITIVE_FILE_EXPOSED:{slug}", names)


class SummaryTests(unittest.TestCase):
    def scan_dict(self):
        fs = [
            make("PUBLIC_BUCKET_ACCESS", Severity.CRITICAL, "https://b/", FindingCategory.PUBLIC_ACCESS, 0.99, scanner="MisconfigAnalyzer"),
            make("AWS_ACCESS_KEY", Severity.CRITICAL), make("AWS_SECRET_KEY", Severity.CRITICAL),
            make("OPEN_NETWORK_INGRESS", Severity.HIGH, "https://b/main.tf", FindingCategory.COMPLIANCE, 0.85, scanner="LocalIntelligence"),
        ]
        for f in fs:
            f.compliance_refs = ["NIST IA-5", "CIS 2.1"]
        fs += L.correlate_findings(fs)
        return {
            "container": {"container_name": "acme-assets", "container_type": "AWS S3", "is_public": True},
            "scanned_files": 12, "total_files": 15, "risk_score": 9.2,
            "findings": [f.to_dict() for f in fs],
            "trend_summary": "Since the previous scan: 2 new critical.",
        }

    def test_summary_is_data_driven(self):
        text = L.generate_summary(self.scan_dict(), version="1.3.0")
        for needle in ("acme-assets", "**CRITICAL**", "9.2/10", "Compound exposure", "Key Risk Drivers",
                       "Highest-Risk Files", "`.env`", "Prioritised Remediation Plan", "Immediate (0–24 hours)",
                       "CloudTrail", "Compliance Impact", "NIST", "Trend vs. previous scan", "offline"):
            self.assertIn(needle, text)
        self.assertNotIn("Regenerate the Azure", text)                  # only actions for what was found

    def test_empty_and_malformed_input(self):
        self.assertIn("no findings", L.generate_summary({"container": {}, "findings": []}))
        self.assertIn("Executive Summary", L.generate_summary({}))
        self.assertIn("Executive Summary", L.generate_summary({"scan": {"findings": ["junk", 3]}}))

    def test_digest_is_valid_and_carries_no_matches(self):
        d = self.scan_dict()
        d["findings"][1]["match"] = "SENTINEL_MATCH"
        d["findings"][1]["context"] = "SENTINEL_CONTEXT"
        digest = L.build_ai_digest(d, max_chars=2500)
        json.loads(digest)
        self.assertNotIn("SENTINEL", digest)


if __name__ == "__main__":
    unittest.main()
