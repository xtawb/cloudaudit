"""
v1.4.0: shared analysis pipeline, document text extraction, owner-side S3
inventory, the accuracy benchmark, and the accuracy fixes it drove.

Credential-shaped values are synthetic and assembled at runtime.
"""

import asyncio
import io
import unittest
import zipfile
import zlib
from unittest import mock

from cloudaudit.core.config import AuditConfig
from cloudaudit.core.exceptions import AuditError
from cloudaudit.core.models import FileType
from cloudaudit.core.pipeline import ContentAnalyzer
from cloudaudit.intelligence import aws_inventory as inv
from cloudaudit.intelligence import benchmark as bench
from cloudaudit.intelligence import local_ai as L
from cloudaudit.intelligence.advanced import EntropyHunter
from cloudaudit.scanners import document_extractor as docx
from cloudaudit.scanners.file_classifier import FileClassifier
from cloudaudit.scanners.secret_scanner import SecretScanner

PASSWORD = "Korva" + "82!tuQ9z"
RANDOM_32 = "Zx9Qm2Lk8Pz4Rt6V" + "w1Yb5Nc7Hf0Jg3Ua"


def rules(findings):
    return {f.rule_name for f in findings}


def make_zip(parts: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in parts.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_pdf(text: bytes, compress: bool = True) -> bytes:
    content = b"BT /F1 12 Tf 72 720 Td (" + text + b") Tj ET"
    body = zlib.compress(content) if compress else content
    flt = b" /Filter /FlateDecode" if compress else b""
    return (b"%PDF-1.4\n1 0 obj\n<< /Author (Dana Admin) >>\nendobj\n"
            b"2 0 obj\n<< /Length " + str(len(body)).encode() + flt + b" >>\nstream\n" + body +
            b"\nendstream\nendobj\n%%EOF\n")


class DocumentExtractionTests(unittest.TestCase):
    def test_docx_joins_runs_split_by_word(self):
        # Word splits one visible string across several <w:t> runs.
        half = len(PASSWORD) // 2
        xml = ('<w:document><w:body><w:p><w:r><w:t>db_password = </w:t></w:r>'
               f'<w:r><w:t>{PASSWORD[:half]}</w:t></w:r><w:r><w:t>{PASSWORD[half:]}</w:t></w:r></w:p>'
               '<w:p><w:r><w:t>Second paragraph &amp; more</w:t></w:r></w:p></w:body></w:document>')
        core = '<cp:coreProperties><dc:creator>Dana Admin</dc:creator><cp:lastModifiedBy>Sam Ops</cp:lastModifiedBy></cp:coreProperties>'
        doc = docx.extract_text(make_zip({"word/document.xml": xml, "docProps/core.xml": core}), "runbook.docx")
        self.assertIn(f"db_password = {PASSWORD}", doc.text)
        self.assertIn("Second paragraph & more", doc.text)
        self.assertEqual(doc.metadata["creator"], "Dana Admin")
        self.assertEqual(doc.metadata["last_modified_by"], "Sam Ops")

    def test_xlsx_shared_strings_and_data_connections(self):
        shared = f'<sst><si><t>service</t></si><si><t>{RANDOM_32}</t></si></sst>'
        conn = f'<connections><connection><dbPr connection="Server=sql01;Database=app;User Id=sa;Password={PASSWORD};"/></connection></connections>'
        doc = docx.extract_text(make_zip({"xl/sharedStrings.xml": shared, "xl/connections.xml": conn}), "export.xlsx")
        self.assertIn(RANDOM_32, doc.text)
        found = ContentAnalyzer().analyse(doc.text, "https://b/export.xlsx", FileType.DOCUMENT)
        self.assertIn("CONNECTION_STRING_PASSWORD", rules(found))

    def test_pdf_builtin_flate_and_plain(self):
        for compress in (True, False):
            with mock.patch.dict("sys.modules", {"pypdf": None}):       # force the built-in extractor
                doc = docx.extract_text(make_pdf(b"api_token: " + RANDOM_32.encode(), compress), "notes.pdf")
            self.assertEqual(doc.method, "pdf-builtin")
            self.assertIn(f"api_token: {RANDOM_32}", doc.text)
            self.assertEqual(doc.metadata.get("author"), "Dana Admin")

    def test_legacy_binary_strings(self):
        ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 40 + f"password = {PASSWORD}".encode("utf-16-le") + b"\x00\x01\x02"
        doc = docx.extract_text(ole, "old.doc")
        self.assertEqual(doc.method, "ole-strings")
        self.assertIn(f"password = {PASSWORD}", doc.text)

    def test_hostile_input_never_raises(self):
        self.assertFalse(docx.extract_text(b"", "x.pdf").ok)
        self.assertFalse(docx.extract_text(b"PK\x03\x04 not really a zip", "x.docx").ok)
        too_many = make_zip({f"word/x{i}.xml": "a" for i in range(docx.MAX_ZIP_ENTRIES + 1)})
        self.assertFalse(docx.extract_text(too_many, "bomb.docx").ok)
        self.assertFalse(docx.extract_text(b"%PDF-1.7\nstream\n\x00\x01garbage\nendstream", "x.pdf").ok)

    def test_document_types_classified(self):
        for name in ("a.pdf", "b.docx", "c.xlsx", "d.pptx", "e.odt", "f.rtf"):
            self.assertEqual(FileClassifier.classify(name), FileType.DOCUMENT, name)


class PipelineTests(unittest.TestCase):
    def test_deep_adds_semantic_and_config_findings(self):
        content = f"db:\n  password: {PASSWORD}\nverify_ssl: false\n"
        a = ContentAnalyzer()
        shallow = rules(a.analyse(content, "https://b/app.yml", FileType.CONFIG, deep=False))
        deep = rules(a.analyse(content, "https://b/app.yml", FileType.CONFIG, deep=True))
        self.assertEqual(shallow, set())
        self.assertEqual(deep, {"SEMANTIC_SECRET_ASSIGNMENT", "TLS_VERIFICATION_DISABLED"})

    def test_terraform_state_goes_through_structural_scanner(self):
        state = '{"resources":[{"type":"aws_db_instance","name":"main","instances":[{"attributes":{"password":"%s"}}]}]}' % PASSWORD
        found = ContentAnalyzer().analyse(state, "https://b/terraform.tfstate", FileType.TERRAFORM)
        self.assertTrue(any(f.scanner == "TerraformStateScanner" for f in found), rules(found))


class AwsInventoryTests(unittest.TestCase):
    def test_parse_bucket(self):
        self.assertEqual(inv.parse_bucket("s3://acme-assets/exports/2026"), ("acme-assets", "exports/2026", ""))
        self.assertEqual(inv.parse_bucket("https://acme-assets.s3.amazonaws.com/"), ("acme-assets", "", ""))
        self.assertEqual(inv.parse_bucket("https://acme-assets.s3.eu-west-1.amazonaws.com/a/b"), ("acme-assets", "a/b", "eu-west-1"))
        self.assertEqual(inv.parse_bucket("https://acme-assets.s3-us-west-2.amazonaws.com"), ("acme-assets", "", "us-west-2"))
        self.assertEqual(inv.parse_bucket("https://s3.eu-central-1.amazonaws.com/acme.assets/x"), ("acme.assets", "x", "eu-central-1"))
        for bad in ("https://example.com/bucket", "s3://", "s3://UPPER_case", "", "https://s3.amazonaws.com/"):
            self.assertIsNone(inv.parse_bucket(bad), bad)

    def test_object_url(self):
        self.assertEqual(inv.object_url("acme", "eu-west-1", "dir/a b+c.txt"),
                         "https://acme.s3.eu-west-1.amazonaws.com/dir/a%20b%2Bc.txt")
        # Dotted bucket names cannot use the wildcard TLS certificate → path-style.
        self.assertEqual(inv.object_url("acme.assets", "", "k"), "https://s3.us-east-1.amazonaws.com/acme.assets/k")

    class FakeS3:
        def __init__(self, pages, location="eu-west-1", error=None):
            self.pages, self.location, self.error = pages, location, error
            self.calls = []

        def get_bucket_location(self, Bucket):
            self.calls.append("get_bucket_location")
            if self.error:
                raise self.error
            return {"LocationConstraint": self.location}

        def get_paginator(self, name):
            self.calls.append(name)
            outer = self

            class P:
                def paginate(self, **kw):
                    outer.kwargs = kw
                    return iter(outer.pages)
            return P()

    def test_list_bucket_reads_pages_and_skips_folders(self):
        pages = [{"Contents": [{"Key": "a/", "Size": 0}, {"Key": "a/.env", "Size": 120, "ETag": '"abc"'}]},
                 {"Contents": [{"Key": "b.sql", "Size": 9}]}, {}]
        s3 = self.FakeS3(pages, location=None)
        out = inv.list_bucket("acme", "a", client=s3)
        self.assertEqual(out.region, "us-east-1")                       # null location == us-east-1
        self.assertEqual([o["key"] for o in out.objects], ["a/.env", "b.sql"])
        self.assertEqual(out.objects[0]["etag"], "abc")
        self.assertEqual(s3.kwargs["Prefix"], "a")
        self.assertEqual(s3.calls, ["get_bucket_location", "list_objects_v2"])   # read-only calls only
        self.assertFalse(out.truncated)

    def test_list_bucket_cap_and_errors(self):
        pages = [{"Contents": [{"Key": f"k{i}", "Size": 1} for i in range(10)]}]
        out = inv.list_bucket("acme", max_objects=4, client=self.FakeS3(pages))
        self.assertEqual(len(out.objects), 4)
        self.assertTrue(out.truncated)

        denied = Exception("denied")
        denied.response = {"Error": {"Code": "AccessDenied"}}
        with self.assertRaises(AuditError) as ctx:
            inv.list_bucket("acme", client=self.FakeS3([], error=denied))
        self.assertIn("only works on buckets you own", str(ctx.exception))

    def test_engine_keeps_only_anonymously_readable_objects(self):
        from cloudaudit.core.engine import AuditEngine

        class Resp:
            def __init__(self, status, body=""):
                self.status, self._body = status, body

            async def text(self, errors="replace"):
                return self._body

            def release(self):
                pass

        class FakeHTTP:
            def __init__(self):
                self.heads = []

            async def get(self, url):
                return Resp(403, "<Error><Code>AccessDenied</Code></Error>")

            async def head(self, url):
                self.heads.append(url)
                return Resp(200 if url.endswith(("public.env", "open.sql")) else 403)

        inventory = inv.BucketInventory(bucket="acme", region="eu-west-1", objects=[
            {"key": "cfg/public.env", "size": 10, "last_modified": "", "etag": ""},
            {"key": "cfg/private.env", "size": 10, "last_modified": "", "etag": ""},
            {"key": "db/open.sql", "size": 10, "last_modified": "", "etag": ""},
        ])
        cfg = AuditConfig(url="s3://acme", ownership_confirmed=True, owner_org="T", aws_inventory=True,
                          record_history=False, rate_limit_delay=0)
        engine = AuditEngine(cfg)
        http = FakeHTTP()
        with mock.patch.object(inv, "list_bucket", return_value=inventory):
            container, files = asyncio.run(engine._phase_aws_inventory(http))

        self.assertEqual(sorted(f.key for f in files), ["cfg/public.env", "db/open.sql"])
        self.assertEqual(len(http.heads), 3)
        self.assertFalse(container.is_public)                            # listing itself is private
        self.assertEqual(container.container_name, "acme")
        f = [x for x in engine._stats.findings if x.rule_name == "PUBLIC_OBJECTS_IN_UNLISTED_BUCKET"]
        self.assertEqual(len(f), 1)
        self.assertIn("2 of 3", f[0].description)

    def test_s3_url_only_valid_in_inventory_mode(self):
        base = dict(ownership_confirmed=True, owner_org="T")
        AuditConfig(url="s3://acme", aws_inventory=True, **base).validate()
        with self.assertRaises(Exception):
            AuditConfig(url="s3://acme", **base).validate()


class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = bench.build_corpus()
        cls.full = bench.run_benchmark(deep=True, corpus=cls.corpus)
        cls.rules_only = bench.run_benchmark(deep=False, corpus=cls.corpus)

    def test_corpus_is_deterministic_and_well_formed(self):
        again = bench.build_corpus()
        self.assertEqual([s.content for s in self.corpus], [s.content for s in again])
        for s in self.corpus:
            if s.kind != "negative":
                self.assertEqual(len(s.secret_lines), 1, s.name)
        self.assertGreater(sum(1 for s in self.corpus if s.kind == "negative"), 40)

    def test_regression_gate(self):
        self.assertGreaterEqual(self.full.precision, 0.97, self.full.false_positives)
        self.assertGreaterEqual(self.full.recall, 0.95, self.full.missed)

    def test_local_intelligence_is_what_adds_recall(self):
        self.assertGreater(self.full.recall, self.rules_only.recall + 0.25)

    def test_other_seeds_hold_up(self):
        analyzer = ContentAnalyzer()
        for seed in (1, 2, 3):
            r = bench.run_benchmark(deep=True, corpus=bench.build_corpus(seed), analyzer=analyzer)
            self.assertGreaterEqual(r.precision, 0.95, (seed, r.false_positives))
            self.assertGreaterEqual(r.recall, 0.93, (seed, r.missed))


class AccuracyRegressionTests(unittest.TestCase):
    """Each case is a false positive or a miss the benchmark found in v1.3.0."""

    def setUp(self):
        self.a = ContentAnalyzer()

    def secret_rules(self, text, path="config/app.yml"):
        ft = FileClassifier.classify(path)
        return {f.rule_name for f in self.a.analyse(text, f"https://b/{path}", ft) if bench.is_secret_class(f)}

    def test_armored_blocks_are_not_reported_line_by_line(self):
        body = "\n".join((RANDOM_32 * 2)[:64] for _ in range(8))
        cert = f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"
        self.assertEqual(self.secret_rules(cert, "tls/server.crt"), set())
        key = "-----BEGIN RSA " + f"PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n"
        self.assertEqual(self.secret_rules(key, "tls/server.key"), {"PRIVATE_KEY"})

    def test_public_material_is_benign(self):
        c = L.TokenClassifier()
        for tok in ("AAAAB3NzaC1yc2EAAAADAQABAAABAQ" + RANDOM_32 * 4, "pk_" + "live_" + RANDOM_32[:24],
                    "/static/chunk7.3f2a9c1b7d5e6f708192.js", "v3.14.159-rc.2+build.20260930",
                    "/obj/5f2a9c1b7d5e6f7081920a1b", "0x" + "ab12" * 10, "5f2a9c1b7d5e6f7081920a1b"):
            self.assertEqual(c.classify(tok).label, "benign", tok)
        self.assertEqual(c.classify(RANDOM_32, key_hint="public_key").label, "benign")
        self.assertEqual(c.classify(RANDOM_32, key_hint="next_page_token").label, "benign")

    def test_code_and_leetspeak_placeholders(self):
        for v in ("get_random_secret_key()", 'os.getenv("DB_PASSWORD")', "self._token",
                  "s3cr3t", "p@ssw0rd", "t0k3n", "argv[1]"):
            self.assertTrue(L.looks_like_placeholder(v), v)
        self.assertFalse(L.looks_like_placeholder(PASSWORD))
        self.assertEqual(self.secret_rules("SECRET_KEY = get_random_secret_key()\n", "app/settings.py"), set())
        self.assertEqual(self.secret_rules("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"), set())

    def test_labels_and_prose_are_not_secrets(self):
        text = ('{"password": "Mot de passe", "api_key": "Clé API", '
                '"secret": "Keep it secret, keep it safe 24/7!", "token": "Jeton"}\n')
        self.assertEqual(self.secret_rules(text, "locales/fr.json"), set())

    def test_weak_literal_password_in_config_is_found(self):
        self.assertIn("SEMANTIC_SECRET_ASSIGNMENT", self.secret_rules("[ftp]\npassword = hunter42\n", "etc/app.ini"))
        # …but the same shape in source code is a variable reference.
        self.assertEqual(self.secret_rules("password = hunter42\n", "app/x.py"), set())

    def test_entropy_floor_scales_with_length(self):
        # A random 24-char key cannot reach 4.5 bits of Shannon entropy.
        key24 = RANDOM_32[:24]
        hits = SecretScanner(min_entropy=4.5).scan(f'api_key = "{key24}"\n', "https://b/a.py", FileType.PYTHON)
        self.assertIn("GENERIC_API_KEY", rules(hits))
        low = SecretScanner(min_entropy=4.5).scan('api_key = "aaaaaaaabbbbbbbbaaaaaaaa"\n', "https://b/a.py", FileType.PYTHON)
        self.assertNotIn("GENERIC_API_KEY", rules(low))

    def test_short_unnamed_tokens_are_identifiers(self):
        hunter, c = EntropyHunter(), L.TokenClassifier()
        self.assertEqual(hunter.scan(f"order,{RANDOM_32[:16]},42.00\n", 4.5, c), [])
        self.assertEqual(len(hunter.scan(f"# old key was {RANDOM_32}\n", 4.5, c)), 1)
        self.assertEqual(len(hunter.scan(f"api_key: {RANDOM_32[:18]}\n", 4.5, c)), 1)    # named → still reported

    def test_new_rules(self):
        self.assertIn("URL_QUERY_SECRET",
                      self.secret_rules(f"curl 'https://api.acme.io/x?access_token={RANDOM_32}&f=csv'\n", "s.sh"))
        self.assertIn("AUTHORIZATION_HEADER",
                      self.secret_rules(f'HEADERS = {{"Authorization": "Token {"a1b2c3d4" * 5}"}}\n', "t.py"))
        self.assertIn("PLAINTEXT_SECURESTRING",
                      self.secret_rules(f'$s = ConvertTo-SecureString "{PASSWORD}" -AsPlainText -Force\n', "d.ps1"))
        jwk = '{"kty": "oct", "kid": "k1", "k": "%s"}\n' % (RANDOM_32 + "abcdefghijk")
        self.assertIn("JWK_PRIVATE_KEY", self.secret_rules(jwk, "keys/sig.jwk"))
        public_jwk = '{"kty": "RSA", "kid": "%s", "e": "AQAB", "n": "%s"}\n' % (RANDOM_32[:27], RANDOM_32 * 8)
        self.assertEqual(self.secret_rules(public_jwk, "public/jwks.json"), set())

    def test_shell_rule_reports_the_right_line(self):
        found = self.a.analyse(f"#!/bin/sh\necho start\nsshpass -p '{PASSWORD}' ssh ops@10.1.2.3 uptime\n",
                               "https://b/ops/push.sh", FileType.SHELL)
        hit = [f for f in found if f.rule_name == "SHELL_HISTORY_SECRET"]
        self.assertEqual([f.line_number for f in hit], [3])
        self.assertNotIn(PASSWORD, hit[0].match)
        self.assertEqual(self.secret_rules('mysql -u root -p"$DB_PASSWORD" app\n', "s.sh"), set())


if __name__ == "__main__":
    unittest.main()
