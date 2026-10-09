"""AI provider layer: error classification, retry/fallback, circuit breaker, key handling."""

import json
import os
import tempfile
import unittest
from unittest import mock

from cloudaudit.ai import providers as P
from cloudaudit.ai.analyzer import AIFileAnalyzer
from cloudaudit.config_mgr import key_manager as K
from cloudaudit.core.exceptions import ProviderAuthError, ProviderError, ProviderQuotaError
from cloudaudit.core.models import FileType


class HTTPErr(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status_code = status


class Scripted(P.AIProvider):
    """Provider whose per-call behaviour is scripted: exceptions are raised, strings returned."""

    name = "scripted"

    def __init__(self, script, models=("m1", "m2", "m3")):
        self.script = list(script)
        self.models = list(models)
        self.calls = []
        self.slept = []
        self._sleep = self.slept.append

    def _candidate_models(self):
        return self.models

    def _call(self, model, prompt, max_tokens):
        self.calls.append((model, max_tokens))
        step = self.script.pop(0) if self.script else "ok " * 100
        if isinstance(step, Exception):
            raise step
        if isinstance(step, P.AIResponse):
            return step
        return P.AIResponse(text=step, provider=self.name, model=model)


class ClassifyTests(unittest.TestCase):
    def kind(self, status, msg):
        return P.classify_error(HTTPErr(status, msg)).kind

    def test_categories(self):
        self.assertEqual(self.kind(400, "API key not valid. Please pass a valid API key. [API_KEY_INVALID]"), P.AUTH)
        self.assertEqual(self.kind(401, "Incorrect API key provided"), P.AUTH)
        self.assertEqual(self.kind(429, "You exceeded your current quota ... insufficient_quota"), P.QUOTA)
        self.assertEqual(self.kind(402, "Insufficient Balance"), P.QUOTA)
        self.assertEqual(self.kind(429, "RESOURCE_EXHAUSTED: quota exceeded for gemini-2.5-pro"), P.RATE_LIMIT)
        self.assertEqual(self.kind(404, "models/gemini-1.5-flash is not found for API version v1beta"), P.MODEL)
        self.assertEqual(self.kind(403, "PERMISSION_DENIED: Generative Language API has not been used in project"), P.PERMISSION)
        self.assertEqual(self.kind(400, "Unsupported parameter: 'max_tokens'. Use 'max_completion_tokens' instead."), P.PARAM)
        self.assertEqual(self.kind(400, "This model's maximum context length is 8192 tokens"), P.CONTEXT)
        self.assertEqual(self.kind(503, "The model is overloaded"), P.TRANSIENT)
        self.assertEqual(P.classify_error(OSError("[WinError 10061] connection refused")).kind, P.UNREACHABLE)

    def test_retry_after_parsed(self):
        info = P.classify_error(HTTPErr(429, "Rate limit reached. Please retry in 7.5s."))
        self.assertEqual(info.retry_after, 7.5)

    def test_keys_scrubbed_from_error_text(self):
        key = "AIza" + "SyD3x7Qm2Lk9Pz4Rt6Vw8Yb1Nc5Hf0Jg3Ua7"
        info = P.classify_error(HTTPErr(400, f"GET https://x/v1beta/models?key={key} failed for {key}"))
        self.assertNotIn(key, info.message)
        self.assertNotIn(key[6:], info.message)
        sk = "sk-" + "proj-" + "A" * 30
        self.assertNotIn("A" * 20, P.scrub_secrets(f"Incorrect API key provided: {sk}"))


class RetryFallbackTests(unittest.TestCase):
    def test_rate_limit_retries_then_succeeds(self):
        p = Scripted([HTTPErr(429, "rate limit, retry in 2s"), "fine " * 20])
        self.assertTrue(p.complete("x").ok)
        self.assertEqual([m for m, _ in p.calls], ["m1", "m1"])
        self.assertEqual(p.slept, [2.0])

    def test_model_not_found_moves_to_next_model_and_is_remembered(self):
        p = Scripted([HTTPErr(404, "model not found"), "fine " * 20, "again " * 20])
        self.assertEqual(p.complete("x").model, "m2")
        self.assertEqual(p.complete("y").model, "m2")           # no second trip through m1
        self.assertEqual([m for m, _ in p.calls], ["m1", "m2", "m2"])

    def test_zero_quota_model_falls_through_to_next(self):
        rl = HTTPErr(429, "RESOURCE_EXHAUSTED limit: 0")
        p = Scripted([rl, rl, rl, "fine " * 20])
        self.assertEqual(p.complete("x").model, "m2")

    def test_auth_error_is_not_retried(self):
        p = Scripted([HTTPErr(401, "invalid api key")])
        with self.assertRaises(ProviderAuthError):
            p.complete("x")
        self.assertEqual(len(p.calls), 1)

    def test_quota_raises_quota_error(self):
        p = Scripted([HTTPErr(429, "insufficient_quota")])
        with self.assertRaises(ProviderQuotaError):
            p.complete("x")

    def test_truncated_empty_reply_retries_with_bigger_budget(self):
        empty = P.AIResponse(text="", provider="scripted", model="m1", truncated=True)
        p = Scripted([empty, "fine " * 20])
        self.assertTrue(p.complete("x", max_tokens=500).ok)
        self.assertEqual(p.calls, [("m1", 500), ("m1", 2000)])

    def test_all_models_failing_raises_provider_error(self):
        p = Scripted([HTTPErr(404, "model not found")] * 3)
        with self.assertRaises(ProviderError):
            p.complete("x")


class ChainTests(unittest.TestCase):
    AUDIT = json.dumps({
        "container": {"container_name": "acme-assets", "container_type": "AWS S3", "is_public": True},
        "scanned_files": 4, "total_files": 5, "risk_score": 8.7,
        "findings": [{
            "rule_name": "AWS_ACCESS_KEY", "severity": "Critical", "category": "Secret Exposure",
            "file_name": ".env", "file_url": "https://x/.env", "confidence": 0.9,
            "description": "AWS Access Key ID", "compliance_refs": ["NIST IA-5"], "scanner": "SecretScanner",
        }],
    })

    def test_no_provider_gives_local_summary(self):
        resp = P.ProviderChain().generate_executive_summary(self.AUDIT)
        self.assertEqual(resp.provider, "heuristic")
        self.assertIn("acme-assets", resp.text)
        self.assertIn("1 finding", resp.text)

    def test_bad_key_disables_remote_and_still_summarises(self):
        p = Scripted([HTTPErr(401, "invalid api key")] * 5)
        chain = P.ProviderChain(p)
        resp = chain.generate_executive_summary(self.AUDIT)       # must not raise
        self.assertEqual(resp.provider, "heuristic")
        self.assertFalse(chain.has_remote)
        self.assertIn("disabled", chain.status)
        chain.analyse_file_content("a", "b", "c")
        self.assertEqual(len(p.calls), 1)                          # breaker: never called again

    def test_consecutive_failures_trip_breaker(self):
        p = Scripted([HTTPErr(500, "internal server error")] * 100, models=("m1",))
        chain = P.ProviderChain(p)
        for _ in range(5):
            chain.analyse_file_content("a", "b", "c")
        self.assertFalse(chain.has_remote)
        self.assertEqual(len(p.calls), 3 * (P.MAX_RETRIES + 1))

    def test_good_remote_summary_is_used(self):
        chain = P.ProviderChain(Scripted(["Remote summary paragraph. " * 20]))
        self.assertEqual(chain.generate_executive_summary(self.AUDIT).provider, "scripted")

    def test_too_short_remote_summary_falls_back(self):
        chain = P.ProviderChain(Scripted(["ok"]))
        self.assertEqual(chain.generate_executive_summary(self.AUDIT).provider, "heuristic")

    def test_truncated_json_no_longer_breaks_fallback(self):
        # Regression: audit JSON used to be cut mid-document before the fallback parsed it.
        big = json.loads(self.AUDIT)
        big["findings"] = big["findings"] * 400
        digest = P.compact_audit_json(json.dumps(big), max_chars=3000)
        parsed = json.loads(digest)                                 # valid JSON
        self.assertEqual(parsed["total_findings"], 400)
        self.assertGreater(parsed["findings_omitted"], 0)
        self.assertLess(len(digest), 4500)

    def test_factory(self):
        self.assertFalse(P.build_provider_chain(None, None).has_remote)
        with self.assertRaises(ProviderAuthError):
            P.build_provider_chain("gemini", None)
        with self.assertRaises(ProviderError):
            P.build_provider_chain("nope", "k")
        with self.assertRaises(ProviderError):
            P.build_provider_chain("custom", "k")                   # no --provider-url


class GeminiRankingTests(unittest.TestCase):
    def test_ranking(self):
        ranked = P.rank_gemini_models([
            "models/gemini-2.5-pro", "models/gemini-2.5-flash", "models/gemini-2.5-flash-preview-tts",
            "models/gemini-3-pro-preview", "models/embedding-001", "models/gemma-3-27b-it",
            "models/gemini-2.0-flash", "models/gemini-2.5-flash-image",
        ])
        self.assertEqual(ranked[:2], ["gemini-2.5-flash", "gemini-2.5-pro"])
        self.assertEqual(ranked[-1], "gemini-3-pro-preview")        # previews after stable
        for bad in ("tts", "embedding", "gemma", "image"):
            self.assertFalse(any(bad in m for m in ranked))


class JsonExtractionTests(unittest.TestCase):
    def test_variants(self):
        self.assertEqual(P.extract_json('{"a": 1}'), {"a": 1})
        self.assertEqual(P.extract_json('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(P.extract_json('Sure! Here it is:\n{"a": {"b": "}"}}\nHope that helps'), {"a": {"b": "}"}})
        self.assertIsNone(P.extract_json("no json here"))

    def test_ai_findings_parsed_and_redacted(self):
        token = "Zx9" + "Qm2Lk8Pz4Rt6Vw1Yb5Nc7Hf0Jg3Ua"
        reply = "```json\n" + json.dumps({"findings": [
            {"type": "internal hostname", "description": f"host db01 with token {token}", "severity": "HIGH",
             "confidence": 85, "line_hint": "line 12", "recommendation": "fix"},
            "garbage",
        ]}) + "\n```"
        out = AIFileAnalyzer._parse_ai_response(reply, "https://x/app.yml", FileType.CONFIG, "p", "m")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].line_number, 12)
        self.assertLessEqual(out[0].confidence, 0.95)
        self.assertNotIn(token, out[0].description)
        self.assertEqual(out[0].category.value, "Infrastructure Information")


class KeyManagerTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(K.normalize_api_key('  "AIzaXYZ"\n'), "AIzaXYZ")
        self.assertEqual(K.normalize_api_key("export GEMINI_API_KEY='AIzaXYZ'"), "AIzaXYZ")
        self.assertEqual(K.normalize_api_key("Bearer sk-abc​"), "sk-abc")
        self.assertEqual(K.normalize_api_key(None), "")

    def test_modern_key_formats_accepted(self):
        proj = "sk-" + "proj-" + "aB3_x-" * 12
        self.assertEqual(K.validate_key_format("openai", proj), (True, ""))       # '-' and '_' used to be rejected
        self.assertTrue(K.validate_key_format("gemini", "AQ." + "Ab1_" * 10)[0])
        self.assertTrue(K.validate_key_format("anthropic", "sk-" + "ant-" + "api03-" + "x" * 40)[0])

    def test_provider_mixup_detected(self):
        ok, hint = K.validate_key_format("openai", "sk-" + "ant-" + "x" * 40)
        self.assertFalse(ok)
        self.assertIn("--provider claude", hint)
        self.assertEqual(K.detect_provider_from_key("AIza" + "x" * 35), "gemini")
        self.assertIsNone(K.detect_provider_from_key("sk-" + "x" * 40))

    def test_store_roundtrip_alias_and_corruption_safety(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(K, "get_config_dir", lambda: K.Path(tmp)):
            store = K.SecureKeyStore()
            self.assertTrue(store.save("Anthropic", "  sk-ant-abc123  "))
            self.assertTrue(store.save("gemini", "AIzaKEY"))
            self.assertEqual(store.get("claude"), "sk-ant-abc123")
            self.assertEqual(sorted(store.list_configured()), ["claude", "gemini"])

            # Corrupt the store: saving another key must not silently wipe it.
            K.get_config_path().write_bytes(b"not-a-fernet-token")
            self.assertEqual(store.load_all(), {})
            self.assertTrue(store.save("openai", "sk-new"))
            self.assertTrue(any(n.startswith("config.enc.unreadable-") for n in os.listdir(tmp)))
            self.assertEqual(store.get("openai"), "sk-new")
            self.assertTrue(store.remove("openai"))
            self.assertIsNone(store.get("openai"))

    def test_resolution_order(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(K, "get_config_dir", lambda: K.Path(tmp)):
            env = {k: v for k, v in os.environ.items() if not k.endswith("_API_KEY")}
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(K.resolve_api_key("gemini", None, env_file=os.path.join(tmp, "none")), (None, ""))
                K.SecureKeyStore().save("gemini", "from-store")
                self.assertEqual(K.resolve_api_key("gemini", None, env_file=os.path.join(tmp, "none"))[0], "from-store")
                envf = os.path.join(tmp, ".cloudaudit.env")
                with open(envf, "w") as fh:
                    fh.write("# comment\nGEMINI_API_KEY='from-file'\n")
                self.assertEqual(K.resolve_api_key("gemini", None, env_file=envf)[0], "from-file")
                os.environ["GOOGLE_API_KEY"] = " from-alt-env "
                self.assertEqual(K.resolve_api_key("gemini", None, env_file=envf)[0], "from-alt-env")
                self.assertEqual(K.resolve_api_key("gemini", "explicit", env_file=envf), ("explicit", "--api-key"))

    def test_live_validation_distinguishes_outcomes(self):
        def fake_chain(result):
            remote = mock.Mock()
            remote.check_key.return_value = result
            return mock.Mock(_remote=remote)

        for status, expect_ok in (("valid", True), ("quota", True), ("invalid", False), ("unverified", False)):
            with mock.patch("cloudaudit.ai.providers.build_provider_chain",
                            return_value=fake_chain({"status": status, "model": "m", "error": "e"})):
                ok, msg = K.validate_key_live("openai", "sk-x")
                self.assertEqual(ok, expect_ok, status)
                if status == "unverified":
                    self.assertIn("does not mean it is invalid", msg)


if __name__ == "__main__":
    unittest.main()
