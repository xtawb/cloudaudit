"""
cloudaudit — Main Audit Engine v2.0

Orchestrates all audit phases:
  Phase 0: Ownership gate
  Phase 1: Container detection
  Phase 2: Recursive file crawl
  Phase 3: Concurrent content analysis (deterministic + entropy)
  Phase 4: AI semantic file analysis (high-value files)
  Phase 5: Archive extraction + recursive scan
  Phase 6: Image EXIF metadata extraction
  Phase 7: Duplicate / reuse detection
  Phase 8: Cloud misconfiguration analysis
  Phase 9: Local intelligence — calibration, aggregation, correlation
  Phase 10: Risk scoring v3 + file risk ranking
  Phase 11: Executive summary (AI provider, or the local engine)
  Phase 12: Report output
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from cloudaudit.core.config import AuditConfig
from cloudaudit.core.exceptions import AuditError, OwnershipError
from cloudaudit.core.models import (
    ContainerInfo, ContainerType, ExposedFile, FileType,
    Finding, FindingCategory, ScanStats, Severity,
)
from cloudaudit.intelligence.image_meta import ImageMetaAnalyser
from cloudaudit.intelligence.risk_scorer import RiskScorer
from cloudaudit.intelligence.advanced import (
    EntropyHunter, SecretDeduplicator, ExposureMapper,
    MisconfigAnalyzer, MisconfigFinding,
)
from cloudaudit.ai.providers import ProviderChain, build_provider_chain, scrub_secrets
from cloudaudit.intelligence.local_ai import (
    LocalIntelligence, aggregate_findings, correlate_findings, is_credential_finding,
    is_noise_file, rank_files,
)
from cloudaudit.ai.analyzer import AIFileAnalyzer, AnomalyScorer
from cloudaudit.core import checkpoint as checkpoint_mod
from cloudaudit.core.constants import CHECKPOINT_SAVE_INTERVAL
from cloudaudit.intelligence.baseline import apply_baseline, load_baseline
from cloudaudit.intelligence.terraform_scanner import TerraformStateScanner
from cloudaudit.reports.generator import ReportGenerator
from cloudaudit.scanners.archive_extractor import ArchiveExtractor
from cloudaudit.scanners.container_detector import ContainerDetector
from cloudaudit.scanners.crawler import FileCrawler
from cloudaudit.scanners.file_classifier import FileClassifier
from cloudaudit.scanners.plugin_loader import discover_plugins, run_plugins
from cloudaudit.scanners.secret_scanner import SecretScanner, load_custom_patterns
from cloudaudit.utils.helpers import human_size, url_filename
from cloudaudit.utils.http_client import HTTPClient

logger = logging.getLogger("cloudaudit.engine")

_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


class AuditEngine:

    def __init__(
        self, config: AuditConfig, display=None,
        on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        config.validate()
        self._config    = config
        self._stats     = ScanStats()
        self._display   = display   # PhaseDisplay or None
        self._on_progress = on_progress  # optional --tui live dashboard callback (v1.2.0)
        self._detector  = ContainerDetector()
        self._crawler   = FileCrawler(config)

        custom_patterns = []
        if config.custom_patterns_path:
            custom_patterns = load_custom_patterns(config.custom_patterns_path)
        self._secret    = SecretScanner(min_entropy=config.min_entropy, custom_patterns=custom_patterns)
        self._terraform = TerraformStateScanner()

        self._entropy   = EntropyHunter()
        self._archive   = ArchiveExtractor()
        self._image     = ImageMetaAnalyser()
        self._scorer    = RiskScorer()
        self._deduper   = SecretDeduplicator()
        self._mapper    = ExposureMapper()
        self._misconfig = MisconfigAnalyzer()
        self._local     = LocalIntelligence()     # offline semantic engine — always on
        self._ai_init_note = ""
        self._provider_chain: Optional[ProviderChain] = None
        self._ai_analyzer: Optional[AIFileAnalyzer] = None
        self._anomaly: Optional[AnomalyScorer] = None

        # Third-party scanner plugins (cloudaudit.scanners entry point group, v1.2.0)
        self._plugins = discover_plugins()

        self._resumed_analysed_urls: set[str] = set()
        self._analysed_urls: set[str] = set()
        self._analysed_since_checkpoint = 0

    # ── Progress reporting (--tui live dashboard) ─────────────────────────────

    def _report_progress(self, **kwargs: Any) -> None:
        if not self._on_progress:
            return
        try:
            self._on_progress(kwargs)
        except Exception:
            pass  # A misbehaving dashboard must never affect the scan itself.

    # ── Entry point ────────────────────────────────────────────────────────────

    async def run(self) -> ScanStats:
        self._init_ai_provider()

        resumed = None
        if self._config.resume_path:
            resumed = checkpoint_mod.load_checkpoint(self._config.resume_path)
            logger.info(
                "Resuming from checkpoint: %d file(s) previously discovered, "
                "%d already analysed, %d finding(s) carried over",
                len(resumed["exposed_files"]), len(resumed["analysed_urls"]), len(resumed["findings"]),
            )
            self._stats.findings.extend(resumed["findings"])
            self._resumed_analysed_urls = resumed["analysed_urls"]

        async with HTTPClient(self._config) as http:
            if resumed and resumed["container"]:
                container = resumed["container"]
            else:
                container = await self._phase_detect(http)
            self._stats.container_info = container
            self._report_progress(phase="Detecting container", container=container.container_type.value)

            if resumed and resumed["crawl_complete"]:
                exposed_files = resumed["exposed_files"]
                self._crawler.seed(exposed_files)
            else:
                exposed_files = await self._phase_crawl(http, container)
            self._stats.total_files   = len(exposed_files)
            self._stats.exposed_files = exposed_files
            self._report_progress(phase="Discovering file inventory", total_files=len(exposed_files))

            # Cloud misconfiguration analysis (metadata-level)
            self._phase_misconfig(container, exposed_files)

            # Optional: enrich AWS S3 findings with real ACL/policy detail (boto3)
            if self._config.aws_acl_check:
                self._phase_aws_acl_check(container)

            self._save_checkpoint(container, crawl_complete=True)

            if self._config.dry_run:
                logger.info("Dry run enabled — skipping content download/analysis for %d file(s)", len(exposed_files))
            else:
                await self._phase_analyse(http, exposed_files)

        self._phase_dedup()
        self._phase_intelligence()
        self._apply_baseline()
        self._apply_min_severity()
        self._phase_score()
        self._report_progress(
            phase="Computing risk score",
            scanned_files=self._stats.scanned_files,
            risk_score=self._stats.risk_score,
            severity_counts=self._severity_counts(),
        )
        self._compute_trend()
        if not self._config.dry_run:
            await self._phase_ai_summary()
        self._report_progress(phase="Audit complete")
        return self._stats

    def _severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self._stats.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    # ── Exposure trend vs. previous scan of this target (v1.2.0) ──────────────

    def _compute_trend(self) -> None:
        """
        Look up the most recent locally-recorded scan of this same target
        (from ~/.cloudaudit/history.db) and, if found, record a short
        human-readable trend delta on ScanStats.trend_summary — e.g.
        "3 new critical findings since last scan on 2026-08-01, 2 resolved".

        This is a lightweight aggregate-count comparison, not a fingerprint
        diff (see the `cloudaudit diff` subcommand for that) — it exists to
        give the executive summary useful context without requiring the
        user to keep old reports around. Never raises.
        """
        if getattr(self._config, "record_history", True) is False:
            return
        try:
            from cloudaudit.config_mgr.history import HistoryStore
            prev_entries = HistoryStore().list_for_target(self._config.url, limit=1)
        except Exception as exc:
            logger.debug("Trend lookup failed: %s", exc)
            return
        if not prev_entries:
            return

        prev = prev_entries[0]
        cur = self._severity_counts()
        deltas: List[str] = []
        for sev, prev_n in (
            ("Critical", prev.critical), ("High", prev.high),
            ("Medium", prev.medium), ("Low", prev.low),
        ):
            cur_n = cur.get(sev, 0)
            diff = cur_n - prev_n
            if diff > 0:
                deltas.append(f"{diff} new {sev.lower()}")
            elif diff < 0:
                deltas.append(f"{-diff} resolved {sev.lower()}")

        if deltas:
            self._stats.trend_summary = (
                f"Since the previous scan of this target on {prev.timestamp}: "
                + ", ".join(deltas) + "."
            )
        else:
            self._stats.trend_summary = (
                f"No change in finding counts since the previous scan of this target "
                f"on {prev.timestamp}."
            )

    # ── Minimum severity filter ────────────────────────────────────────────────

    def _apply_min_severity(self) -> None:
        """
        Apply --min-severity: findings below the configured threshold are
        dropped from the report. This flag was previously parsed and stored
        on AuditConfig but never actually consulted anywhere.
        """
        try:
            threshold = Severity[self._config.min_severity.upper()]
        except KeyError:
            return
        if threshold == Severity.LOW:
            return  # LOW is the lowest real severity — nothing to filter (INFORMATIONAL findings are rare/synthetic)
        before = len(self._stats.findings)
        self._stats.findings = [
            f for f in self._stats.findings if f.severity.int_value >= threshold.int_value
        ]
        dropped = before - len(self._stats.findings)
        if dropped:
            logger.info("Filtered %d finding(s) below --min-severity=%s", dropped, self._config.min_severity)

    # ── Baseline suppression ──────────────────────────────────────────────────

    def _apply_baseline(self) -> None:
        if not self._config.baseline_path:
            return
        baseline = load_baseline(self._config.baseline_path)
        kept, suppressed = apply_baseline(self._stats.findings, baseline)
        self._stats.findings = kept
        self._stats.suppressed_count = suppressed
        if suppressed:
            logger.info("Suppressed %d finding(s) via baseline %s", suppressed, self._config.baseline_path)

    # ── AWS ACL/policy enrichment ──────────────────────────────────────────────

    def _phase_aws_acl_check(self, container: ContainerInfo) -> None:
        if container.container_type != ContainerType.AWS_S3 or not container.container_name:
            return
        from cloudaudit.intelligence import aws_acl
        if not aws_acl.is_available():
            logger.info("--aws-acl-check requested but boto3 is not installed — skipping.")
            return
        try:
            findings = aws_acl.check_bucket(container.container_name, container.region, container.raw_url)
            self._stats.findings.extend(findings)
            if findings:
                logger.info("AWS ACL/policy check added %d finding(s)", len(findings))
        except Exception as exc:
            logger.warning("AWS ACL/policy check failed: %s", exc)

    # ── Checkpointing ──────────────────────────────────────────────────────────

    def _save_checkpoint(self, container: Optional[ContainerInfo], crawl_complete: bool) -> None:
        if not self._config.checkpoint_path:
            return
        checkpoint_mod.save_checkpoint(
            self._config.checkpoint_path,
            url=self._config.url,
            container=container,
            exposed_files=self._stats.exposed_files,
            analysed_urls=sorted(self._analysed_urls),
            findings=self._stats.findings,
            crawl_complete=crawl_complete,
        )

    # ── AI initialisation ──────────────────────────────────────────────────────

    def _init_ai_provider(self) -> None:
        """
        Build the provider chain. Nothing here can abort the audit: a missing
        key, a missing SDK, a rejected key or an unreachable endpoint all end
        with the local intelligence engine doing the work, and the reason is
        recorded on ``ScanStats.ai_status`` so the user is told once, clearly.
        """
        provider = self._config.provider
        try:
            api_key = self._config.resolve_api_key()
            self._provider_chain = build_provider_chain(
                provider,
                api_key,
                self._config.provider_url,
                self._config.ollama_url,
                self._config.ollama_model,
                model=self._config.ai_model,
            )
        except Exception as exc:
            self._ai_init_note = scrub_secrets(f"{provider} unavailable — {exc}")[:300]
            logger.warning("AI provider %s. Continuing with the local intelligence engine.", self._ai_init_note)
            self._provider_chain = ProviderChain()

        # Verify the credential once, up front — a bad key then costs one
        # request and one warning instead of one failure per scanned file.
        if self._provider_chain.has_remote and not self._config.dry_run:
            check = self._provider_chain.preflight()
            if check.get("status") == "valid":
                logger.info("AI provider %s ready (model: %s)", provider, check.get("model") or "auto")
            elif check.get("status") == "unverified":
                logger.info("AI provider %s could not be verified up front (%s) — will try during the scan.",
                            provider, check.get("error", "")[:120])

        self._ai_analyzer = AIFileAnalyzer(self._provider_chain)
        self._anomaly     = AnomalyScorer(self._provider_chain)

    # ── Phase 1: Container Detection ──────────────────────────────────────────

    async def _phase_detect(self, http: HTTPClient) -> ContainerInfo:
        logger.info("Phase 1: Container detection at %s", self._config.url)
        try:
            resp = await http.get(self._config.url)
            body = await resp.text(errors="replace")
        except Exception as exc:
            raise AuditError(f"Cannot reach target URL: {exc}") from exc

        if resp.status not in (200, 206):
            raise AuditError(
                f"Target returned HTTP {resp.status}. Verify the URL is accessible and owned by your organisation."
            )

        container = self._detector.detect(self._config.url, resp, body)
        logger.info(
            "Container: type=%s name=%s region=%s public=%s",
            container.container_type.value,
            container.container_name or "unknown",
            container.region or "unknown",
            container.is_public,
        )
        return container

    # ── Phase 2: Crawl ────────────────────────────────────────────────────────

    async def _phase_crawl(
        self, http: HTTPClient, container: ContainerInfo
    ) -> List[ExposedFile]:
        logger.info("Phase 2: Crawling (max_depth=%d)", self._config.max_depth)
        files = await self._crawler.crawl(http, self._config.url, container.container_type)
        logger.info("Crawl complete: %d files", len(files))
        return files

    # ── Phase 3: Misconfiguration analysis ───────────────────────────────────

    def _phase_misconfig(
        self, container: ContainerInfo, files: List[ExposedFile]
    ) -> None:
        # Bucket-level checks
        bucket_findings = self._misconfig.analyse_bucket_exposure(
            container.is_public,
            container.container_type.value,
            container.notes,
        )
        # File inventory checks
        inventory_findings = self._misconfig.analyse_file_inventory(
            [ef.key for ef in files]
        )

        for mf in bucket_findings + inventory_findings:
            self._stats.findings.append(Finding(
                file_url=container.raw_url,
                file_name=container.container_name or "container",
                file_type=FileType.OTHER,
                category=FindingCategory.PUBLIC_ACCESS,
                rule_name=mf.name,
                description=mf.description,
                severity=mf.severity,
                match=f"[{container.container_type.value}]",
                recommendation=mf.recommendation,
                compliance_refs=mf.compliance_refs,
                confidence=0.99,
                scanner="MisconfigAnalyzer",
            ))

    # ── Phase 4+5+6: Concurrent analysis ─────────────────────────────────────

    async def _phase_analyse(
        self, http: HTTPClient, files: List[ExposedFile]
    ) -> None:
        pending = [ef for ef in files if ef.url not in self._resumed_analysed_urls]
        skipped_resumed = len(files) - len(pending)
        if skipped_resumed:
            logger.info("Resume: skipping %d already-analysed file(s)", skipped_resumed)

        logger.info("Phase 3-6: Analysing %d files", len(pending))
        sem   = asyncio.Semaphore(self._config.max_concurrent)
        tasks = [
            asyncio.create_task(self._analyse_one(http, sem, ef))
            for ef in pending
        ]
        for coro in asyncio.as_completed(tasks):
            try:
                await coro
            except Exception as exc:
                logger.debug("Analysis task error: %s", exc)

        logger.info(
            "Analysis complete: scanned=%d findings=%d",
            self._stats.scanned_files, len(self._stats.findings),
        )

    async def _analyse_one(
        self, http: HTTPClient, sem: asyncio.Semaphore, ef: ExposedFile
    ) -> None:
        try:
            await self._analyse_one_inner(http, sem, ef)
        finally:
            self._analysed_urls.add(ef.url)
            self._analysed_since_checkpoint += 1
            if (
                self._config.checkpoint_path
                and self._analysed_since_checkpoint >= CHECKPOINT_SAVE_INTERVAL
            ):
                self._analysed_since_checkpoint = 0
                self._save_checkpoint(self._stats.container_info, crawl_complete=True)

    async def _analyse_one_inner(
        self, http: HTTPClient, sem: asyncio.Semaphore, ef: ExposedFile
    ) -> None:
        async with sem:
            try:
                ft = ef.file_type

                # Image metadata
                if ft == FileType.IMAGE and self._config.deep_metadata:
                    await self._handle_image(http, ef)
                    return

                # Archive handling
                if ft == FileType.ARCHIVE and self._config.extract_archives:
                    await self._handle_archive(http, ef)
                    return

                if not FileClassifier.is_text_analysable(ft):
                    self._stats.skipped_files += 1
                    return

                if ef.size_bytes and ef.size_bytes > self._config.max_file_size:
                    self._stats.skipped_files += 1
                    return

                resp = await http.get(ef.url)
                if resp.status != 200:
                    resp.release()  # don't leak the connection back to the pool unread
                    return

                cl = resp.headers.get("Content-Length")
                if cl and int(cl) > self._config.max_file_size:
                    self._stats.skipped_files += 1
                    resp.release()
                    return

                content = await resp.text(errors="replace")

                # Deterministic secret scanning
                det_findings = self._secret.scan(content, ef.url, ft)

                # Dedicated Terraform state scanner — walks resources[].instances[].attributes
                # structurally instead of relying only on generic regex/entropy matching.
                if ft == FileType.TERRAFORM and url_filename(ef.url).lower().endswith(
                    (".tfstate", ".tfstate.backup")
                ):
                    tf_findings = self._terraform.scan(content, ef.url)
                    for tf in tf_findings:
                        self._deduper.register(tf)
                    det_findings.extend(tf_findings)

                # Third-party scanner plugins (cloudaudit.scanners entry points)
                if self._plugins:
                    file_meta = {"url": ef.url, "file_name": url_filename(ef.url), "file_type": ft}
                    plugin_findings = run_plugins(self._plugins, content, file_meta)
                    for pf in plugin_findings:
                        self._deduper.register(pf)
                    det_findings.extend(plugin_findings)

                # Local intelligence: semantic key/value analysis, config audit,
                # JWT inspection. Offline, always on — no API key involved.
                det_findings.extend(self._local.analyse_file(content, ef.url, ft, det_findings))

                # Entropy analysis, filtered by the statistical token classifier so
                # hashes, UUIDs, identifiers and lockfile noise are not reported.
                det_findings.extend(self._entropy_findings(content, ef.url, ft, det_findings))

                # Register for deduplication
                for f in det_findings:
                    self._deduper.register(f)

                self._stats.findings.extend(det_findings)
                self._stats.scanned_files += 1
                self._report_progress(
                    phase="Analysing file contents",
                    scanned_files=self._stats.scanned_files,
                    total_files=self._stats.total_files,
                    severity_counts=self._severity_counts(),
                )

                # AI semantic analysis (only for high-value files)
                if (
                    self._ai_analyzer
                    and self._ai_analyzer.should_analyse_with_ai(ef.url, ft)
                    and (det_findings or ft in (FileType.ENVIRONMENT, FileType.CERTIFICATE, FileType.CONFIG))
                ):
                    loop = asyncio.get_running_loop()
                    ai_findings = await loop.run_in_executor(
                        None,
                        self._ai_analyzer.analyse,
                        content, ef.url, ft, det_findings,
                    )
                    for af in ai_findings:
                        self._stats.findings.append(af.to_finding())

                if det_findings:
                    logger.info("[!] %s — %d finding(s)", ef.key, len(det_findings))

            except asyncio.TimeoutError:
                self._stats.errors.append(f"Timeout: {ef.url}")
            except Exception as exc:
                self._stats.errors.append(f"Error: {ef.url} — {exc}")
                logger.debug("Error analysing %s: %s", ef.url, exc)

    def _entropy_findings(
        self, content: str, url: str, ft: FileType, existing: List[Finding]
    ) -> List[Finding]:
        if is_noise_file(url):
            return []
        taken = {f.line_number for f in existing if f.line_number and is_credential_finding(f)}
        out: List[Finding] = []
        for hit in self._entropy.scan(
            content, threshold=self._config.min_entropy, classifier=self._local.classifier
        ):
            if hit.line_number in taken:
                continue
            strong = hit.score >= 0.8
            out.append(Finding(
                file_url=url,
                file_name=url_filename(url),
                file_type=ft,
                category=FindingCategory.SECRET_EXPOSURE,
                rule_name="HIGH_ENTROPY_STRING",
                description=(
                    f"High-entropy string detected (entropy={hit.entropy:.2f}, "
                    f"secret-likelihood {hit.score:.0%}) — possible undiscovered secret"
                ),
                severity=Severity.MEDIUM if strong else Severity.LOW,
                match=hit.value,
                context=hit.context,
                line_number=hit.line_number,
                recommendation="Review this string — high entropy may indicate an undocumented credential or key.",
                compliance_refs=["NIST IA-5"],
                confidence=round(min(0.35 + 0.5 * hit.score, 0.85), 3),
                scanner="EntropyHunter",
                value_hash=hit.value_hash,
            ))
        return out

    async def _handle_image(self, http: HTTPClient, ef: ExposedFile) -> None:
        try:
            raw      = await http.download_bytes(ef.url, self._config.max_file_size)
            findings = self._image.analyse(raw, ef.url)
            self._stats.findings.extend(findings)
            self._stats.scanned_files += 1
        except Exception as exc:
            self._stats.errors.append(f"Image analysis failed: {ef.url}: {exc}")

    async def _handle_archive(self, http: HTTPClient, ef: ExposedFile) -> None:
        logger.info("Extracting archive: %s (%s)", ef.key, human_size(ef.size_bytes))
        try:
            raw     = await http.download_bytes(ef.url, self._config.max_file_size)
            members = self._archive.extract(raw, ef.key, self._config.workspace)
            self._stats.archive_files += 1

            for rel_path, content_bytes in members:
                try:
                    text = content_bytes.decode("utf-8", errors="replace")
                except Exception:
                    continue

                ft       = FileClassifier.classify(rel_path)
                member_url = f"{ef.url}!/{rel_path}"
                findings = self._secret.scan(text, member_url, ft)
                findings.extend(self._local.analyse_file(text, member_url, ft, findings))
                for f in findings:
                    f.from_archive = True
                    f.archive_path = rel_path
                    self._deduper.register(f)
                self._stats.findings.extend(findings)

        except Exception as exc:
            self._stats.errors.append(f"Archive extraction failed: {ef.url}: {exc}")
            logger.debug("Archive error %s: %s", ef.url, exc)

    # ── Phase 7: Deduplication and reuse ─────────────────────────────────────

    def _phase_dedup(self) -> None:
        dups  = self._deduper.get_duplicate_findings()
        reuse = self._deduper.get_reuse_findings(min_files=3)
        self._stats.findings.extend(dups + reuse)

    # ── Phase 9: Local intelligence (run-level) ───────────────────────────────

    def _phase_intelligence(self) -> None:
        """
        Calibrate confidence from context, collapse bulk noise, then correlate
        what is left into compound exposures. Each step is isolated so a bug
        in one can never cost the audit its findings.
        """
        before = len(self._stats.findings)
        try:
            LocalIntelligence.calibrate(self._stats.findings)
        except Exception as exc:
            logger.debug("Calibration skipped: %s", exc)
        try:
            self._stats.findings = aggregate_findings(self._stats.findings)
        except Exception as exc:
            logger.debug("Aggregation skipped: %s", exc)
        try:
            compound = correlate_findings(self._stats.findings)
            self._stats.findings.extend(compound)
            if compound:
                logger.info("Correlation engine identified %d compound exposure(s)", len(compound))
        except Exception as exc:
            logger.debug("Correlation skipped: %s", exc)
        if len(self._stats.findings) != before:
            logger.info("Local intelligence: %d raw finding(s) -> %d after aggregation/correlation",
                        before, len(self._stats.findings))

    # ── Phase 10: Risk scoring ────────────────────────────────────────────────

    def _phase_score(self) -> None:
        self._stats.findings.sort(
            key=lambda f: (_SEV_ORDER.get(f.severity.value, 99), -f.confidence)
        )
        if self._stats.container_info:
            self._stats.risk_score = self._scorer.compute(
                self._stats.findings, self._stats.container_info
            )
        try:
            self._stats.file_risk = rank_files(f.to_dict() for f in self._stats.findings)
        except Exception as exc:
            logger.debug("File risk ranking skipped: %s", exc)
        logger.info("Risk score: %.1f/10", self._stats.risk_score)

    # ── Phase 9: AI executive summary ────────────────────────────────────────

    async def _phase_ai_summary(self) -> None:
        import json
        chain = self._provider_chain or ProviderChain()
        # Full, valid JSON. (This used to be cut to 12,000 characters, which
        # produced invalid JSON for any non-trivial scan: the fallback summary
        # then saw an empty document and reported "0 findings".) Remote
        # providers receive a compact digest built from this; the local
        # engine reads all of it.
        audit_json = json.dumps(self._stats.to_dict(), default=str)
        try:
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(None, chain.generate_executive_summary, audit_json)
        except Exception as exc:
            logger.warning("Executive summary via provider failed (%s) — generating it locally.",
                           scrub_secrets(str(exc))[:200])
            resp = ProviderChain().generate_executive_summary(audit_json)

        self._stats.ai_summary = resp.text
        self._stats.ai_engine  = f"{resp.provider}/{resp.model}"
        status = chain.status
        if self._ai_init_note:
            status = f"{self._ai_init_note}. Local intelligence engine used instead"
        self._stats.ai_status = status
        if resp.provider != "heuristic":
            logger.info("AI summary: provider=%s model=%s latency=%dms",
                        resp.provider, resp.model, resp.latency_ms)

    # ── Report output ──────────────────────────────────────────────────────────

    def write_reports(self) -> List[Path]:
        if not self._config.output_base:
            return []
        return ReportGenerator.write_all(
            self._stats, self._config.output_base, self._config.output_format,
            org=self._config.owner_org,
        )
