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
  Phase 9: Risk scoring v2
  Phase 10: AI executive summary
  Phase 11: Report output
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import List, Optional

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
from cloudaudit.ai.providers import ProviderChain, build_provider_chain
from cloudaudit.ai.analyzer import AIFileAnalyzer, AnomalyScorer
from cloudaudit.reports.generator import ReportGenerator
from cloudaudit.scanners.archive_extractor import ArchiveExtractor
from cloudaudit.scanners.container_detector import ContainerDetector
from cloudaudit.scanners.crawler import FileCrawler
from cloudaudit.scanners.file_classifier import FileClassifier
from cloudaudit.scanners.secret_scanner import SecretScanner
from cloudaudit.utils.helpers import human_size, url_filename
from cloudaudit.utils.http_client import HTTPClient

logger = logging.getLogger("cloudaudit.engine")

_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


class AuditEngine:

    def __init__(self, config: AuditConfig, display=None) -> None:
        config.validate()
        self._config    = config
        self._stats     = ScanStats()
        self._display   = display   # PhaseDisplay or None
        self._detector  = ContainerDetector()
        self._crawler   = FileCrawler(config)
        self._secret    = SecretScanner(min_entropy=config.min_entropy)
        self._entropy   = EntropyHunter()
        self._archive   = ArchiveExtractor()
        self._image     = ImageMetaAnalyser()
        self._scorer    = RiskScorer()
        self._deduper   = SecretDeduplicator()
        self._mapper    = ExposureMapper()
        self._misconfig = MisconfigAnalyzer()
        self._provider_chain: Optional[ProviderChain] = None
        self._ai_analyzer: Optional[AIFileAnalyzer] = None
        self._anomaly: Optional[AnomalyScorer] = None

    # ── Entry point ────────────────────────────────────────────────────────────

    async def run(self) -> ScanStats:
        self._init_ai_provider()

        async with HTTPClient(self._config) as http:
            container     = await self._phase_detect(http)
            self._stats.container_info = container

            exposed_files = await self._phase_crawl(http, container)
            self._stats.total_files   = len(exposed_files)
            self._stats.exposed_files = exposed_files

            # Cloud misconfiguration analysis (metadata-level)
            self._phase_misconfig(container, exposed_files)

            await self._phase_analyse(http, exposed_files)

        self._phase_dedup()
        self._phase_score()
        await self._phase_ai_summary()
        return self._stats

    # ── AI initialisation ──────────────────────────────────────────────────────

    def _init_ai_provider(self) -> None:
        try:
            api_key = self._config.resolve_api_key()
            self._provider_chain = build_provider_chain(
                self._config.provider,
                api_key,
                getattr(self._config, "provider_url", None),
                self._config.ollama_url,
                self._config.ollama_model,
            )
            self._ai_analyzer = AIFileAnalyzer(self._provider_chain)
            self._anomaly     = AnomalyScorer(self._provider_chain)
        except Exception as exc:
            logger.warning("AI provider init failed: %s — using heuristic", exc)
            from cloudaudit.ai.providers import ProviderChain
            self._provider_chain = ProviderChain()
            self._ai_analyzer    = AIFileAnalyzer(self._provider_chain)
            self._anomaly        = AnomalyScorer(self._provider_chain)

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
        logger.info("Phase 3-6: Analysing %d files", len(files))
        sem   = asyncio.Semaphore(self._config.max_concurrent)
        tasks = [
            asyncio.create_task(self._analyse_one(http, sem, ef))
            for ef in files
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
                    return

                cl = resp.headers.get("Content-Length")
                if cl and int(cl) > self._config.max_file_size:
                    self._stats.skipped_files += 1
                    return

                content = await resp.text(errors="replace")

                # Deterministic secret scanning
                det_findings = self._secret.scan(content, ef.url, ft)

                # Entropy analysis
                entropy_hits = self._entropy.scan(content, threshold=self._config.min_entropy)
                for hit in entropy_hits:
                    # Convert entropy hits into informational findings if not already caught
                    if not any(f.line_number == hit.line_number for f in det_findings):
                        det_findings.append(Finding(
                            file_url=ef.url,
                            file_name=url_filename(ef.url),
                            file_type=ft,
                            category=FindingCategory.SECRET_EXPOSURE,
                            rule_name="HIGH_ENTROPY_STRING",
                            description=f"High-entropy string detected (entropy={hit.entropy:.2f}) — possible undiscovered secret",
                            severity=Severity.LOW,
                            match=hit.value,
                            context=hit.context,
                            line_number=hit.line_number,
                            recommendation="Review this string — high entropy may indicate an undocumented credential or key.",
                            compliance_refs=["NIST IA-5"],
                            confidence=0.55,
                            scanner="EntropyHunter",
                        ))

                # Register for deduplication
                for f in det_findings:
                    self._deduper.register(f)

                self._stats.findings.extend(det_findings)
                self._stats.scanned_files += 1

                # AI semantic analysis (only for high-value files)
                if (
                    self._ai_analyzer
                    and self._ai_analyzer.should_analyse_with_ai(ef.url, ft)
                    and (det_findings or ft in (FileType.ENVIRONMENT, FileType.CERTIFICATE))
                ):
                    loop = asyncio.get_event_loop()
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
                findings = self._secret.scan(text, f"{ef.url}!/{rel_path}", ft)
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

    # ── Phase 8: Risk scoring ─────────────────────────────────────────────────

    def _phase_score(self) -> None:
        self._stats.findings.sort(
            key=lambda f: _SEV_ORDER.get(f.severity.value, 99)
        )
        if self._stats.container_info:
            self._stats.risk_score = self._scorer.compute(
                self._stats.findings, self._stats.container_info
            )
        logger.info("Risk score: %.1f/10", self._stats.risk_score)

    # ── Phase 9: AI executive summary ────────────────────────────────────────

    async def _phase_ai_summary(self) -> None:
        if not self._provider_chain:
            return
        try:
            import json
            audit_json = json.dumps(self._stats.to_dict(), indent=2, default=str)[:12000]
            loop    = asyncio.get_event_loop()
            resp    = await loop.run_in_executor(
                None,
                self._provider_chain.generate_executive_summary,
                audit_json,
            )
            self._stats.ai_summary = resp.text
            if resp.provider != "heuristic":
                logger.info("AI summary: provider=%s model=%s latency=%dms",
                            resp.provider, resp.model, resp.latency_ms)
        except Exception as exc:
            logger.warning("AI summary failed: %s", exc)
            self._stats.ai_summary = "[Summary generation failed]"

    # ── Report output ──────────────────────────────────────────────────────────

    def write_reports(self) -> List[Path]:
        if not self._config.output_base:
            return []
        base    = Path(self._config.output_base)
        fmt     = self._config.output_format
        written: List[Path] = []

        if fmt in ("json", "all"):
            p = base.with_suffix(".json")
            p.write_text(ReportGenerator.json(self._stats, org=self._config.owner_org), encoding="utf-8")
            written.append(p)
        if fmt in ("html", "all"):
            p = base.with_suffix(".html")
            p.write_text(ReportGenerator.html(self._stats, org=self._config.owner_org), encoding="utf-8")
            written.append(p)
        if fmt in ("markdown", "md", "all"):
            p = base.with_suffix(".md")
            p.write_text(ReportGenerator.markdown(self._stats, org=self._config.owner_org), encoding="utf-8")
            written.append(p)

        return written
