"""
cloudaudit — Async HTTP Client

Read-only by design: only GET, HEAD, and OPTIONS are exposed.
PUT and DELETE are intentionally omitted — this is an audit tool,
not a penetration testing framework.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, Optional

import aiohttp

from cloudaudit.core.config import AuditConfig
from cloudaudit.core.exceptions import AuditError

logger = logging.getLogger("cloudaudit.http")

_UA = "CloudAudit-SecurityAuditor/1.0 (Internal Enterprise Posture Tool)"


class HTTPClient:
    """
    Async HTTP client for audit operations.

    Exposes only safe, read-only HTTP methods (GET, HEAD, OPTIONS).
    Write methods are intentionally absent to prevent accidental modification
    of organisation assets.
    """

    def __init__(self, config: AuditConfig) -> None:
        self._config  = config
        self._session: Optional[aiohttp.ClientSession] = None

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def __aenter__(self) -> "HTTPClient":
        connector = aiohttp.TCPConnector(
            limit=self._config.max_concurrent,
            limit_per_host=self._config.max_concurrent,
            ssl=False,   # Many internal S3-compatible endpoints use self-signed certs
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": _UA},
            timeout=aiohttp.ClientTimeout(total=self._config.timeout),
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    # ── Public read-only API ───────────────────────────────────────────────────

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> aiohttp.ClientResponse:
        return await self._request("GET", url, headers=headers, allow_redirects=allow_redirects)

    async def head(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> aiohttp.ClientResponse:
        return await self._request("HEAD", url, headers=headers)

    async def options(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> aiohttp.ClientResponse:
        return await self._request("OPTIONS", url, headers=headers)

    async def download_bytes(self, url: str, max_bytes: int) -> bytes:
        """Stream-download up to max_bytes. Raises if over limit."""
        if self._session is None:
            raise AuditError("HTTPClient not started.")
        chunks: list[bytes] = []
        total = 0
        async with self._session.get(url, headers={"User-Agent": _UA}) as resp:
            if resp.status != 200:
                raise AuditError(f"HTTP {resp.status} fetching {url}")
            async for chunk in resp.content.iter_chunked(65536):
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    raise AuditError(
                        f"File at {url} exceeds download limit ({max_bytes} bytes). Skipping."
                    )
        return b"".join(chunks)

    # ── Private ────────────────────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> aiohttp.ClientResponse:
        if self._session is None:
            raise AuditError("HTTPClient not started. Use async-with.")

        last_exc: Optional[Exception] = None

        for attempt in range(1, self._config.max_retries + 1):
            try:
                resp = await self._session.request(
                    method,
                    url,
                    headers=headers,
                    allow_redirects=allow_redirects,
                )
                await asyncio.sleep(self._config.rate_limit_delay)
                return resp
            except asyncio.TimeoutError as exc:
                last_exc = exc
                logger.debug("Timeout on %s %s (attempt %d)", method, url, attempt)
            except aiohttp.ClientError as exc:
                last_exc = exc
                logger.debug("Client error on %s %s: %s", method, url, exc)

            if attempt < self._config.max_retries:
                await asyncio.sleep(self._config.retry_delay * (2 ** (attempt - 1)))

        raise AuditError(
            f"All {self._config.max_retries} attempts failed for {method} {url}: {last_exc}"
        )
