"""Проба сервиса по HTTPS/HTTP: жив ли сервер, не сломан ли сертификат, не парковка ли."""
from __future__ import annotations

import asyncio
import re
import secrets
import ssl
from contextlib import suppress
from dataclasses import dataclass
from typing import Sequence
from urllib.parse import urlsplit

from . import names

PROBE_TIMEOUT = 4.0
BODY_LIMIT = 32 * 1024
USER_AGENT = "Mozilla/5.0 (compatible; domains-check/2.1; +https://github.com/mazixs/domains)"
# RFC 5737 TEST-NET: здесь никогда нет сервера, успешный TLS значит MITM по пути.
CANARY_ADDR = "192.0.2.1"

# Площадки продажи и парковки доменов: редирект туда = домен брошен.
PARKING_HOSTS = (
    "above.com", "afternic.com", "atom.com", "bodis.com", "brandbucket.com", "buydomains.com",
    "dan.com", "domainmarket.com", "hugedomains.com", "parkingcrew.net", "sav.com", "sedo.com",
    "sedoparking.com", "squadhelp.com", "undeveloped.com",
)
_PARKING_TEXT = re.compile(
    r"this domain (is|may be) for sale|buy this domain|domain is parked|parked free"
    r"|domain has expired|домен продается|домен выставлен на продажу|срок регистрации домена истек",
    re.IGNORECASE,
)
# Ответы Cloudflare, когда до origin не достучаться: фронт жив, сервиса за ним нет.
CF_ORIGIN_DOWN = {521: "origin не отвечает", 523: "origin недоступен", 530: "origin не найден"}


@dataclass
class ProbeResult:
    reachable: bool
    detail: str = ""
    broken: str | None = None
    parked: str | None = None


@dataclass
class _Http:
    status: int
    location: str
    body: str


def _tls_problem(exc: ssl.SSLCertVerificationError) -> tuple[str, bool]:
    """(описание, признак заброшенности). Чужое имя в сертификате типично для защитных доменов."""
    msg = (exc.verify_message or str(exc)).lower()
    if "expired" in msg:
        return "TLS-сертификат истек", True
    if "hostname mismatch" in msg or "not valid for" in msg:
        return "сертификат на другое имя", False
    if "self-signed" in msg or "self signed" in msg:
        return "самоподписанный сертификат", False
    return f"TLS: {exc.verify_message or exc}", False


async def _fetch(domain: str, host: str, port: int, ctx: ssl.SSLContext | None, timeout: float) -> _Http:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=domain if ctx else None), timeout,
    )
    try:
        writer.write(
            f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Accept: text/html,*/*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".encode()
        )
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
        body = b""
        with suppress(asyncio.TimeoutError, OSError, asyncio.IncompleteReadError):
            while len(body) < BODY_LIMIT:
                chunk = await asyncio.wait_for(reader.read(BODY_LIMIT - len(body)), 2)
                if not chunk:
                    break
                body += chunk
    finally:
        writer.close()
        with suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 1)

    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise ValueError("не HTTP-ответ")
    location = next((ln.split(":", 1)[1].strip() for ln in lines[1:] if ln.lower().startswith("location:")), "")
    return _Http(int(parts[1]), location, body.decode("utf-8", "replace"))


def _parking(resp: _Http) -> str | None:
    target = urlsplit(resp.location).hostname or ""
    if target and any(names.is_within(target.lower(), h) for h in PARKING_HOSTS):
        return f"редирект на площадку продажи доменов {target}"
    m = _PARKING_TEXT.search(resp.body.replace("\u0451", "\u0435"))
    if m:
        return f'страница парковки ("{m.group(0)}")'
    return None


def _describe(scheme: str, resp: _Http) -> str:
    text = f"{scheme} {resp.status}"
    if resp.location:
        text += f" -> {resp.location[:80]}"
    return text


def _summarize(scheme: str, resp: _Http, tls: tuple[str, bool] | None) -> ProbeResult:
    detail = _describe(scheme, resp)
    broken = None
    if tls:
        detail += f" ({tls[0]})"
        broken = tls[0] if tls[1] else None
    if broken is None and resp.status in CF_ORIGIN_DOWN:
        broken = f"Cloudflare: {CF_ORIGIN_DOWN[resp.status]} (HTTP {resp.status})"
    return ProbeResult(True, detail, broken, _parking(resp))


_UNREACHABLE = (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError, ssl.SSLEOFError, ssl.SSLZeroReturnError, ValueError)


class Prober:
    """HTTPS с проверкой сертификата, при ошибке сертификата повтор без проверки, затем HTTP:80."""

    def __init__(self, timeout: float = PROBE_TIMEOUT):
        self.timeout = timeout
        self._verified = ssl.create_default_context()
        self._insecure = ssl.create_default_context()
        self._insecure.check_hostname = False
        self._insecure.verify_mode = ssl.CERT_NONE

    async def canary(self) -> bool:
        """True, если TLS с несуществующим именем на немаршрутизируемый адрес прошел (MITM)."""
        with suppress(*_UNREACHABLE, ssl.SSLError):
            await _fetch(f"{secrets.token_hex(8)}.com", CANARY_ADDR, 443, self._insecure, self.timeout)
            return True
        return False

    async def __call__(self, domain: str, addresses: Sequence[str]) -> ProbeResult:
        host = sorted(addresses, key=lambda a: ":" in a)[0]
        tls = None
        try:
            return _summarize("HTTPS", await _fetch(domain, host, 443, self._verified, self.timeout), None)
        except ssl.SSLCertVerificationError as exc:
            tls = _tls_problem(exc)
        except ssl.SSLError as exc:
            if not isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
                return ProbeResult(True, f"TLS отвечает ({exc.reason or 'handshake'})")
        except _UNREACHABLE:
            pass

        if tls:
            try:
                return _summarize("HTTPS", await _fetch(domain, host, 443, self._insecure, self.timeout), tls)
            except (*_UNREACHABLE, ssl.SSLError):
                return ProbeResult(True, f"HTTPS ({tls[0]})", tls[0] if tls[1] else None)

        try:
            return _summarize("HTTP", await _fetch(domain, host, 80, None, self.timeout), None)
        except _UNREACHABLE:
            return ProbeResult(False, "443 и 80 не отвечают")
