"""RDAP: статус домена в реестре (не зарегистрирован, истек, снят с DNS), независимо от DNS."""
from __future__ import annotations

import asyncio
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_TTL = 7 * 24 * 3600
RDAP_TIMEOUT = 8.0
RDAP_CONCURRENCY = 4
EXPIRY_WARN_DAYS = 30

HOLD = ("client hold", "server hold")
DELETING = ("redemption period", "pending delete", "pending restore")


@dataclass
class RdapInfo:
    registered: bool | None
    statuses: tuple[str, ...] = ()
    expires: datetime | None = None
    error: str | None = None

    @property
    def dead(self) -> str | None:
        """Причина считать домен мертвым по данным реестра."""
        if self.registered is False:
            return "не зарегистрирован (RDAP реестра)"
        if any(s in self.statuses for s in DELETING):
            return "регистрация истекла, домен удаляется из реестра (RDAP)"
        if any(s in self.statuses for s in HOLD):
            return "снят с DNS регистратором или реестром (RDAP: hold)"
        if self.expires and self.expires < datetime.now(timezone.utc):
            return f"срок регистрации истек {self.expires:%Y-%m-%d} (RDAP)"
        return None

    def expires_in_days(self) -> int | None:
        if not self.expires:
            return None
        return (self.expires - datetime.now(timezone.utc)).days


FetchFn = Callable[[str, float], tuple[int, bytes]]


def _fetch(url: str, timeout: float) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={
        "Accept": "application/rdap+json, application/json",
        "User-Agent": "domains-check/2.1 (+https://github.com/mazixs/domains)",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def parse_bootstrap(data: dict) -> dict[str, str]:
    servers = {}
    for tlds, urls in data.get("services", []):
        url = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
        if url:
            for tld in tlds:
                servers[tld.lower()] = url if url.endswith("/") else url + "/"
    return servers


def parse_domain(data: dict) -> RdapInfo:
    statuses = tuple(str(s).lower() for s in data.get("status", []))
    expires = None
    for event in data.get("events", []):
        if event.get("eventAction") == "expiration":
            try:
                expires = datetime.fromisoformat(str(event["eventDate"]).replace("Z", "+00:00"))
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
            except (KeyError, ValueError):
                pass
    return RdapInfo(True, statuses, expires)


class Rdap:
    def __init__(self, cache: Path | None = None, timeout: float = RDAP_TIMEOUT,
                 concurrency: int = RDAP_CONCURRENCY, fetch: FetchFn = _fetch):
        self.cache = cache
        self.timeout = timeout
        self.concurrency = concurrency
        self._fetch = fetch
        self._servers: dict[str, str] | None = None

    def _bootstrap(self) -> dict[str, str]:
        if self._servers is not None:
            return self._servers
        raw = None
        if self.cache and self.cache.exists() and time.time() - self.cache.stat().st_mtime < BOOTSTRAP_TTL:
            raw = self.cache.read_bytes()
        if raw is None:
            status, raw = self._fetch(BOOTSTRAP_URL, self.timeout)
            if status != 200:
                raise OSError(f"bootstrap IANA: HTTP {status}")
            if self.cache:
                self.cache.parent.mkdir(parents=True, exist_ok=True)
                self.cache.write_bytes(raw)
        self._servers = parse_bootstrap(json.loads(raw))
        return self._servers

    def lookup(self, domain: str) -> RdapInfo:
        try:
            base = self._bootstrap().get(domain.rsplit(".", 1)[-1])
        except (OSError, ValueError) as exc:
            return RdapInfo(None, error=f"RDAP недоступен: {exc}")
        if base is None:
            return RdapInfo(None, error="у зоны нет RDAP")
        try:
            status, body = self._fetch(f"{base}domain/{domain}", self.timeout)
        except OSError as exc:
            return RdapInfo(None, error=f"RDAP недоступен: {exc}")
        if status == 404:
            return RdapInfo(False)
        if status == 429:
            return RdapInfo(None, error="RDAP ограничил частоту запросов")
        if status != 200:
            return RdapInfo(None, error=f"RDAP: HTTP {status}")
        try:
            return parse_domain(json.loads(body))
        except ValueError:
            return RdapInfo(None, error="RDAP: некорректный ответ")

    async def lookup_many(self, domains: Iterable[str]) -> dict[str, RdapInfo]:
        sem = asyncio.Semaphore(self.concurrency)

        async def one(domain: str) -> tuple[str, RdapInfo]:
            async with sem:
                return domain, await asyncio.to_thread(self.lookup, domain)

        return dict(await asyncio.gather(*(one(d) for d in sorted(set(domains)))))
