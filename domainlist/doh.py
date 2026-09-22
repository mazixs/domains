"""DNS-over-HTTPS (JSON API): независимый зашифрованный канал, провайдер не может подменить ответ."""
from __future__ import annotations

import asyncio
import http.client
import json
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Sequence
from urllib.parse import urlencode, urlsplit

from .resolver import Answer, DnsClient, Rcode

DOH_RESOLVERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "AAAA": 28}
_RCODES = {0: Rcode.NOERROR, 2: Rcode.SERVFAIL, 3: Rcode.NXDOMAIN, 5: Rcode.REFUSED}


def is_doh(server: str) -> bool:
    return server.startswith("https://")


def parse_answer(data: dict, qtype: str) -> Answer:
    rcode = _RCODES.get(data.get("Status"), Rcode.ERROR)
    if rcode is not Rcode.NOERROR:
        return Answer(rcode)
    want = QTYPES[qtype]
    records = tuple(
        str(a.get("data", "")).rstrip(".").lower()
        for a in data.get("Answer") or () if a.get("type") == want
    )
    return Answer(Rcode.NOERROR, records)


class DohClient(DnsClient):
    """Блокирующий http.client в пуле потоков: keep-alive на поток, без внешних зависимостей."""

    def __init__(self, servers: Sequence[str], timeout: float = 5.0, workers: int = 16):
        super().__init__(servers)
        self.timeout = timeout
        self._ctx = ssl.create_default_context()
        self._local = threading.local()
        self._pool = ThreadPoolExecutor(workers, thread_name_prefix="doh")

    def _get(self, server: str, name: str, qtype: str) -> dict:
        url = urlsplit(server)
        conns = self._local.__dict__.setdefault("conns", {})
        path = f"{url.path}?{urlencode({'name': name, 'type': qtype})}"
        for attempt in (1, 2):
            conn = conns.get(url.netloc)
            if conn is None:
                conn = http.client.HTTPSConnection(url.hostname, url.port or 443,
                                                   timeout=self.timeout, context=self._ctx)
                conns[url.netloc] = conn
            try:
                conn.request("GET", path, headers={"Accept": "application/dns-json"})
                resp = conn.getresponse()
                body = resp.read()
            except (OSError, http.client.HTTPException):
                conn.close()
                conns.pop(url.netloc, None)
                if attempt == 2:
                    raise
                continue
            if resp.status != 200:
                raise OSError(f"HTTP {resp.status}")
            return json.loads(body)
        raise OSError("unreachable")

    async def query(self, server: str, name: str, qtype: str) -> Answer:
        loop = asyncio.get_running_loop()
        try:
            data = await asyncio.wait_for(
                loop.run_in_executor(self._pool, self._get, server, name, qtype), self.timeout * 2 + 1,
            )
        except (asyncio.TimeoutError, OSError, http.client.HTTPException, ValueError):
            return Answer(Rcode.TIMEOUT)
        return parse_answer(data, qtype)

    async def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
