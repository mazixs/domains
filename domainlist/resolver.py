"""DNS-клиенты и консенсус резолверов: положительный ответ от одного, отрицательный от кворума."""
from __future__ import annotations

import asyncio
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

DNS_TIMEOUT = 3.0
DNS_TRIES = 2


class Rcode(str, Enum):
    NOERROR = "NOERROR"
    NXDOMAIN = "NXDOMAIN"
    SERVFAIL = "SERVFAIL"
    REFUSED = "REFUSED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


@dataclass(frozen=True)
class Answer:
    rcode: Rcode
    records: tuple[str, ...] = ()


@dataclass
class Resolution:
    rcode: Rcode | None
    records: tuple[str, ...] = ()
    votes: dict[str, Rcode] = field(default_factory=dict)


class DnsClient:
    """Базовый клиент: логика консенсуса поверх абстрактного query()."""

    def __init__(self, servers: Sequence[str]):
        self.servers = list(servers)

    async def query(self, server: str, name: str, qtype: str) -> Answer:
        raise NotImplementedError

    async def close(self) -> None:
        pass

    async def addresses(self, server: str, name: str) -> Answer:
        a = await self.query(server, name, "A")
        if a.rcode is not Rcode.NOERROR or a.records:
            return a
        aaaa = await self.query(server, name, "AAAA")
        return aaaa if aaaa.rcode is Rcode.NOERROR else a

    async def resolve(self, name: str, qtype: str = "ADDR") -> Resolution:
        """Положительный ответ принимается от первого резолвера, отрицательный требует кворума."""
        async def ask(server: str) -> Answer:
            if qtype == "ADDR":
                return await self.addresses(server, name)
            return await self.query(server, name, qtype)

        first, rest = self.servers[0], self.servers[1:]
        answer = await ask(first)
        votes = {first: answer.rcode}
        if answer.rcode is Rcode.NOERROR:
            return Resolution(Rcode.NOERROR, answer.records, votes)

        positive = None
        for server, ans in zip(rest, await asyncio.gather(*(ask(s) for s in rest))):
            votes[server] = ans.rcode
            if ans.rcode is Rcode.NOERROR and positive is None:
                positive = ans
        if positive:
            return Resolution(Rcode.NOERROR, positive.records, votes)
        return Resolution(consensus(votes), (), votes)


def consensus(votes: dict[str, Rcode]) -> Rcode | None:
    quorum = min(2, len(votes))
    counts = Counter(votes.values())
    for rcode in (Rcode.NXDOMAIN, Rcode.SERVFAIL):
        if counts[rcode] >= quorum:
            return rcode
    return None


class AiodnsClient(DnsClient):
    def __init__(self, servers: Sequence[str], timeout: float = DNS_TIMEOUT, tries: int = DNS_TRIES):
        import aiodns
        import pycares

        super().__init__(servers)
        self._error = aiodns.error.DNSError
        self._qtypes = {"A": pycares.QUERY_TYPE_A, "AAAA": pycares.QUERY_TYPE_AAAA, "NS": pycares.QUERY_TYPE_NS,
                        "CNAME": pycares.QUERY_TYPE_CNAME}
        self._codes = {
            aiodns.error.ARES_ENODATA: Rcode.NOERROR,
            aiodns.error.ARES_ENOTFOUND: Rcode.NXDOMAIN,
            aiodns.error.ARES_ESERVFAIL: Rcode.SERVFAIL,
            aiodns.error.ARES_EREFUSED: Rcode.REFUSED,
            aiodns.error.ARES_ETIMEOUT: Rcode.TIMEOUT,
            aiodns.error.ARES_ECONNREFUSED: Rcode.TIMEOUT,
        }
        self._resolvers = {
            s: aiodns.DNSResolver(nameservers=[s], timeout=timeout, tries=tries) for s in servers
        }
        self._guard = timeout * tries + 2

    async def query(self, server: str, name: str, qtype: str) -> Answer:
        try:
            result = await asyncio.wait_for(
                self._resolvers[server].query_dns(name, qtype), self._guard
            )
        except self._error as exc:
            code = exc.args[0] if exc.args else None
            return Answer(self._codes.get(code, Rcode.ERROR))
        except asyncio.TimeoutError:
            return Answer(Rcode.TIMEOUT)
        want = self._qtypes[qtype]
        records = tuple(_record_text(r.data) for r in result.answer if r.type == want)
        return Answer(Rcode.NOERROR, records)

    async def close(self) -> None:
        for resolver in self._resolvers.values():
            with suppress(Exception):
                await resolver.close()


def _record_text(data: object) -> str:
    for attr in ("addr", "nsdname", "cname"):
        value = getattr(data, attr, None)
        if value is not None:
            return str(value).rstrip(".").lower()
    return str(data)
