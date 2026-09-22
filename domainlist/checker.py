"""Проверка доменов по независимым каналам: DNS (UDP), DoH, RDAP реестра, HTTPS/HTTP."""
from __future__ import annotations

import asyncio
import ipaddress
import secrets
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Mapping, Sequence

from . import names
from .doh import DOH_RESOLVERS, DohClient, is_doh
from .probe import Prober, ProbeResult
from .rdap import EXPIRY_WARN_DAYS, Rdap, RdapInfo
from .resolver import DNS_TIMEOUT, AiodnsClient, Answer, DnsClient, Rcode, Resolution, consensus

__all__ = ["Answer", "DnsClient", "Rcode", "Resolution", "consensus", "DOH_RESOLVERS", "DNS_TIMEOUT"]

DEFAULT_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
DEFAULT_CONCURRENCY = 64
CANARY_DOMAINS = ("example.com", "iana.org")

# NS-серверы парковщиков и "домен истек" у регистраторов.
PARKING_NS = (
    "above.com", "afternic.com", "bodis.com", "cashparking.com", "dan.com",
    "fabulous.com", "hugedomains.com", "namebrightdns.com", "parkingcrew.net",
    "parklogic.com", "pendingrenewaldeletion.com", "sedoparking.com", "undeveloped.com",
)

CH_DNS, CH_DOH, CH_RDAP, CH_WEB = "DNS", "DoH", "RDAP", "HTTP"


class Status(str, Enum):
    OK = "ok"
    NO_CONNECT = "no_connect"
    NO_ADDRESS = "no_address"
    PARKED = "parked"
    SINKHOLE = "sinkhole"
    BROKEN = "broken"
    SERVFAIL = "servfail"
    NXDOMAIN = "nxdomain"
    UNKNOWN = "unknown"


KEEP = frozenset({Status.OK, Status.NO_CONNECT, Status.NO_ADDRESS})
REVIEW = frozenset({Status.PARKED, Status.SINKHOLE, Status.BROKEN, Status.SERVFAIL})
REMOVE = frozenset({Status.NXDOMAIN})


@dataclass
class Result:
    domain: str
    status: Status
    addresses: list[str] = field(default_factory=list)
    votes: dict[str, str] = field(default_factory=dict)
    note: str = ""
    evidence: list[str] = field(default_factory=list)
    confirmed: list[str] = field(default_factory=list)


@dataclass
class Expiring:
    zone: str
    expires: str
    days: int


@dataclass
class CheckReport:
    results: list[Result]
    servers: list[str]
    warnings: list[str]
    duration: float
    probed: bool = False
    channels: list[str] = field(default_factory=list)
    expiring: list[Expiring] = field(default_factory=list)


class PreflightError(RuntimeError):
    pass


class MultiClient(DnsClient):
    """Смешанный список: IP-адреса идут по UDP, https:// - через DoH."""

    def __init__(self, servers: Sequence[str], timeout: float):
        super().__init__(servers)
        udp = [s for s in servers if not is_doh(s)]
        doh = [s for s in servers if is_doh(s)]
        self._by_server: dict[str, DnsClient] = {}
        for group, cls in ((udp, AiodnsClient), (doh, DohClient)):
            if group:
                client = cls(group, timeout=timeout)
                self._by_server.update(dict.fromkeys(group, client))

    async def query(self, server: str, name: str, qtype: str) -> Answer:
        return await self._by_server[server].query(server, name, qtype)

    async def close(self) -> None:
        for client in {id(c): c for c in self._by_server.values()}.values():
            await client.close()


def make_client(servers: Sequence[str], timeout: float) -> DnsClient:
    return MultiClient(servers, timeout)


def is_bogon(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_unspecified
            or ip.is_link_local or ip.is_multicast or ip.is_reserved)


def is_parking_ns(ns_records: Sequence[str]) -> bool:
    return bool(ns_records) and all(
        any(names.is_within(ns, zone) for zone in PARKING_NS) for ns in ns_records
    )


def server_label(server: str) -> str:
    return server.split("/")[2] if is_doh(server) else server


async def preflight(client: DnsClient) -> tuple[list[str], list[str]]:
    """Отбрасывает резолверы, которые не отвечают или подменяют NXDOMAIN."""
    bogus = f"{secrets.token_hex(10)}.com"

    async def check(server: str) -> str | None:
        label = server_label(server)
        canaries = [await client.addresses(server, d) for d in CANARY_DOMAINS]
        good = [a for a in canaries if a.rcode is Rcode.NOERROR and a.records]
        if not good:
            return f"резолвер {label} исключен: не отвечает ({canaries[0].rcode.value})"
        if all(is_bogon(ip) for ip in good[0].records):
            return (f"резолвер {label} исключен: example.com резолвится в {good[0].records[0]}, DNS перехватывается "
                    "(fake-ip у VPN/прокси-клиента?)")
        fake = await client.addresses(server, bogus)
        if fake.rcode is Rcode.NOERROR and fake.records:
            return f"резолвер {label} исключен: подменяет NXDOMAIN (несуществующий домен резолвится в {fake.records[0]})"
        return None

    problems = await asyncio.gather(*(check(s) for s in client.servers))
    usable = [s for s, p in zip(client.servers, problems) if p is None]
    return usable, [p for p in problems if p]


def merge(primary: Resolution, second: Resolution | None) -> tuple[Resolution, bool]:
    """Итог двух каналов DNS и флаг "первый канал сказал нет, второй нашел адреса"."""
    if second is None or second.rcode is None:
        return primary, False
    votes = {**primary.votes, **second.votes}
    if second.rcode is Rcode.NOERROR:
        disputed = primary.rcode in (Rcode.NXDOMAIN, Rcode.SERVFAIL)
        return Resolution(Rcode.NOERROR, second.records, votes), disputed
    if primary.rcode is None:
        return Resolution(second.rcode, (), votes), False
    return Resolution(primary.rcode, primary.records, votes), False


def _votes_text(res: Resolution) -> str:
    if res.rcode is Rcode.NOERROR:
        if not res.records:
            return "имя есть, адресов нет"
        more = f" (+{len(res.records) - 1})" if len(res.records) > 1 else ""
        return res.records[0] + more
    counts = Counter(r.value for r in res.votes.values())
    top, n = counts.most_common(1)[0] if counts else ("нет ответа", 0)
    return f"{top} от {n} из {sum(counts.values())}"


def classify(
    domain: str, res: Resolution, zone: Resolution | None = None, *,
    second: Resolution | None = None, cname: str | None = None, rdap: RdapInfo | None = None,
    primary: str = CH_DNS,
) -> Result:
    """res - ответ основного канала, second - подтверждение через DoH (для отрицательных ответов)."""
    final, disputed = merge(res, second)
    votes = {server_label(s): r.value for s, r in final.votes.items()}
    zone_name = names.registrable(domain)
    evidence = [f"{primary}: {_votes_text(res)}"] if res.votes else []
    if second is not None and second.votes:
        evidence.append(f"{CH_DOH}: {_votes_text(second)}")
    if rdap is not None:
        evidence.append(f"{CH_RDAP} {zone_name}: {_rdap_text(rdap)}")

    def result(status: Status, note: str, addrs: Sequence[str] = (), confirmed: Sequence[str] = ()) -> Result:
        return Result(domain, status, list(addrs), votes, note, evidence, list(confirmed))

    if final.rcode is Rcode.NOERROR:
        addrs = list(final.records)
        prefix = f"{primary} вернул {res.rcode.value if res.rcode else 'таймаут'}, а DoH нашел имя: вероятна подмена DNS. " \
            if disputed else ""
        if not addrs:
            return result(Status.NO_ADDRESS, prefix + "имя существует, но A/AAAA-записей нет")
        if all(is_bogon(a) for a in addrs):
            return result(Status.SINKHOLE, prefix + f"резолвится в служебный адрес {addrs[0]}", addrs)
        if zone and zone.rcode is Rcode.NOERROR and is_parking_ns(zone.records):
            evidence.append(f"NS {zone_name}: {', '.join(zone.records[:2])}")
            return result(Status.PARKED, f"NS домена {zone_name} у парковщика: {zone.records[0]}", addrs)
        if rdap is not None and rdap.dead:
            return result(Status.PARKED, f"DNS отвечает, но {rdap.dead}", addrs, [CH_RDAP])
        return result(Status.OK, prefix.strip(), addrs)

    zone_dead = zone is not None and zone.rcode is Rcode.NXDOMAIN
    registry_dead = rdap.dead if rdap is not None else None
    if final.rcode is Rcode.NXDOMAIN:
        confirmed = []
        if res.rcode is Rcode.NXDOMAIN:
            confirmed.append(primary)
        if second is not None and second.rcode is Rcode.NXDOMAIN:
            confirmed.append(CH_DOH)
        if cname:
            evidence.append(f"CNAME -> {cname}")
        if zone_dead or domain == zone_name:
            if registry_dead:
                confirmed.append(CH_RDAP)
                note = f"домен {registry_dead}"
            elif rdap is not None and rdap.registered:
                note = "домен числится в реестре, но не делегирован в DNS"
            else:
                note = "домен не зарегистрирован или истек"
        elif cname:
            note = f"указывает (CNAME) на {cname}, которого больше нет: сервис удален"
        else:
            note = f"поддомен не существует (домен {zone_name} жив)"
        return result(Status.NXDOMAIN, note, confirmed=confirmed)
    if final.rcode is Rcode.SERVFAIL:
        if registry_dead:
            return result(Status.SERVFAIL, f"DNS сломан, а домен {registry_dead}", confirmed=[CH_RDAP])
        return result(Status.SERVFAIL, "все резолверы вернули SERVFAIL: сломан DNS домена")
    return result(Status.UNKNOWN, "нет согласованного ответа (таймауты)")


def _rdap_text(info: RdapInfo) -> str:
    if info.error:
        return info.error
    if info.dead:
        return info.dead
    if info.expires:
        return f"зарегистрирован до {info.expires:%Y-%m-%d}"
    return "зарегистрирован"


def apply_probe(result: Result, probe: ProbeResult) -> None:
    result.evidence.append(f"{CH_WEB}: {probe.detail}")
    if not probe.reachable:
        result.status = Status.NO_CONNECT
        result.note = "DNS в порядке, но HTTPS/HTTP (443/80) не отвечают"
    elif probe.parked:
        result.status, result.note = Status.PARKED, probe.parked
        result.confirmed.append(CH_WEB)
    elif probe.broken:
        result.status, result.note = Status.BROKEN, probe.broken
        result.confirmed.append(CH_WEB)


ProgressFn = Callable[[str, int, int], None]
ClientFactory = Callable[[Sequence[str], float], DnsClient]


async def run_check(
    domains: Sequence[str],
    resolvers: Sequence[str] = DEFAULT_RESOLVERS,
    doh: Sequence[str] = DOH_RESOLVERS,
    timeout: float = DNS_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    probe: bool = True,
    rdap: str = "auto",
    progress: ProgressFn | None = None,
    client_factory: ClientFactory = make_client,
    prober: Prober | None = None,
    rdap_client: Rdap | None = None,
) -> CheckReport:
    """rdap: auto - только для подозрительных доменов, all - для всех (плюс сроки регистрации), off."""
    started = time.monotonic()
    prober = prober or Prober()
    # Канарейка на нормальной сети ждет таймаут, поэтому идет параллельно с DNS.
    canary = asyncio.ensure_future(prober.canary()) if probe else None
    warnings: list[str] = []
    channels: list[str] = []
    rdap_task = None
    try:
        client, servers, primary = await _open_primary(resolvers, doh, timeout, client_factory, warnings)
        channels.append(f"{primary}: {', '.join(map(server_label, servers))}")
        try:
            resolved, zones = await _resolve_all(client, domains, concurrency, progress)
        finally:
            await client.close()
        await _retry_undecided(resolved, client_factory(servers, timeout * 2), concurrency)

        second: dict[str, Resolution] = {}
        second_zones: dict[str, Resolution] = {}
        cnames: dict[str, str] = {}
        if primary == CH_DNS and doh:
            await _confirm(resolved, zones, second, second_zones, cnames,
                           client_factory(doh, timeout), concurrency, warnings, channels)
        final_zones = {z: merge(r, second_zones.get(z))[0] for z, r in zones.items()}

        targets = {}
        for d in domains:
            res, _ = merge(resolved[d], second.get(d))
            if res.rcode is Rcode.NOERROR and res.records and not all(is_bogon(a) for a in res.records):
                targets[d] = list(res.records)

        rdap_zones = _rdap_zones(domains, resolved, second, final_zones, rdap)
        rdap_task = asyncio.ensure_future(
            (rdap_client or Rdap()).lookup_many(rdap_zones) if rdap_zones else _empty()
        )
        probed = False
        probes: dict[str, ProbeResult] = {}
        if canary is not None:
            if await canary:
                warnings.append("HTTPS-проба отключена: TLS с несуществующим именем на немаршрутизируемый "
                                "192.0.2.1 прошел, значит трафик расшифровывает прокси (MITM)")
            else:
                probed = True
                channels.append(f"{CH_WEB}: HTTPS/HTTP-проба")
                probes = await _probe_all(targets, prober, concurrency, progress)
        registry = await rdap_task
        if registry:
            channels.append(f"{CH_RDAP}: статус в реестре, доменов: {len(registry)}")

        results = []
        for d in domains:
            zone = names.registrable(d) or ""
            r = classify(d, resolved[d], final_zones.get(zone), second=second.get(d),
                         cname=cnames.get(d), rdap=registry.get(zone), primary=primary)
            if r.status is Status.OK and d in probes:
                apply_probe(r, probes[d])
            results.append(r)
    finally:
        for task in (canary, rdap_task):
            if task is not None and not task.done():
                task.cancel()

    return CheckReport(results, servers, warnings, time.monotonic() - started, probed, channels,
                       _expiring(registry))


async def _empty() -> dict:
    return {}


async def _open_primary(resolvers, doh, timeout, factory, warnings) -> tuple[DnsClient, list[str], str]:
    """UDP-резолверы, а если они недоступны - DoH (частый случай: UDP/53 наружу закрыт)."""
    attempts = [(list(resolvers), CH_DNS)]
    if doh and any(not is_doh(s) for s in resolvers):
        attempts.append((list(doh), CH_DOH))
    problems: list[str] = []
    for servers, label in attempts:
        if not servers:
            continue
        client = factory(servers, timeout)
        usable, warns = await preflight(client)
        if usable:
            if label == CH_DOH:
                warnings.append("UDP DNS недоступен, проверка идет через DoH: " + "; ".join(problems))
            warnings.extend(warns)
            client.servers = usable
            primary = CH_DOH if all(is_doh(s) for s in usable) else CH_DNS
            return client, usable, primary
        problems.extend(warns)
        await client.close()
    raise PreflightError("\n".join(problems) or "нет доступных DNS-резолверов")


async def _resolve_all(
    client: DnsClient, domains: Sequence[str], concurrency: int, progress: ProgressFn | None,
) -> tuple[dict[str, Resolution], dict[str, Resolution]]:
    """Адреса всех доменов и NS их зарегистрированных доменов (для парковки и истекших)."""
    zone_names = sorted({z for z in map(names.registrable, domains) if z})
    sem = asyncio.Semaphore(concurrency)
    resolved: dict[str, Resolution] = {}
    zones: dict[str, Resolution] = {}

    async def resolve(target: dict[str, Resolution], name: str, qtype: str) -> None:
        async with sem:
            target[name] = await client.resolve(name, qtype)

    tasks = [asyncio.ensure_future(resolve(zones, z, "NS")) for z in zone_names]
    tasks += [asyncio.ensure_future(resolve(resolved, d, "ADDR")) for d in domains]
    for done, fut in enumerate(asyncio.as_completed(tasks), 1):
        await fut
        if progress:
            progress("DNS", done, len(tasks))
    return resolved, zones


async def _retry_undecided(resolved: dict[str, Resolution], client: DnsClient, concurrency: int) -> None:
    """Второй проход с увеличенным таймаутом и меньшей нагрузкой для спорных ответов."""
    undecided = [d for d, r in resolved.items() if r.rcode not in (Rcode.NOERROR, Rcode.NXDOMAIN)]
    try:
        sem = asyncio.Semaphore(max(4, concurrency // 8))

        async def again(name: str) -> None:
            async with sem:
                res = await client.resolve(name)
            if res.rcode is not None:
                resolved[name] = res

        await asyncio.gather(*(again(d) for d in undecided))
    finally:
        await client.close()


async def _confirm(
    resolved, zones, second, second_zones, cnames, client: DnsClient, concurrency: int,
    warnings: list[str], channels: list[str],
) -> None:
    """Отрицательные ответы UDP перепроверяются через DoH: провайдер не может подменить HTTPS."""
    bad = [d for d, r in resolved.items() if r.rcode is not Rcode.NOERROR]
    bad_zones = sorted({z for z, r in zones.items() if r.rcode is not Rcode.NOERROR}
                       | {z for z in map(names.registrable, bad) if z and z in zones})
    if not bad and not bad_zones:
        await client.close()
        return
    try:
        usable, warns = await preflight(client)
        if not usable:
            warnings.append("DoH недоступен, отрицательные ответы подтверждены только по UDP: " + "; ".join(warns))
            return
        client.servers = usable
        channels.append(f"{CH_DOH}: {', '.join(map(server_label, usable))} (перепроверка)")
        sem = asyncio.Semaphore(max(4, concurrency // 4))

        async def one(target: dict[str, Resolution], name: str, qtype: str) -> None:
            async with sem:
                target[name] = await client.resolve(name, qtype)

        await asyncio.gather(*(one(second, d, "ADDR") for d in bad),
                             *(one(second_zones, z, "NS") for z in bad_zones))

        async def cname(name: str) -> None:
            async with sem:
                ans = await client.query(usable[0], name, "CNAME")
            if ans.rcode is Rcode.NOERROR and ans.records:
                cnames[name] = ans.records[0]

        dead = [d for d in bad if merge(resolved[d], second.get(d))[0].rcode is Rcode.NXDOMAIN]
        await asyncio.gather(*(cname(d) for d in dead))
    finally:
        await client.close()


def _rdap_zones(domains, resolved, second, zones, mode: str) -> list[str]:
    if mode == "off":
        return []
    all_zones = sorted({z for z in map(names.registrable, domains) if z})
    if mode == "all":
        return all_zones
    suspicious = set()
    for d in domains:
        z = names.registrable(d)
        if not z:
            continue
        res, _ = merge(resolved[d], second.get(d))
        zone = zones.get(z)
        zone_bad = zone is not None and zone.rcode is not Rcode.NOERROR
        if zone_bad or res.rcode is Rcode.SERVFAIL or (res.rcode is Rcode.NXDOMAIN and d == z):
            suspicious.add(z)
        elif zone is not None and zone.rcode is Rcode.NOERROR and is_parking_ns(zone.records):
            suspicious.add(z)
    return sorted(suspicious)


def _expiring(registry: Mapping[str, RdapInfo]) -> list[Expiring]:
    soon = []
    for zone, info in registry.items():
        days = info.expires_in_days()
        if info.registered and days is not None and 0 <= days < EXPIRY_WARN_DAYS:
            soon.append(Expiring(zone, f"{info.expires:%Y-%m-%d}", days))
    return sorted(soon, key=lambda e: e.days)


async def _probe_all(
    targets: Mapping[str, list[str]], prober: Prober, concurrency: int, progress: ProgressFn | None,
) -> dict[str, ProbeResult]:
    sem = asyncio.Semaphore(concurrency)
    out: dict[str, ProbeResult] = {}

    async def one(domain: str) -> None:
        async with sem:
            out[domain] = await prober(domain, targets[domain])

    tasks = [asyncio.ensure_future(one(d)) for d in targets]
    for done, fut in enumerate(asyncio.as_completed(tasks), 1):
        await fut
        if progress:
            progress("HTTPS", done, len(tasks))
    return out
