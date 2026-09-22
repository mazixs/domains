import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from domainlist import checker
from domainlist.checker import Answer, Rcode, Resolution, Status
from domainlist.probe import ProbeResult
from domainlist.rdap import RdapInfo

NX = Answer(Rcode.NXDOMAIN)
SERVFAIL = Answer(Rcode.SERVFAIL)
TIMEOUT = Answer(Rcode.TIMEOUT)
NODATA = Answer(Rcode.NOERROR)


def ok(*records):
    return Answer(Rcode.NOERROR, records)


CANARIES = {("example.com", "A"): ok("93.184.215.14"), ("iana.org", "A"): ok("192.0.43.8")}


class FakeClient(checker.DnsClient):
    """Ответы по ключу (name, qtype) или (server, name, qtype); по умолчанию NXDOMAIN."""

    def __init__(self, servers, answers):
        super().__init__(servers)
        self.answers = answers
        self.calls = []

    async def query(self, server, name, qtype):
        self.calls.append((server, name, qtype))
        for key in ((server, name, qtype), (name, qtype)):
            if key in self.answers:
                return self.answers[key]
        return NX


def resolve(answers, name, servers=("s1", "s2", "s3"), qtype="ADDR"):
    client = FakeClient(servers, answers)
    return asyncio.run(client.resolve(name, qtype)), client


def test_positive_answer_from_first_server_is_enough():
    res, client = resolve({("a.com", "A"): ok("1.1.1.1")}, "a.com")
    assert res.rcode is Rcode.NOERROR and res.records == ("1.1.1.1",)
    assert {c[0] for c in client.calls} == {"s1"}


def test_aaaa_used_when_no_a_records():
    res, _ = resolve({("v6.com", "A"): NODATA, ("v6.com", "AAAA"): ok("2001:db8::1")}, "v6.com")
    assert res.records == ("2001:db8::1",)


def test_nodata_means_name_exists():
    res, _ = resolve({("apex.com", "A"): NODATA, ("apex.com", "AAAA"): NODATA}, "apex.com")
    assert res.rcode is Rcode.NOERROR and res.records == ()


def test_nxdomain_needs_quorum():
    res, _ = resolve({}, "dead.com")
    assert res.rcode is Rcode.NXDOMAIN
    assert res.votes == {"s1": Rcode.NXDOMAIN, "s2": Rcode.NXDOMAIN, "s3": Rcode.NXDOMAIN}


def test_single_filtering_resolver_does_not_kill_domain():
    answers = {("s1", "a.com", "A"): NX, ("a.com", "A"): ok("1.2.3.4")}
    res, _ = resolve(answers, "a.com")
    assert res.rcode is Rcode.NOERROR


def test_nxdomain_plus_timeouts_is_undecided():
    answers = {("s2", "x.com", "A"): TIMEOUT, ("s3", "x.com", "A"): TIMEOUT}
    res, _ = resolve(answers, "x.com")
    assert res.rcode is None


def test_single_resolver_quorum_is_one():
    res, _ = resolve({}, "dead.com", servers=("s1",))
    assert res.rcode is Rcode.NXDOMAIN


def test_servfail_quorum():
    res, _ = resolve({("x.com", "A"): SERVFAIL}, "x.com")
    assert res.rcode is Rcode.SERVFAIL


def test_preflight_drops_bad_resolvers():
    answers = dict(CANARIES)
    answers[("hijack", "example.com", "A")] = ok("93.184.215.14")
    answers[("dead", "example.com", "A")] = TIMEOUT
    answers[("dead", "iana.org", "A")] = TIMEOUT
    answers[("fakeip", "example.com", "A")] = ok("198.18.0.5")

    class Hijacker(FakeClient):
        async def query(self, server, name, qtype):
            if server == "hijack" and name.endswith(".com") and name not in ("example.com",):
                return ok("10.10.10.10") if qtype == "A" else NODATA
            return await super().query(server, name, qtype)

    client = Hijacker(["good", "hijack", "dead", "fakeip"], answers)
    usable, warnings = asyncio.run(checker.preflight(client))
    assert usable == ["good"]
    joined = "\n".join(warnings)
    assert "hijack" in joined and "NXDOMAIN" in joined
    assert "dead" in joined and "не отвечает" in joined
    assert "fakeip" in joined and "перехватывается" in joined


@pytest.mark.parametrize("res, zone, status, note", [
    (Resolution(Rcode.NOERROR, ("8.8.8.8",)), None, Status.OK, ""),
    (Resolution(Rcode.NOERROR, ()), None, Status.NO_ADDRESS, "A/AAAA"),
    (Resolution(Rcode.NOERROR, ("::", "0.0.0.0")), None, Status.SINKHOLE, "служебный"),
    (Resolution(Rcode.NOERROR, ("8.8.8.8",)), Resolution(Rcode.NOERROR, ("ns1.sedoparking.com",)),
     Status.PARKED, "sedoparking"),
    (Resolution(Rcode.NXDOMAIN), Resolution(Rcode.NOERROR, ("ns.x.com",)), Status.NXDOMAIN, "поддомен"),
    (Resolution(Rcode.NXDOMAIN), Resolution(Rcode.NXDOMAIN), Status.NXDOMAIN, "не зарегистрирован"),
    (Resolution(Rcode.SERVFAIL), None, Status.SERVFAIL, "SERVFAIL"),
    (Resolution(None), None, Status.UNKNOWN, "таймауты"),
])
def test_classify(res, zone, status, note):
    result = checker.classify("api.example.com", res, zone)
    assert result.status is status
    assert note in result.note


def test_parking_requires_all_ns_to_match():
    assert checker.is_parking_ns(["ns1.bodis.com", "ns2.bodis.com"])
    assert not checker.is_parking_ns(["ns1.bodis.com", "a.ns.facebook.com"])
    assert not checker.is_parking_ns([])


class FakeProber:
    def __init__(self, results=None, mitm=False):
        self.results = results or {}
        self.mitm = mitm
        self.calls = []

    async def canary(self):
        return self.mitm

    async def __call__(self, domain, addresses):
        self.calls.append((domain, list(addresses)))
        return self.results.get(domain, ProbeResult(True, "HTTPS 200"))


class FakeRdap:
    def __init__(self, infos=None):
        self.infos = infos or {}
        self.asked = []

    async def lookup_many(self, domains):
        domains = list(domains)
        self.asked += domains
        return {d: self.infos.get(d, RdapInfo(True)) for d in domains}


DOH = ("https://doh1/q", "https://doh2/q")


def _run(answers, domains, *, doh_answers=None, retry_answers=None, probe=False, prober=None,
         rdap="off", rdap_client=None, progress=None):
    """UDP-клиенты получают answers (повторный проход - retry_answers), DoH-клиенты - doh_answers."""
    udp_calls = []

    def factory(servers, timeout):
        if checker.is_doh(servers[0]):
            return FakeClient(servers, doh_answers or {})
        udp_calls.append(servers)
        return FakeClient(servers, answers if len(udp_calls) == 1 else (retry_answers or answers))

    return asyncio.run(checker.run_check(
        domains, resolvers=["s1", "s2"], doh=DOH if doh_answers is not None else (), probe=probe,
        rdap=rdap, client_factory=factory, prober=prober or FakeProber(), rdap_client=rdap_client or FakeRdap(),
        progress=progress,
    ))


def by_domain(report):
    return {r.domain: r for r in report.results}


def test_run_check_end_to_end():
    answers = dict(CANARIES)
    answers.update({
        ("alive.com", "A"): ok("8.8.8.8"),
        ("alive.com", "NS"): ok("ns1.alive.com"),
        ("api.alive.com", "A"): NX,
    })
    stages = set()
    report = _run(answers, ["alive.com", "api.alive.com", "gone.com"], progress=lambda s, d, t: stages.add(s))
    statuses = {r.domain: r.status for r in report.results}
    assert statuses == {"alive.com": Status.OK, "api.alive.com": Status.NXDOMAIN, "gone.com": Status.NXDOMAIN}
    notes = {r.domain: r.note for r in report.results}
    assert "alive.com жив" in notes["api.alive.com"]
    assert "не зарегистрирован" in notes["gone.com"]
    assert by_domain(report)["gone.com"].confirmed == ["DNS"]
    assert stages == {"DNS"}
    assert report.channels == ["DNS: s1, s2"]


def test_retry_pass_resolves_timeouts():
    first = {**CANARIES, ("slow.com", "A"): TIMEOUT}
    second = {**CANARIES, ("slow.com", "A"): ok("8.8.4.4")}
    report = _run(first, ["slow.com"], retry_answers=second)
    assert report.results[0].status is Status.OK


def test_probe_statuses_and_mitm_canary():
    answers = {**CANARIES, ("a.com", "A"): ok("8.8.8.8"), ("b.com", "A"): ok("8.8.8.8"),
               ("c.com", "A"): ok("8.8.8.8"), ("d.com", "A"): ok("8.8.8.8"), ("e.com", "A"): ok("0.0.0.0")}
    prober = FakeProber({
        "a.com": ProbeResult(False, "443 и 80 не отвечают"),
        "b.com": ProbeResult(True, "HTTPS 530", broken="Cloudflare: origin не найден (HTTP 530)"),
        "c.com": ProbeResult(True, "HTTP 302", parked="редирект на площадку продажи доменов sedo.com"),
    })
    stages = set()
    report = _run(answers, ["a.com", "b.com", "c.com", "d.com", "e.com"], probe=True, prober=prober,
                  progress=lambda s, d, t: stages.add(s))
    res = by_domain(report)
    assert report.probed and stages == {"DNS", "HTTPS"}
    assert res["a.com"].status is Status.NO_CONNECT
    assert res["b.com"].status is Status.BROKEN and res["b.com"].confirmed == ["HTTP"]
    assert res["c.com"].status is Status.PARKED and "sedo.com" in res["c.com"].note
    assert res["d.com"].status is Status.OK and "HTTP: HTTPS 200" in res["d.com"].evidence
    assert res["e.com"].status is Status.SINKHOLE
    assert "e.com" not in [c[0] for c in prober.calls]

    report = _run(answers, ["a.com"], probe=True, prober=FakeProber(mitm=True))
    assert not report.probed and report.results[0].status is Status.OK
    assert any("192.0.2.1" in w for w in report.warnings)


def test_doh_confirms_negative_answers():
    answers = {**CANARIES, ("alive.com", "NS"): ok("ns.alive.com")}
    doh = {**CANARIES, ("alive.com", "NS"): ok("ns.alive.com"),
           ("old.alive.com", "CNAME"): ok("gone-app.herokuapp.com")}
    report = _run(answers, ["gone.com", "old.alive.com"], doh_answers=doh)
    res = by_domain(report)
    assert res["gone.com"].status is Status.NXDOMAIN
    assert res["gone.com"].confirmed == ["DNS", "DoH"]
    assert "CNAME" in res["old.alive.com"].note and "gone-app.herokuapp.com" in res["old.alive.com"].note
    assert any(c.startswith("DoH: doh1, doh2") for c in report.channels)


def test_doh_overrides_hijacked_nxdomain():
    answers = {**CANARIES, ("blocked.com", "NS"): ok("ns.blocked.com")}
    doh = {**CANARIES, ("blocked.com", "A"): ok("8.8.8.8")}
    result = _run(answers, ["blocked.com"], doh_answers=doh).results[0]
    assert result.status is Status.OK
    assert "подмена" in result.note and result.addresses == ["8.8.8.8"]


def test_udp_blocked_falls_back_to_doh():
    doh = {**CANARIES, ("alive.com", "A"): ok("8.8.8.8")}
    report = _run({}, ["alive.com", "gone.com"], doh_answers=doh)
    res = by_domain(report)
    assert res["alive.com"].status is Status.OK
    assert res["gone.com"].status is Status.NXDOMAIN and res["gone.com"].confirmed == ["DoH"]
    assert any("UDP DNS недоступен" in w for w in report.warnings)
    assert report.channels[0].startswith("DoH:")


def test_doh_unavailable_is_a_warning_not_an_error():
    report = _run(dict(CANARIES), ["gone.com"], doh_answers={})
    assert report.results[0].status is Status.NXDOMAIN and report.results[0].confirmed == ["DNS"]
    assert any("DoH недоступен" in w for w in report.warnings)


def test_rdap_auto_asks_only_suspicious_zones():
    answers = {**CANARIES, ("alive.com", "A"): ok("8.8.8.8"), ("alive.com", "NS"): ok("ns.alive.com")}
    rdap = FakeRdap({"gone.com": RdapInfo(False)})
    report = _run(answers, ["alive.com", "gone.com"], rdap="auto", rdap_client=rdap)
    assert rdap.asked == ["gone.com"]
    gone = by_domain(report)["gone.com"]
    assert gone.confirmed == ["DNS", "RDAP"]
    assert "RDAP реестра" in gone.note


def test_rdap_all_finds_hold_and_expiring():
    answers = {**CANARIES, ("held.com", "A"): ok("8.8.8.8"), ("soon.com", "A"): ok("8.8.4.4")}
    soon = datetime.now(timezone.utc) + timedelta(days=10, hours=1)
    rdap = FakeRdap({"held.com": RdapInfo(True, ("client hold",)), "soon.com": RdapInfo(True, expires=soon)})
    report = _run(answers, ["held.com", "soon.com"], rdap="all", rdap_client=rdap)
    res = by_domain(report)
    assert res["held.com"].status is Status.PARKED and res["held.com"].confirmed == ["RDAP"]
    assert res["soon.com"].status is Status.OK
    assert [(e.zone, e.days) for e in report.expiring] == [("soon.com", 10)]


def test_preflight_failure_raises():
    with pytest.raises(checker.PreflightError):
        _run({}, ["a.com"])


def test_is_bogon():
    assert checker.is_bogon("0.0.0.0") and checker.is_bogon("::") and checker.is_bogon("127.0.0.1")
    assert checker.is_bogon("192.168.1.1") and checker.is_bogon("198.18.0.1")
    assert not checker.is_bogon("8.8.8.8") and not checker.is_bogon("2606:4700::1111")


def test_merge_prefers_positive_second_channel():
    nx = Resolution(Rcode.NXDOMAIN, (), {"s1": Rcode.NXDOMAIN})
    found = Resolution(Rcode.NOERROR, ("1.2.3.4",), {"https://doh1/q": Rcode.NOERROR})
    merged, disputed = checker.merge(nx, found)
    assert merged.rcode is Rcode.NOERROR and disputed
    merged, disputed = checker.merge(nx, Resolution(Rcode.NXDOMAIN))
    assert merged.rcode is Rcode.NXDOMAIN and not disputed
    merged, _ = checker.merge(Resolution(None), Resolution(Rcode.NXDOMAIN))
    assert merged.rcode is Rcode.NXDOMAIN
    assert checker.merge(nx, None) == (nx, False)


@pytest.mark.parametrize("rdap, status, note, confirmed", [
    (RdapInfo(False), Status.NXDOMAIN, "RDAP реестра", ["DNS", "RDAP"]),
    (RdapInfo(True), Status.NXDOMAIN, "не делегирован", ["DNS"]),
    (RdapInfo(None, error="у зоны нет RDAP"), Status.NXDOMAIN, "не зарегистрирован", ["DNS"]),
])
def test_classify_registered_domain_with_rdap(rdap, status, note, confirmed):
    res = Resolution(Rcode.NXDOMAIN, (), {"s1": Rcode.NXDOMAIN})
    result = checker.classify("gone.com", res, Resolution(Rcode.NXDOMAIN), rdap=rdap)
    assert result.status is status and note in result.note
    assert result.confirmed == confirmed
    assert any(e.startswith("RDAP gone.com") for e in result.evidence)


def test_servfail_with_dead_registry_is_confirmed():
    result = checker.classify("x.com", Resolution(Rcode.SERVFAIL), rdap=RdapInfo(True, ("pending delete",)))
    assert result.status is Status.SERVFAIL and result.confirmed == ["RDAP"] and "удаляется" in result.note


def test_server_label():
    assert checker.server_label("https://dns.google/resolve") == "dns.google"
    assert checker.server_label("1.1.1.1") == "1.1.1.1"
