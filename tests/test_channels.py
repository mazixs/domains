import json
import ssl
from datetime import date, datetime, timedelta, timezone

import pytest

from domainlist import doh, probe, rdap, report
from domainlist.history import History
from domainlist.resolver import Rcode


def test_doh_parse_answer_filters_by_type():
    data = {"Status": 0, "Answer": [
        {"type": 5, "data": "edge.example.net."},
        {"type": 1, "data": "93.184.215.14"},
    ]}
    assert doh.parse_answer(data, "A").records == ("93.184.215.14",)
    assert doh.parse_answer(data, "CNAME").records == ("edge.example.net",)
    assert doh.parse_answer({"Status": 3}, "A").rcode is Rcode.NXDOMAIN
    assert doh.parse_answer({"Status": 2}, "A").rcode is Rcode.SERVFAIL
    assert doh.parse_answer({"Status": 0}, "A").records == ()
    assert doh.parse_answer({}, "A").rcode is Rcode.ERROR
    assert doh.is_doh("https://dns.google/resolve") and not doh.is_doh("8.8.8.8")


BOOTSTRAP = {"services": [
    [["com", "net"], ["http://rdap.verisign.com/com/v1", "https://rdap.verisign.com/com/v1/"]],
    [["ai"], ["https://rdap.nic.ai"]],
]}


def test_rdap_parse_bootstrap_prefers_https():
    servers = rdap.parse_bootstrap(BOOTSTRAP)
    assert servers == {"com": "https://rdap.verisign.com/com/v1/", "net": "https://rdap.verisign.com/com/v1/",
                       "ai": "https://rdap.nic.ai/"}


def test_rdap_parse_domain():
    info = rdap.parse_domain({"status": ["Client Transfer Prohibited", "client hold"], "events": [
        {"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2030-05-01T00:00:00Z"},
    ]})
    assert info.registered and "client hold" in info.statuses
    assert info.expires == datetime(2030, 5, 1, tzinfo=timezone.utc)
    assert "hold" in info.dead


@pytest.mark.parametrize("info, text", [
    (rdap.RdapInfo(False), "не зарегистрирован"),
    (rdap.RdapInfo(True, ("redemption period",)), "удаляется"),
    (rdap.RdapInfo(True, expires=datetime(2020, 1, 1, tzinfo=timezone.utc)), "истек 2020-01-01"),
    (rdap.RdapInfo(True, ("active",), datetime.now(timezone.utc) + timedelta(days=90)), None),
    (rdap.RdapInfo(None, error="у зоны нет RDAP"), None),
])
def test_rdap_dead(info, text):
    assert (info.dead is None) if text is None else (text in info.dead)


class FakeFetch:
    def __init__(self, routes):
        self.routes = routes
        self.urls = []

    def __call__(self, url, timeout):
        self.urls.append(url)
        status, body = self.routes.get(url, (404, b""))
        return status, json.dumps(body).encode() if isinstance(body, dict) else body


def test_rdap_lookup_and_bootstrap_cache(tmp_path):
    fetch = FakeFetch({
        rdap.BOOTSTRAP_URL: (200, BOOTSTRAP),
        "https://rdap.verisign.com/com/v1/domain/alive.com": (200, {"status": ["active"]}),
        "https://rdap.verisign.com/com/v1/domain/busy.com": (429, b""),
    })
    cache = tmp_path / "rdap.json"
    client = rdap.Rdap(cache=cache, fetch=fetch)
    assert client.lookup("alive.com").registered is True
    assert client.lookup("gone.com").registered is False
    assert "частоту" in client.lookup("busy.com").error
    assert client.lookup("x.io").error == "у зоны нет RDAP"
    assert cache.exists() and fetch.urls.count(rdap.BOOTSTRAP_URL) == 1

    again = rdap.Rdap(cache=cache, fetch=FakeFetch({}))
    assert again.lookup("gone.com").registered is False


def test_rdap_unavailable_bootstrap_is_error_not_dead(tmp_path):
    info = rdap.Rdap(cache=tmp_path / "c.json", fetch=FakeFetch({})).lookup("gone.com")
    assert info.registered is None and "недоступен" in info.error and info.dead is None


def test_history_streaks(tmp_path):
    path = tmp_path / "state.json"
    h = History.load(path)
    day1, day2 = date(2026, 9, 1), date(2026, 9, 8)
    h.update([("a.com", "nxdomain", True), ("b.com", "ok", False)], day1)
    h.update([("a.com", "nxdomain", True)], day1)
    assert h.get("a.com").count == 1 and h.get("b.com") is None
    h.save()

    h = History.load(path)
    h.update([("a.com", "nxdomain", True), ("c.com", "broken", True)], day2)
    assert (h.get("a.com").count, h.get("a.com").since, h.get("a.com").last) == (2, "2026-09-01", "2026-09-08")
    h.update([("a.com", "servfail", True)], date(2026, 9, 9))
    assert h.get("a.com").count == 1
    h.update([("a.com", "ok", False)], date(2026, 9, 10))
    assert h.get("a.com") is None
    h.forget(["c.com"])
    assert h.domains == {} and h.last_run == "2026-09-10"


def test_history_ignores_corrupt_file(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{not json", encoding="utf-8")
    assert History.load(path).domains == {}


def _cert_error(message):
    exc = ssl.SSLCertVerificationError(1, message)
    exc.verify_message = message
    return exc


def test_tls_problem_only_expired_means_abandoned():
    assert probe._tls_problem(_cert_error("certificate has expired")) == ("TLS-сертификат истек", True)
    assert probe._tls_problem(_cert_error("Hostname mismatch, certificate is not valid for 'x'"))[1] is False
    assert probe._tls_problem(_cert_error("self-signed certificate"))[1] is False


def test_parking_detection():
    http = probe._Http
    assert "sedo.com" in probe._parking(http(302, "https://sedo.com/search?domain=x", ""))
    assert "for sale" in probe._parking(http(200, "", "<h1>This domain is for sale!</h1>"))
    assert probe._parking(http(200, "", "Этот домен продается"))
    assert probe._parking(http(200, "", "Добро пожаловать")) is None
    assert probe._parking(http(200, "", "<title>Срок регистрации домена ист\u0451к</title>"))
    assert probe._parking(http(301, "https://www.example.com/", "moved")) is None


def test_summarize():
    http = probe._Http
    cf = probe._summarize("HTTPS", http(530, "", ""), None)
    assert cf.reachable and "530" in cf.broken
    expired = probe._summarize("HTTPS", http(200, "", ""), ("TLS-сертификат истек", True))
    assert expired.broken == "TLS-сертификат истек"
    mismatch = probe._summarize("HTTPS", http(200, "", ""), ("сертификат на другое имя", False))
    assert mismatch.broken is None and "другое имя" in mismatch.detail
    assert probe._summarize("HTTP", http(404, "", ""), None).broken is None


def test_report_html_is_self_contained_and_escaped():
    data = {"checked_at": "2026-09-22T10:00:00+03:00", "source": "list.txt", "duration_sec": 1.5,
            "channels": [], "warnings": [], "expiring": [],
            "results": [{"domain": "x.com", "label": "работает", "group": "ok", "section": "</script><b>",
                         "line": 1, "note": "", "evidence": [], "confirmed": []}]}
    page = report.render_html(data)
    assert page.startswith("<!doctype html>")
    assert "</script><b>" not in page and "<\\/script><b>" in page
    assert "<link" not in page and " src=" not in page
