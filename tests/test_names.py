import pytest

from domainlist import names


@pytest.mark.parametrize("raw, expected, fix", [
    ("Claude.AI", "claude.ai", "регистр"),
    ("https://claude.ai/new?x=1", "claude.ai", "URL"),
    ("http://user@api.github.com:8443/path", "api.github.com", "URL"),
    ("*.discord.com", "discord.com", "маска"),
    (".discord.com", "discord.com", "точка в начале"),
    ("discord.com.", "discord.com", "точка в конце"),
    ("api.github.com:443", "api.github.com", "порт"),
    ("пример.рф", "xn--e1afmkfd.xn--p1ai", "punycode"),
])
def test_normalize_fixes(raw, expected, fix):
    res = names.normalize(raw)
    assert res.domain == expected
    assert res.error is None
    assert any(fix in f for f in res.fixes)


def test_normalize_clean_domain_has_no_fixes():
    res = names.normalize("  claude.ai  ")
    assert res.domain == "claude.ai" and not res.fixes and not res.warnings


@pytest.mark.parametrize("raw, error", [
    ("1.2.3.4", "IP"),
    ("10.0.0.0/8", "IP"),
    ("2001:db8::1", "IP"),
    ("1.2.3.4:80", "IP"),
    ("localhost", "зоны"),
    ("foo.local", "неизвестная доменная зона"),
    ("co.uk", "публичная зона"),
    ("a..b.com", "пустая метка"),
    ("-bad.com", "дефисом"),
    ("bad-.com", "дефисом"),
    ("bad!.com", "недопустимые символы"),
    ("a" * 64 + ".com", "длиннее 63"),
    ("foo bar.com", "пробел"),
    ("foo.*.com", "маска"),
    ("example.123", "числом"),
    ("ctobsnssdk.comwww.trae.ai", "склеенные"),
])
def test_normalize_errors(raw, error):
    res = names.normalize(raw)
    assert res.domain is None
    assert error in res.error


def test_glued_suggests_split():
    res = names.normalize("ctobsnssdk.comwww.trae.ai")
    assert '"ctobsnssdk.com"' in res.error and '"www.trae.ai"' in res.error


def test_real_www_prefixed_names_are_not_glued():
    assert names.normalize("wwwinstagram.com").domain == "wwwinstagram.com"
    assert names.normalize("www.claude.ai").domain == "www.claude.ai"


def test_underscore_is_warning():
    res = names.normalize("_dmarc.example.com")
    assert res.domain == "_dmarc.example.com"
    assert res.warnings


def test_private_suffix_itself_is_allowed():
    assert names.normalize("github.io").domain == "github.io"
    assert names.normalize("googleapis.com").domain == "googleapis.com"


def test_registrable():
    assert names.registrable("api.console.anthropic.com") == "anthropic.com"
    assert names.registrable("marscode.com.cn") == "marscode.com.cn"
    assert names.registrable("app.adjust.net.in") == "adjust.net.in"
    assert names.registrable("exafunction.github.io") == "github.io"
    assert names.registrable("co.uk") is None


def test_under_private_suffix():
    assert names.under_private_suffix("exafunction.github.io")
    assert names.under_private_suffix("openai.com.cdn.cloudflare.net")
    assert not names.under_private_suffix("api.openai.com")


def test_parents():
    assert list(names.parents("a.b.example.com")) == ["b.example.com", "example.com"]
    assert list(names.parents("example.com")) == []


def test_zone_set(tmp_path):
    path = tmp_path / "zones.txt"
    path.write_text("# comment\n## CDN\n\nb-cdn.net\nSentry.IO  # tenant subdomains\n", encoding="utf-8")
    zones = names.ZoneSet.load(path)
    assert len(zones) == 2
    assert zones.match("x.y.b-cdn.net") == "b-cdn.net"
    assert "sentry.io" in zones
    assert "notb-cdn.net" not in zones
    assert len(names.ZoneSet.load(tmp_path / "missing.txt")) == 0
