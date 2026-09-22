import pytest

from domainlist import build as builder
from domainlist.listfile import ListFile
from domainlist.names import ZoneSet

SHARED = ZoneSet(["b-cdn.net", "sentry.io", "livekit.cloud"])


@pytest.mark.parametrize("domain, key, reason", [
    ("api.console.anthropic.com", "anthropic.com", builder.COLLAPSED),
    ("anthropic.com", "anthropic.com", builder.AS_IS),
    ("marscode.com.cn", "marscode.com.cn", builder.AS_IS),
    ("servd-anthropic-website.b-cdn.net", "servd-anthropic-website.b-cdn.net", builder.SHARED),
    ("o123.ingest.us.sentry.io", "o123.ingest.us.sentry.io", builder.SHARED),
    ("openaicomproductionae4b.blob.core.windows.net",
     "openaicomproductionae4b.blob.core.windows.net", builder.PSL_PRIVATE),
    ("openai.com.cdn.cloudflare.net", "openai.com.cdn.cloudflare.net", builder.PSL_PRIVATE),
    ("exafunction.github.io", "exafunction.github.io", builder.PSL_PRIVATE),
])
def test_routing_key(domain, key, reason):
    assert builder.routing_key(domain, SHARED) == (key, reason)


def _build(text):
    return builder.build(ListFile.parse(text), SHARED)


def test_minimal_cover_and_dedup():
    result = _build(
        "## A\nclaude.ai\nwww.claude.ai\na-cdn.claude.ai\n"
        "chatgpt.turn.livekit.cloud\nturn.livekit.cloud\n"
    )
    assert [r.domain for r in result.routes] == ["claude.ai", "turn.livekit.cloud"]
    assert result.covered == {"chatgpt.turn.livekit.cloud": "turn.livekit.cloud"}


def test_explicit_zone_covers_shared_fqdns():
    result = _build("## Copilot\no1.ingest.us.sentry.io\n## Monitoring\nsentry.io\n")
    assert [(r.domain, r.section) for r in result.routes] == [("sentry.io", "Monitoring")]


def test_literal_entry_wins_placement():
    result = _build("## Copilot\nc.bing.com\n## Search\nbing.com\n")
    assert [(r.domain, r.section) for r in result.routes] == [("bing.com", "Search")]


def test_first_occurrence_placement_without_literal():
    result = _build("## Google\naccounts.google.com\n## Other\ndocs.google.com\n")
    assert [(r.domain, r.section) for r in result.routes] == [("google.com", "Google")]


def test_render_format_and_empty_sections_skipped():
    result = _build("# Заголовок\n\n## A\napi.x.ai\n\n## B\nx.ai\n\n## C\ndata.x.ai\nclaude.ai\n")
    assert builder.render(result) == (
        "# Заголовок\n"
        f"{builder.GENERATED_NOTE}\n"
        "\n## B\n\nx.ai\n"
        "\n## C\n\nclaude.ai\n"
    )


def test_build_ignores_invalid_entries():
    result = _build("## A\nbad..com\nclaude.ai\n")
    assert [r.domain for r in result.routes] == ["claude.ai"]


def test_keenetic_commands_split_evenly():
    domains = [f"d{i}.com" for i in range(7)]
    commands, groups = builder.keenetic_commands(domains, "vpn", "Wireguard0", limit=3, reject=True)
    assert groups == ["vpn", "vpn-2", "vpn-3"]
    includes = [c for c in commands if " include " in c]
    assert len(includes) == 7
    assert includes[0] == "object-group fqdn vpn include d0.com"
    assert sum(c.startswith("object-group fqdn vpn-3 ") for c in commands) == 1
    assert commands[-4:] == [
        "dns-proxy route object-group vpn Wireguard0 auto reject",
        "dns-proxy route object-group vpn-2 Wireguard0 auto reject",
        "dns-proxy route object-group vpn-3 Wireguard0 auto reject",
        "system configuration save",
    ]


def test_keenetic_rejects_bad_group_name():
    with pytest.raises(ValueError):
        builder.keenetic_commands(["a.com"], "bad name", "Wireguard0")
