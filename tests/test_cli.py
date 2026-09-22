import json

import pytest

from domainlist import checker, cli
from domainlist.checker import CheckReport, Result, Status

LIST = "# Заголовок\n\n## A\n\napi.claude.ai\ndead.claude.ai\n\n## B\n\ngone.example\nx.ai\n"


@pytest.fixture
def files(tmp_path):
    src = tmp_path / "list.txt"
    src.write_text(LIST.replace("gone.example", "gone-domain.com"), encoding="utf-8")
    return src, tmp_path / "out.txt", tmp_path / "shared.txt"


def run(*argv):
    return cli.main([str(a) for a in argv])


def test_build_then_check(files, capsys):
    src, out, shared = files
    assert run("build", "-f", src, "-o", out, "--shared", shared, "--check") == 1
    assert run("build", "-f", src, "-o", out, "--shared", shared) == 0
    assert "claude.ai" in out.read_text(encoding="utf-8")
    assert run("build", "-f", src, "-o", out, "--shared", shared, "--check") == 0


def test_build_refuses_on_errors(files, capsys):
    src, out, shared = files
    src.write_text("## A\nbad..com\n", encoding="utf-8")
    assert run("build", "-f", src, "-o", out, "--shared", shared) == 1
    assert not out.exists()
    assert "пустая метка" in capsys.readouterr().out


def test_lint_exit_codes(files):
    src, _, _ = files
    assert run("lint", "-f", src) == 0
    src.write_text("## A\nClaude.AI\n", encoding="utf-8")
    assert run("lint", "-f", src) == 0
    assert run("lint", "-f", src, "--strict") == 1
    assert run("lint", "-f", src, "--fix", "--strict") == 0
    assert src.read_text(encoding="utf-8") == "## A\nclaude.ai\n"


def test_missing_file_is_usage_error(tmp_path):
    assert run("lint", "-f", tmp_path / "nope.txt") == 2


def _fake_report(statuses, confirmed=("DNS", "DoH")):
    async def fake_run_check(domains, **kwargs):
        results = [
            Result(d, statuses.get(d, Status.OK), note="n", evidence=["DNS: x"],
                   confirmed=list(confirmed) if statuses.get(d) else [])
            for d in domains
        ]
        return CheckReport(results, ["s1"], [], 0.1, channels=["DNS: s1"])
    return fake_run_check


def test_check_removes_nxdomain_with_yes(files, monkeypatch, capsys):
    src, _, _ = files
    monkeypatch.setattr(checker, "run_check", _fake_report({
        "dead.claude.ai": Status.NXDOMAIN, "gone-domain.com": Status.PARKED,
    }))
    report = src.parent / "report.json"
    html = src.parent / "report.html"
    assert run("check", "-f", src, "--yes", "--json", report, "--html", html) == 0
    text = src.read_text(encoding="utf-8")
    assert "dead.claude.ai" not in text
    assert "gone-domain.com" in text
    data = json.loads(report.read_text(encoding="utf-8"))
    by_domain = {r["domain"]: r for r in data["results"]}
    assert by_domain["dead.claude.ai"]["status"] == "nxdomain"
    assert by_domain["dead.claude.ai"]["group"] == "remove"
    assert by_domain["dead.claude.ai"]["confirmed"] == ["DNS", "DoH"]
    assert by_domain["dead.claude.ai"]["locations"] == [{"line": 6, "section": "A"}]
    assert data["channels"] == ["DNS: s1"]
    assert "dead.claude.ai" in html.read_text(encoding="utf-8")
    state = json.loads((src.parent / ".domains-state.json").read_text(encoding="utf-8"))
    assert list(state["domains"]) == ["gone-domain.com"]


def test_yes_needs_two_confirmations_history_counts(files, monkeypatch, capsys):
    src, _, _ = files
    monkeypatch.setattr(checker, "run_check", _fake_report({"dead.claude.ai": Status.NXDOMAIN}, confirmed=["DoH"]))
    assert run("check", "-f", src, "--yes") == 1
    assert "dead.claude.ai" in src.read_text(encoding="utf-8")
    assert "одним каналом" in capsys.readouterr().out

    state = src.parent / ".domains-state.json"
    data = json.loads(state.read_text(encoding="utf-8"))
    data["domains"]["dead.claude.ai"].update(since="2026-01-01", last="2026-01-01")
    state.write_text(json.dumps(data), encoding="utf-8")
    assert run("check", "-f", src, "--yes") == 0
    assert "dead.claude.ai" not in src.read_text(encoding="utf-8")
    assert "история (2-я проверка подряд с 2026-01-01)" in capsys.readouterr().out
    assert json.loads(state.read_text(encoding="utf-8"))["domains"] == {}


def test_check_failed_rechecks_only_history(files, monkeypatch, capsys):
    src, _, _ = files
    seen = []

    def fake(statuses):
        inner = _fake_report(statuses)

        async def wrapper(domains, **kwargs):
            seen.append(list(domains))
            return await inner(domains, **kwargs)
        return wrapper

    assert run("check", "-f", src, "--failed") == 0
    assert "нет проблемных" in capsys.readouterr().out
    monkeypatch.setattr(checker, "run_check", fake({"x.ai": Status.BROKEN}))
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    assert run("check", "-f", src) == 0
    assert run("check", "-f", src, "--failed") == 0
    assert seen[-1] == ["x.ai"]
    assert run("check", "x.ai", "--failed") == 2


def test_check_without_tty_does_not_modify(files, monkeypatch):
    src, _, _ = files
    monkeypatch.setattr(checker, "run_check", _fake_report({"dead.claude.ai": Status.NXDOMAIN}))
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    before = src.read_text(encoding="utf-8")
    assert run("check", "-f", src) == 1
    assert src.read_text(encoding="utf-8") == before


def test_check_interactive_select(files, monkeypatch):
    src, _, _ = files
    monkeypatch.setattr(checker, "run_check", _fake_report({
        "dead.claude.ai": Status.NXDOMAIN, "gone-domain.com": Status.SERVFAIL,
    }))
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    answers = iter(["s", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert run("check", "-f", src) == 1
    text = src.read_text(encoding="utf-8")
    assert "dead.claude.ai" in text and "gone-domain.com" not in text


def test_check_section_filter(files, monkeypatch):
    src, _, _ = files
    seen = {}

    async def fake(domains, **kwargs):
        seen["domains"] = list(domains)
        return CheckReport([Result(d, Status.OK) for d in domains], ["s1"], [], 0.1)

    monkeypatch.setattr(checker, "run_check", fake)
    assert run("check", "-f", src, "-s", "b") == 0
    assert seen["domains"] == ["gone-domain.com", "x.ai"]
    assert run("check", "-f", src, "-s", "zzz") == 2


def test_keenetic_output(files, capsys):
    src, _, shared = files
    assert run("keenetic", "-f", src, "--shared", shared, "-i", "Wireguard0", "--limit", "2") == 0
    lines = capsys.readouterr().out.splitlines()
    assert "object-group fqdn vpn include claude.ai" in lines
    assert lines[-1] == "system configuration save"
    assert sum(line.startswith("dns-proxy route") for line in lines) == 2


@pytest.mark.parametrize("n, text", [
    (1, "1 список"), (2, "2 списка"), (5, "5 списков"), (11, "11 списков"), (21, "21 список"), (112, "112 списков"),
])
def test_plural(n, text):
    assert cli.plural(n, "список", "списка", "списков") == text


def test_build_output_is_lf_and_crlf_counts_as_stale(files):
    src, out, shared = files
    assert run("build", "-f", src, "-o", out, "--shared", shared) == 0
    out.write_bytes(out.read_bytes().replace(b"\n", b"\r\n"))
    assert run("build", "-f", src, "-o", out, "--shared", shared, "--check") == 1
    assert run("build", "-f", src, "-o", out, "--shared", shared) == 0
    assert b"\r\n" not in out.read_bytes()


def test_default_command_is_status(files, monkeypatch, capsys):
    src, _, _ = files
    monkeypatch.setattr(cli, "DEFAULT_LIST", src)
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "4 домена" in out and "Частые команды" in out and "Проверок еще не было" in out


def test_add_places_domain_and_rebuilds(files, monkeypatch, capsys):
    src, _, _ = files
    target = src.with_name("list_2nd_level.txt")
    assert run("build", "-f", src, "-o", target) == 0
    monkeypatch.setattr(checker, "run_check", _fake_report({}))
    assert run("add", "-f", src, "https://www.brand-new.net/page", "new-service.org", "--new", "C") == 0
    text = src.read_text(encoding="utf-8")
    assert text.endswith("## C\n\nwww.brand-new.net\nnew-service.org\n")
    assert "new-service.org" in target.read_text(encoding="utf-8")
    out = capsys.readouterr().out
    assert "+ new-service.org" in out and "Добавлен new-service.org" in out

    assert run("add", "-f", src, "status.claude.ai", "www.gone-domain.com") == 0
    out = capsys.readouterr().out
    assert "уже маршрутизируется через claude.ai" in out and "уже покрыт gone-domain.com" in out


def test_add_guesses_section_and_skips_typos(files, monkeypatch, capsys):
    src, _, _ = files
    monkeypatch.setattr(checker, "run_check", _fake_report({"typo-domain.com": Status.NXDOMAIN}))
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    assert run("add", "-f", src, "typo-domain.com", "-s", "B") == 1
    assert "Опечатка" in capsys.readouterr().out
    assert run("add", "-f", src, "api.x.ai", "--force") == 0
    lines = src.read_text(encoding="utf-8").splitlines()
    assert lines[lines.index("x.ai") + 1] == "api.x.ai"
    assert run("add", "-f", src, "unrelated.org", "--no-check") == 2
    assert "укажите -s" in capsys.readouterr().err


def test_rm_and_where(files, capsys):
    src, _, _ = files
    assert run("where", "-f", src, "code.claude.ai") == 0
    assert "через claude.ai" in capsys.readouterr().out
    assert run("rm", "-f", src, "x.ai", "nothere.com") == 1
    out = capsys.readouterr().out
    assert "x.ai" not in src.read_text(encoding="utf-8") and "nothere.com: в list.txt нет" in out
    assert run("where", "-f", src, "x.ai") == 1
    assert run("rm", "-f", src, "claude.ai", "--sub") == 0
    assert "claude.ai" not in src.read_text(encoding="utf-8")
    assert "## A" not in src.read_text(encoding="utf-8")


def test_add_interactive_section_choice(files, monkeypatch, capsys):
    src, _, _ = files
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    answers = iter(["2", "Новый", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert run("add", "-f", src, "first.org", "second.org", "--no-check") == 0
    lines = src.read_text(encoding="utf-8").splitlines()
    assert lines[lines.index("x.ai") + 1] == "first.org"
    assert lines[-3:] == ["## Новый", "", "second.org"]
