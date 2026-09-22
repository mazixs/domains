import pytest

from domainlist import build as builder, edit, names
from domainlist.listfile import ListFile

TEXT = """# Список

## Anthropic Claude

claude.ai
api.anthropic.com

## OpenAI ChatGPT

openai.com

## CDN

servd-anthropic-website.b-cdn.net
"""


@pytest.fixture
def doc(tmp_path):
    path = tmp_path / "list.txt"
    path.write_text(TEXT, encoding="utf-8")
    return ListFile.load(path)


SHARED = names.ZoneSet(["b-cdn.net"])


def test_find_section(doc):
    assert edit.find_section(doc, "cdn").title == "CDN"
    assert edit.find_section(doc, "openai").title == "OpenAI ChatGPT"
    with pytest.raises(edit.EditError, match="не найден"):
        edit.find_section(doc, "telegram")
    with pytest.raises(edit.EditError, match="нескольким"):
        edit.find_section(doc, "a")


def test_guess_section(doc):
    assert edit.guess_section(doc, "status.anthropic.com", SHARED).title == "Anthropic Claude"
    assert edit.guess_section(doc, "chat.openai.com", SHARED).title == "OpenAI ChatGPT"
    assert edit.guess_section(doc, "other.b-cdn.net", SHARED) is None
    assert edit.guess_section(doc, "unknown.org", SHARED) is None


def test_add_to_existing_and_new_sections(doc):
    edit.add(doc, [("claude.com", "Anthropic Claude"), ("t.me", "Telegram"), ("telegram.org", "Telegram")])
    lines = doc.path.read_text(encoding="utf-8").splitlines()
    assert lines[lines.index("api.anthropic.com") + 1] == "claude.com"
    assert lines[-5:] == ["", "## Telegram", "", "t.me", "telegram.org"]


def test_add_into_empty_section(tmp_path):
    path = tmp_path / "list.txt"
    path.write_text("## A\n\n## B\n\nb.com\n", encoding="utf-8")
    edit.add(ListFile.load(path), [("a.com", "A")])
    assert path.read_text(encoding="utf-8") == "## A\n\na.com\n\n## B\n\nb.com\n"
    path.write_text("## A\n## B\nb.com\n", encoding="utf-8")
    edit.add(ListFile.load(path), [("a.com", "A")])
    assert path.read_text(encoding="utf-8") == "## A\na.com\n## B\nb.com\n"


def test_remove_drops_emptied_sections(doc):
    assert edit.remove(doc, {"openai.com", "servd-anthropic-website.b-cdn.net"}) == 2
    text = doc.path.read_text(encoding="utf-8")
    assert "## OpenAI" not in text and "## CDN" not in text
    assert text.endswith("\napi.anthropic.com\n")
    assert edit.remove(ListFile.load(doc.path), {"nothing.com"}) == 0


def test_remove_keeps_section_with_comments(tmp_path):
    path = tmp_path / "list.txt"
    path.write_text("## A\n# важно\na.com\n\n## B\nb.com\n", encoding="utf-8")
    edit.remove(ListFile.load(path), {"a.com"})
    assert path.read_text(encoding="utf-8") == "## A\n# важно\n\n## B\nb.com\n"


def test_matching_and_coverage(doc):
    assert [e.domain for e in edit.matching(doc, "anthropic.com")] == []
    assert [e.domain for e in edit.matching(doc, "anthropic.com", subdomains=True)] == ["api.anthropic.com"]
    result = builder.build(doc, SHARED)

    cov = edit.coverage(doc, result, "code.claude.ai", SHARED)
    assert [e.domain for e in cov.parents] == ["claude.ai"] and cov.route.domain == "claude.ai"
    cov = edit.coverage(doc, result, "console.anthropic.com", SHARED)
    assert cov.parents == [] and cov.route.domain == "anthropic.com"
    cov = edit.coverage(doc, result, "other.b-cdn.net", SHARED)
    assert cov.route is None and cov.shared_zone == "b-cdn.net"
    cov = edit.coverage(doc, result, "x.github.io", SHARED)
    assert cov.route is None and cov.shared_zone == "github.io"
