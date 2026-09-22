from domainlist.listfile import ListFile

SAMPLE = """# Список доменов

## Alpha

claude.ai
www.claude.ai  # веб
# отключено: old.claude.ai

## Beta (сервис)

discord.com
"""


def test_parse_structure():
    doc = ListFile.parse(SAMPLE)
    assert doc.preamble == ["# Список доменов"]
    assert [s.title for s in doc.sections] == ["Alpha", "Beta (сервис)"]
    assert [e.domain for e in doc.entries] == ["claude.ai", "www.claude.ai", "discord.com"]
    www = doc.entries[1]
    assert www.comment == "# веб" and www.line_no == 6 and www.section == "Alpha"


def test_entries_before_first_section():
    doc = ListFile.parse("claude.ai\n\n## Beta\nx.com\n")
    assert doc.sections[0].title is None
    assert doc.entries[0].section is None


def test_domains_are_unique_and_ordered():
    doc = ListFile.parse("## A\nb.com\na.com\n## B\nb.com\nc.com\n")
    assert doc.domains() == ["b.com", "a.com", "c.com"]


def test_remove_domains_keeps_structure(tmp_path):
    path = tmp_path / "list.txt"
    path.write_text(SAMPLE, encoding="utf-8")
    doc = ListFile.load(path)
    assert doc.remove_domains({"www.claude.ai", "discord.com"}) == 2
    text = path.read_text(encoding="utf-8")
    assert "www.claude.ai" not in text and "discord.com" not in text
    assert "# отключено: old.claude.ai" in text
    assert "## Beta (сервис)" in text
    assert text.endswith("\n")


def test_crlf_and_bom_preserved(tmp_path):
    path = tmp_path / "list.txt"
    path.write_bytes("﻿## A\r\na.com\r\nb.com\r\n".encode("utf-8"))
    doc = ListFile.load(path)
    assert doc.sections[0].title == "A"
    doc.remove_domains({"a.com"})
    assert path.read_bytes() == b"## A\r\nb.com\r\n"
