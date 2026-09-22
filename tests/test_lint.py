from domainlist.lint import Level, fix, lint
from domainlist.listfile import ListFile


def _issues(text):
    return lint(ListFile.parse(text))


def test_clean_file_has_no_issues():
    assert _issues("# t\n\n## A\n\nclaude.ai\nwww.claude.ai\n") == []


def test_errors_and_fixable_warnings():
    issues = _issues("## A\nctobsnssdk.comwww.trae.ai\nHTTPS://Claude.ai/\n")
    assert [(i.level, i.line_no, i.fixable) for i in issues] == [
        (Level.ERROR, 2, False),
        (Level.WARNING, 3, True),
    ]


def test_duplicates_same_section_vs_cross_section():
    issues = _issues("## A\na.com\na.com\n## B\na.com\na.com\n")
    by_line = {i.line_no: i for i in issues}
    assert by_line[3].level is Level.WARNING and by_line[3].fixable
    assert by_line[5].level is Level.INFO and "A" in by_line[5].message
    assert by_line[6].level is Level.WARNING and by_line[6].fixable


def test_normalized_duplicates_are_detected():
    issues = _issues("## A\nclaude.ai\nClaude.AI.\n")
    assert any("повтор" in i.message for i in issues)


def test_empty_section_and_trailing_spaces():
    issues = _issues("## Empty \n## B\nb.com\n")
    messages = [i.message for i in issues]
    assert any("пуст" in m for m in messages)
    assert any("пробелы" in m for m in messages)


def test_fix_rewrites_file(tmp_path):
    path = tmp_path / "list.txt"
    path.write_text(
        "## A \n*.Claude.ai  # note\nclaude.ai\nbad..com\n## B\nclaude.ai\n", encoding="utf-8"
    )
    changed = fix(ListFile.load(path))
    assert changed == 3
    assert path.read_text(encoding="utf-8") == "## A\nclaude.ai  # note\nbad..com\n## B\nclaude.ai\n"
    remaining = lint(ListFile.load(path))
    assert [i.level for i in remaining] == [Level.ERROR, Level.INFO]
