"""Статическая проверка list.txt: синтаксис, дубли, мусор. Сеть не нужна."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .listfile import Entry, ListFile


class Level(IntEnum):
    INFO = 0
    WARNING = 1
    ERROR = 2


LEVEL_NAMES = {Level.INFO: "инфо", Level.WARNING: "предупреждение", Level.ERROR: "ошибка"}


@dataclass
class Issue:
    level: Level
    line_no: int
    message: str
    fixable: bool = False


def lint(doc: ListFile) -> list[Issue]:
    issues: list[Issue] = []

    for line_no, line in enumerate(doc.lines, 1):
        if line != line.strip():
            issues.append(Issue(Level.WARNING, line_no, "лишние пробелы в начале или конце строки", True))

    for section in doc.sections:
        if not section.entries:
            issues.append(Issue(Level.WARNING, section.line_no, f'раздел "{section.title}" пуст'))

    first_seen: dict[str, Entry] = {}
    first_in_section: dict[tuple[str | None, str], Entry] = {}
    for entry in doc.entries:
        norm = entry.norm
        if norm.error:
            issues.append(Issue(Level.ERROR, entry.line_no, f"{entry.raw}: {norm.error}"))
            continue
        if norm.fixes:
            issues.append(Issue(
                Level.WARNING, entry.line_no,
                f"{entry.raw} -> {norm.domain}: {', '.join(norm.fixes)}", True,
            ))
        for warning in norm.warnings:
            issues.append(Issue(Level.WARNING, entry.line_no, f"{norm.domain}: {warning}"))

        first = first_seen.setdefault(norm.domain, entry)
        first_here = first_in_section.setdefault((entry.section, norm.domain), entry)
        if first_here is not entry:
            issues.append(Issue(
                Level.WARNING, entry.line_no,
                f"{norm.domain}: повтор в том же разделе (первый раз в строке {first_here.line_no})", True,
            ))
        elif first is not entry:
            issues.append(Issue(
                Level.INFO, entry.line_no,
                f'{norm.domain}: уже есть в разделе "{first.section}" (строка {first.line_no})',
            ))

    issues.sort(key=lambda i: (i.line_no, -i.level))
    return issues


def fix(doc: ListFile) -> int:
    """Исправляет то, что можно исправить автоматически. Возвращает число измененных строк."""
    replace: dict[int, str] = {}
    drop: set[int] = set()

    for line_no, line in enumerate(doc.lines, 1):
        if line != line.strip():
            replace[line_no] = line.strip()

    seen: set[tuple[str | None, str]] = set()
    for entry in doc.entries:
        if not entry.domain:
            continue
        key = (entry.section, entry.domain)
        if key in seen:
            drop.add(entry.line_no)
            continue
        seen.add(key)
        if entry.norm.fixes:
            replace[entry.line_no] = entry.domain + (f"  {entry.comment}" if entry.comment else "")

    changed = len(drop) + len(set(replace) - drop)
    if changed:
        doc.rewrite(replace, drop)
    return changed
