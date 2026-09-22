"""Правка list.txt из командной строки: куда добавить домен, что удалить, чем покрыт домен."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from . import build as builder, names
from .listfile import Entry, ListFile, Section


class EditError(ValueError):
    pass


def find_section(doc: ListFile, needle: str) -> Section:
    """Раздел по точному названию или однозначной подстроке."""
    titled = [s for s in doc.sections if s.title]
    exact = [s for s in titled if s.title.lower() == needle.lower()]
    if exact:
        return exact[0]
    found = [s for s in titled if needle.lower() in s.title.lower()]
    if len(found) == 1:
        return found[0]
    if not found:
        raise EditError(f'раздел "{needle}" не найден (новый раздел: --new "{needle}")')
    raise EditError(f'"{needle}" подходит к нескольким разделам: ' + ", ".join(f'"{s.title}"' for s in found))


def guess_section(doc: ListFile, domain: str, shared: names.ZoneSet) -> Section | None:
    """Раздел, где уже живут родственные домены: тот же зарегистрированный домен или родитель.

    Для общих зон (CDN, облака) родство по зарегистрированному домену не считается:
    x.b-cdn.net и y.b-cdn.net могут принадлежать разным сервисам.
    """
    _, reason = builder.routing_key(domain, shared)
    reg = names.registrable(domain)
    by_zone = reason in (builder.COLLAPSED, builder.AS_IS) and reg

    def related(e: Entry) -> bool:
        if not e.domain or not e.section:
            return False
        if names.is_within(domain, e.domain) or names.is_within(e.domain, domain):
            return True
        return bool(by_zone) and names.registrable(e.domain) == reg

    counts = Counter(e.section for e in doc.entries if related(e))
    if not counts:
        return None
    title = counts.most_common(1)[0][0]
    return next(s for s in doc.sections if s.title == title)


def add(doc: ListFile, placements: list[tuple[str, str]]) -> None:
    """placements: (домен, название раздела). Несуществующие разделы создаются в конце файла."""
    by_title = {s.title: s for s in doc.sections if s.title}
    insert: dict[int, list[str]] = {}
    new_sections: dict[str, list[str]] = {}
    for domain, title in placements:
        section = by_title.get(title)
        if section is None:
            new_sections.setdefault(title, []).append(domain)
            continue
        if section.entries:
            insert.setdefault(section.entries[-1].line_no, []).append(domain)
        else:
            # Пустой раздел: вставка сразу после заголовка, пустая строка за ним остается разделителем.
            nxt = section.line_no
            blank = nxt < len(doc.lines) and not doc.lines[nxt].strip()
            insert.setdefault(nxt, [""] if blank else []).append(domain)

    append: list[str] = []
    for title, domains in new_sections.items():
        append += ["", f"## {title}", "", *domains]
    doc.rewrite(insert_after=insert, append=append or None)


def remove(doc: ListFile, domains: set[str]) -> int:
    """Удаляет записи; раздел, в котором не осталось ничего, кроме пустых строк, удаляется целиком."""
    drop = {e.line_no for e in doc.entries if e.domain in domains}
    if not drop:
        return 0
    removed = len(drop)
    starts = [s.line_no for s in doc.sections if s.title] + [len(doc.lines) + 1]
    for start, end in zip(starts, starts[1:]):
        body = range(start + 1, end)
        if any(i in drop for i in body) and all(i in drop or not doc.lines[i - 1].strip() for i in body):
            drop.update(range(start, end))
            # У последнего раздела убираются и пустые строки перед заголовком.
            while end > len(doc.lines) and start > 1 and (start - 1 in drop or not doc.lines[start - 2].strip()):
                start -= 1
                drop.add(start)
    doc.rewrite(drop=drop)
    return removed


def matching(doc: ListFile, domain: str, subdomains: bool = False) -> list[Entry]:
    return [
        e for e in doc.entries
        if e.domain and (e.domain == domain or (subdomains and names.is_within(e.domain, domain)))
    ]


@dataclass
class Coverage:
    domain: str
    exact: list[Entry] = field(default_factory=list)
    parents: list[Entry] = field(default_factory=list)
    route: builder.Route | None = None
    shared_zone: str | None = None


def coverage(doc: ListFile, result: builder.BuildResult, domain: str, shared: names.ZoneSet) -> Coverage:
    entries = [e for e in doc.entries if e.domain]
    route = next((r for r in result.routes if names.is_within(domain, r.domain)), None)
    zone = shared.match(domain) or names.private_suffix(domain)
    return Coverage(
        domain,
        exact=[e for e in entries if e.domain == domain],
        parents=[e for e in entries if e.domain != domain and names.is_within(domain, e.domain)],
        route=route,
        shared_zone=zone if route is None else None,
    )
