"""Сборка списка для маршрутизации: схлопывание до 2-го уровня и минимальное покрытие."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from . import names
from .listfile import Entry, ListFile

KEENETIC_LIST_LIMIT = 300
GENERATED_NOTE = "# Собрано автоматически из list.txt: python domains.py build. Руками не редактировать."

COLLAPSED = "collapsed"
AS_IS = "as-is"
SHARED = "shared"
PSL_PRIVATE = "psl-private"


@dataclass
class Route:
    domain: str
    section: str | None
    line_no: int


@dataclass
class BuildResult:
    preamble: list[str]
    routes: list[Route]
    keys: dict[str, tuple[str, str]] = field(default_factory=dict)
    covered: dict[str, str] = field(default_factory=dict)

    def count(self, reason: str) -> int:
        return sum(1 for d, (k, r) in self.keys.items() if r == reason)


def routing_key(domain: str, shared: names.ZoneSet) -> tuple[str, str]:
    """Во что превращается запись в итоговом списке и почему."""
    if domain in shared:
        return domain, SHARED
    if names.under_private_suffix(domain):
        return domain, PSL_PRIVATE
    reg = names.registrable(domain) or domain
    return reg, (AS_IS if reg == domain else COLLAPSED)


def build(doc: ListFile, shared: names.ZoneSet) -> BuildResult:
    entries = [e for e in doc.entries if e.domain]
    keys: dict[str, tuple[str, str]] = {}
    for e in entries:
        if e.domain not in keys:
            keys[e.domain] = routing_key(e.domain, shared)

    all_keys = {k for k, _ in keys.values()}
    covered: dict[str, str] = {}
    for key in all_keys:
        # parents() идет от ближайшего родителя к корню, запоминаем самый верхний.
        for parent in names.parents(key):
            if parent in all_keys:
                covered[key] = parent
    final = all_keys - covered.keys()

    # Раздел для записи: где она указана буквально, иначе где встретилась впервые.
    placement: dict[str, Entry] = {}
    for e in entries:
        if e.domain in final:
            placement.setdefault(e.domain, e)
    for e in entries:
        key = keys[e.domain][0]
        if key in final:
            placement.setdefault(key, e)

    routes = sorted(
        (Route(k, e.section, e.line_no) for k, e in placement.items()),
        key=lambda r: r.line_no,
    )
    return BuildResult(doc.preamble, routes, keys, covered)


def render(result: BuildResult) -> str:
    out = list(result.preamble) + [GENERATED_NOTE]
    current: object = object()
    for route in result.routes:
        if route.section != current:
            current = route.section
            if route.section is not None:
                out += ["", f"## {route.section}"]
            out.append("")
        out.append(route.domain)
    return "\n".join(out) + "\n"


_GROUP_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def keenetic_commands(
    domains: list[str], group: str, interface: str,
    limit: int = KEENETIC_LIST_LIMIT, reject: bool = False,
) -> tuple[list[str], list[str]]:
    """CLI-команды KeeneticOS 5.x. Возвращает (команды, имена групп)."""
    if not _GROUP_NAME_RE.match(group):
        raise ValueError("имя группы: латиница, цифры, - и _, до 32 символов")
    if not domains:
        return [], []
    chunks_count = math.ceil(len(domains) / limit)
    size = math.ceil(len(domains) / chunks_count)
    groups = [group if i == 0 else f"{group}-{i + 1}" for i in range(chunks_count)]

    commands = []
    for i, name in enumerate(groups):
        commands += [f"object-group fqdn {name} include {d}" for d in domains[i * size:(i + 1) * size]]
    suffix = " auto reject" if reject else " auto"
    commands += [f"dns-proxy route object-group {name} {interface}{suffix}" for name in groups]
    commands.append("system configuration save")
    return commands, groups
