"""Чтение и запись list.txt с сохранением структуры (заголовки, комментарии, пустые строки)."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .names import Normalized, normalize

_INLINE_COMMENT_RE = re.compile(r"\s+#")


@dataclass
class Entry:
    raw: str
    line_no: int
    section: str | None
    norm: Normalized
    comment: str = ""

    @property
    def domain(self) -> str | None:
        return self.norm.domain


@dataclass
class Section:
    title: str | None
    line_no: int
    entries: list[Entry] = field(default_factory=list)


@dataclass
class ListFile:
    path: Path
    lines: list[str]
    preamble: list[str]
    sections: list[Section]
    newline: str = "\n"

    @classmethod
    def load(cls, path: Path) -> ListFile:
        data = path.read_bytes().decode("utf-8-sig")
        newline = "\r\n" if "\r\n" in data else "\n"
        return cls.parse(data, path=path, newline=newline)

    @classmethod
    def parse(cls, text: str, path: Path = Path("list.txt"), newline: str = "\n") -> ListFile:
        lines = text.splitlines()
        preamble: list[str] = []
        sections: list[Section] = []
        current: Section | None = None

        for idx, line in enumerate(lines):
            line_no = idx + 1
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("##") and not stripped.startswith("###"):
                current = Section(stripped[2:].strip(), line_no)
                sections.append(current)
                continue
            if stripped.startswith("#"):
                if current is None:
                    preamble.append(stripped)
                continue
            if current is None:
                current = Section(None, line_no)
                sections.append(current)
            value, comment = _split_comment(stripped)
            current.entries.append(Entry(value, line_no, current.title, normalize(value), comment))

        return cls(path, lines, preamble, sections, newline)

    @property
    def entries(self) -> list[Entry]:
        return [e for s in self.sections for e in s.entries]

    def domains(self) -> list[str]:
        """Уникальные валидные домены в порядке появления."""
        return list(dict.fromkeys(e.domain for e in self.entries if e.domain))

    def rewrite(
        self, replace: dict[int, str] | None = None, drop: set[int] | None = None,
        insert_after: dict[int, list[str]] | None = None, append: list[str] | None = None,
    ) -> None:
        """Сохраняет файл: замена, удаление и вставка строк по номерам (1-based), дописывание в конец."""
        replace, drop, insert_after = replace or {}, drop or set(), insert_after or {}
        out = list(insert_after.get(0, []))
        for i, line in enumerate(self.lines, 1):
            if i not in drop:
                out.append(replace.get(i, line))
            out.extend(insert_after.get(i, []))
        if append:
            while out and not out[-1].strip():
                out.pop()
            out.extend(append)
        atomic_write(self.path, self.newline.join(out) + self.newline)

    def remove_domains(self, domains: set[str]) -> int:
        drop = {e.line_no for e in self.entries if e.domain in domains}
        if drop:
            self.rewrite(drop=drop)
        return len(drop)


def _split_comment(line: str) -> tuple[str, str]:
    m = _INLINE_COMMENT_RE.search(line)
    if not m:
        return line, ""
    return line[: m.start()], line[m.start():].strip()


def atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    os.replace(tmp, path)
