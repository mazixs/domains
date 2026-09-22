"""История проверок: сколько проверок подряд домен не работает и с какого дня."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable

from .listfile import atomic_write

VERSION = 1


@dataclass
class Streak:
    status: str
    since: str
    last: str
    count: int


class History:
    """Хранит только неудачные статусы: домен, вернувшийся в строй, из истории пропадает."""

    def __init__(self, path: Path | None, data: dict[str, Streak] | None = None, last_run: str | None = None):
        self.path = path
        self.domains = data or {}
        self.last_run = last_run

    @classmethod
    def load(cls, path: Path | None) -> History:
        if path is None or not path.exists():
            return cls(path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            data = {d: Streak(**s) for d, s in raw.get("domains", {}).items()}
        except (ValueError, TypeError, OSError):
            return cls(path)
        return cls(path, data, raw.get("last_run"))

    def get(self, domain: str) -> Streak | None:
        return self.domains.get(domain)

    def update(self, results: Iterable[tuple[str, str, bool]], today: date | None = None) -> None:
        """results: (домен, статус, неудача ли). Повторный запуск в тот же день счетчик не растит."""
        day = (today or date.today()).isoformat()
        for domain, status, failed in results:
            prev = self.domains.get(domain)
            if not failed:
                self.domains.pop(domain, None)
            elif prev is None or prev.status != status:
                self.domains[domain] = Streak(status, day, day, 1)
            elif prev.last != day:
                self.domains[domain] = Streak(status, prev.since, day, prev.count + 1)
        self.last_run = day

    def forget(self, domains: Iterable[str]) -> None:
        for d in domains:
            self.domains.pop(d, None)

    def save(self) -> None:
        if self.path is None:
            return
        data = {
            "version": VERSION,
            "last_run": self.last_run,
            "domains": {d: vars(s) for d, s in sorted(self.domains.items())},
        }
        atomic_write(self.path, json.dumps(data, ensure_ascii=False, indent=1) + "\n")
