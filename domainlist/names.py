"""Нормализация и валидация доменных имен, работа с Public Suffix List."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator

import idna
import tldextract

MAX_NAME_LEN = 253
MAX_LABEL_LEN = 63

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_LABEL_RE = re.compile(r"^[a-z0-9_-]+$")

# Встроенный снимок PSL: работает без сети и дает одинаковый результат на любой машине.
_PSL = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


@dataclass
class Normalized:
    domain: str | None = None
    fixes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None


@lru_cache(maxsize=None)
def _extract(domain: str, private: bool) -> tldextract.tldextract.ExtractResult:
    return _PSL(domain, include_psl_private_domains=private)


@lru_cache(maxsize=1)
def _tlds() -> frozenset[str]:
    return frozenset(s for s in _PSL.tlds if "." not in s)


def _is_ip(value: str) -> bool:
    if "." not in value and ":" not in value:
        return False
    try:
        ipaddress.ip_network(value.strip("[]"), strict=False)
    except ValueError:
        return False
    return True


def _find_glued(labels: list[str]) -> tuple[str, str] | None:
    """Ищет склейку двух строк вида ctobsnssdk.comwww.trae.ai."""
    for i in range(1, len(labels) - 1):
        label = labels[i]
        if label.endswith("www") and label[:-3] in _tlds():
            left = ".".join(labels[:i] + [label[:-3]])
            right = ".".join(["www"] + labels[i + 1:])
            return left, right
    return None


def normalize(raw: str) -> Normalized:
    res = Normalized()
    s = raw.strip()
    if not s:
        res.error = "пустая запись"
        return res

    if _is_ip(s):
        res.error = "IP-адрес или подсеть: в списке должны быть только домены"
        return res
    if _SCHEME_RE.match(s) or "/" in s:
        s = _SCHEME_RE.sub("", s)
        s = re.split(r"[/?#]", s, maxsplit=1)[0].rsplit("@", 1)[-1]
        res.fixes.append("URL заменен на домен")
    if _is_ip(s):
        res.error = "IP-адрес или подсеть: в списке должны быть только домены"
        return res
    host, sep, port = s.rpartition(":")
    if sep and port.isdigit():
        s = host
        res.fixes.append("убран порт")
        if _is_ip(s):
            res.error = "IP-адрес или подсеть: в списке должны быть только домены"
            return res

    if s.startswith("*."):
        s = s[2:]
        res.fixes.append("маска *. не нужна: поддомены включаются автоматически")
    elif s.startswith("."):
        s = s.lstrip(".")
        res.fixes.append("убрана точка в начале")
    if s.endswith("."):
        s = s.rstrip(".")
        res.fixes.append("убрана точка в конце")

    if any(c.isspace() for c in s):
        res.error = "пробел внутри имени"
        return res
    if "*" in s:
        res.error = "маска * поддерживается только в начале (*.example.com)"
        return res

    if s != s.lower():
        s = s.lower()
        res.fixes.append("приведено к нижнему регистру")
    if not s.isascii():
        try:
            s = idna.encode(s, uts46=True).decode("ascii")
        except idna.IDNAError as exc:
            res.error = f"некорректное IDN-имя: {exc}"
            return res
        res.fixes.append("IDN переведен в punycode")

    res.error = _validate(s, res.warnings)
    if res.error is None:
        res.domain = s
    return res


def _validate(s: str, warnings: list[str]) -> str | None:
    if len(s) > MAX_NAME_LEN:
        return f"имя длиннее {MAX_NAME_LEN} символов"
    labels = s.split(".")
    if len(labels) < 2:
        return "нет доменной зоны"
    for label in labels:
        if not label:
            return "пустая метка (две точки подряд)"
        if len(label) > MAX_LABEL_LEN:
            return f"метка '{label[:20]}...' длиннее {MAX_LABEL_LEN} символов"
        if not _LABEL_RE.match(label):
            return f"недопустимые символы в '{label}'"
        if label.startswith("-") or label.endswith("-"):
            return f"метка '{label}' начинается или заканчивается дефисом"
    if labels[-1].isdigit():
        return "доменная зона не может быть числом"
    if "_" in s:
        warnings.append("символ _ допустим в DNS, но не в имени хоста")

    ext = _extract(s, True)
    if not ext.suffix:
        return f"неизвестная доменная зона .{labels[-1]}"
    if not ext.domain and not ext.is_private:
        return f"'{s}' - публичная зона, правило накроет все сайты в ней"
    glued = _find_glued(labels)
    if glued:
        return f'похоже на две склеенные строки: "{glued[0]}" и "{glued[1]}"'
    return None


def registrable(domain: str) -> str | None:
    """Домен, зарегистрированный у регистратора (eTLD+1 по ICANN-части PSL)."""
    ext = _extract(domain, False)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None


def under_private_suffix(domain: str) -> bool:
    """Имя лежит в зоне из private-раздела PSL (github.io, azureedge.net и т.д.)."""
    return _extract(domain, True).is_private


def private_suffix(domain: str) -> str | None:
    """Зона из private-раздела PSL, в которой лежит имя: x.github.io -> github.io."""
    ext = _extract(domain, True)
    return ext.suffix if ext.is_private else None


def parents(domain: str) -> Iterator[str]:
    """Родительские домены от ближайшего к корню, без TLD: a.b.c.com -> b.c.com, c.com."""
    labels = domain.split(".")
    for i in range(1, len(labels) - 1):
        yield ".".join(labels[i:])


def is_within(domain: str, zone: str) -> bool:
    return domain == zone or domain.endswith("." + zone)


class ZoneSet:
    """Набор зон с проверкой вхождения домена в любую из них."""

    def __init__(self, zones: Iterable[str] = ()):
        self._zones = frozenset(zones)

    def __len__(self) -> int:
        return len(self._zones)

    def __contains__(self, domain: str) -> bool:
        return self.match(domain) is not None

    def match(self, domain: str) -> str | None:
        if domain in self._zones:
            return domain
        return next((p for p in parents(domain) if p in self._zones), None)

    @classmethod
    def load(cls, path: Path) -> ZoneSet:
        if not path.exists():
            return cls()
        zones = []
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                norm = normalize(line)
                if norm.domain:
                    zones.append(norm.domain)
        return cls(zones)
