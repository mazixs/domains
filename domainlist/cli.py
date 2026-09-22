"""Командная строка: python domains.py [status|add|rm|where|lint|build|check|keenetic]."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Callable, Sequence

from . import build as builder
from . import checker, edit, lint as linter, names, report as html_report
from .checker import Status
from .history import History, Streak
from .listfile import Entry, ListFile, atomic_write
from .rdap import Rdap


def _find_root() -> Path:
    """Папка со списком: текущая, если в ней есть list.txt, иначе папка проекта."""
    cwd = Path.cwd()
    if (cwd / "list.txt").exists():
        return cwd
    return Path(__file__).resolve().parent.parent


ROOT = _find_root()
DEFAULT_LIST = ROOT / "list.txt"
OUT_NAME = "list_2nd_level.txt"
SHARED_NAME = "shared_infra.txt"
STATE_NAME = ".domains-state.json"
RDAP_CACHE = Path(".cache") / "rdap-dns.json"

STATUS_INFO = {
    Status.OK: ("работает", "32"),
    Status.NO_CONNECT: ("DNS есть, сервер молчит", "36"),
    Status.NO_ADDRESS: ("имя есть, адресов нет", "36"),
    Status.PARKED: ("припаркован или брошен", "33"),
    Status.SINKHOLE: ("служебный IP", "33"),
    Status.BROKEN: ("сервис сломан (TLS/HTTP)", "33"),
    Status.SERVFAIL: ("сломан DNS", "33"),
    Status.NXDOMAIN: ("не существует", "31"),
    Status.UNKNOWN: ("не удалось проверить", "35"),
}
FAILING = frozenset({Status.NXDOMAIN, Status.SERVFAIL})
MIN_CONFIRMATIONS = 2


def status_group(status: Status) -> str:
    if status is Status.OK:
        return "ok"
    if status in checker.KEEP:
        return "keep"
    if status in checker.REVIEW:
        return "review"
    if status in checker.REMOVE:
        return "remove"
    return "unknown"


class CliError(Exception):
    pass


class Style:
    def __init__(self, stream):
        self.enabled = (
            hasattr(stream, "isatty") and stream.isatty()
            and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
        )

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text


out = Style(sys.stdout)


def plural(n: int, one: str, few: str, many: str) -> str:
    if n % 10 == 1 and n % 100 != 11:
        return f"{n} {one}"
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return f"{n} {few}"
    return f"{n} {many}"


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def _load(path: Path) -> ListFile:
    if not path.exists():
        raise CliError(f"файл не найден: {path}")
    return ListFile.load(path)


def _normalize_all(raw: Sequence[str], strict: bool = True) -> list[str]:
    """Нормализует аргументы, печатает автоисправления. strict: ошибка прерывает команду."""
    domains = []
    for value in raw:
        norm = names.normalize(value)
        if not norm.domain:
            if strict:
                raise CliError(f"{value}: {norm.error}")
            print(out(f"{value}: {norm.error}", "31"))
            continue
        if norm.fixes and norm.domain != value:
            print(out(f"{value} -> {norm.domain} ({', '.join(norm.fixes)})", "2"))
        domains.append(norm.domain)
    return list(dict.fromkeys(domains))


def _where(doc: ListFile, entry: Entry) -> str:
    section = f" [{entry.section}]" if entry.section else ""
    return f"{doc.path.name}:{entry.line_no}{section}"


def _print_issues(doc: ListFile, issues: list[linter.Issue], verbose: bool) -> None:
    colors = {linter.Level.ERROR: "31", linter.Level.WARNING: "33", linter.Level.INFO: "2"}
    name = _rel(doc.path)
    for issue in issues:
        if issue.level is linter.Level.INFO and not verbose:
            continue
        level = out(f"{linter.LEVEL_NAMES[issue.level]:<14}", colors[issue.level])
        fix = out(" [--fix]", "2") if issue.fixable else ""
        print(f"{name}:{issue.line_no:<5} {level} {issue.message}{fix}")


def cmd_lint(args: argparse.Namespace) -> int:
    doc = _load(args.file)
    issues = linter.lint(doc)

    if args.fix and any(i.fixable for i in issues):
        changed = linter.fix(doc)
        print(out(f"Исправлено строк: {changed}", "32"))
        doc = _load(args.file)
        issues = linter.lint(doc)

    _print_issues(doc, issues, args.verbose)
    count = {lvl: sum(1 for i in issues if i.level is lvl) for lvl in linter.Level}
    fixable = sum(1 for i in issues if i.fixable)
    domains = doc.domains()
    print(
        f"\n{_rel(doc.path)}: записей {len(doc.entries)}, уникальных доменов {len(domains)}, "
        f"разделов {len(doc.sections)}"
    )
    summary = (f"Ошибок: {count[linter.Level.ERROR]}, предупреждений: {count[linter.Level.WARNING]}, "
               f"инфо: {count[linter.Level.INFO]}")
    if count[linter.Level.INFO] and not args.verbose:
        summary += " (подробно: -v)"
    if fixable and not args.fix:
        summary += f". Автоисправимо: {fixable} (--fix)"
    print(summary)

    failed = count[linter.Level.ERROR] or (args.strict and count[linter.Level.WARNING])
    return 1 if failed else 0


def _lint_errors(doc: ListFile) -> list[linter.Issue]:
    return [i for i in linter.lint(doc) if i.level is linter.Level.ERROR]


def _build(args: argparse.Namespace) -> builder.BuildResult | None:
    doc = _load(args.file)
    errors = _lint_errors(doc)
    if errors:
        _print_issues(doc, errors, verbose=False)
        print(out("\nСборка остановлена: исправьте ошибки в list.txt (python domains.py lint)", "31"))
        return None
    return builder.build(doc, names.ZoneSet.load(args.shared))


def _read_text(path: Path) -> str | None:
    # Побайтово: CRLF в результате тоже считается устаревшим (kvas import требует LF)
    return path.read_bytes().decode("utf-8", "replace") if path.exists() else None


def cmd_build(args: argparse.Namespace) -> int:
    result = _build(args)
    if result is None:
        return 1
    text = builder.render(result)
    current = _read_text(args.out)

    if args.check:
        if current == text:
            print(f"{_rel(args.out)} актуален")
            return 0
        print(out(f"{_rel(args.out)} устарел: запустите python domains.py build", "31"))
        return 1

    if current != text:
        atomic_write(args.out, text)
    _print_build_stats(result, args)
    return 0


def _print_build_stats(result: builder.BuildResult, args: argparse.Namespace) -> None:
    kept = sorted(
        d for d, (_, r) in result.keys.items()
        if r in (builder.SHARED, builder.PSL_PRIVATE) and names.registrable(d) != d
    )
    total = len(result.routes)
    print(f"Уникальных доменов в list.txt:        {len(result.keys)}")
    print(f"Схлопнуто до 2-го уровня:             {result.count(builder.COLLAPSED)}")
    print(f"Оставлено целиком (облака и CDN):     {len(kept)}" + ("" if args.verbose else " (список: -v)"))
    print(f"Поглощено родительским доменом:       {len(result.covered)}")
    print(out(f"Итого в {_rel(args.out)}: {total}", "1"))

    if args.verbose and kept:
        print("\nОставлены целиком, чтобы не завернуть в VPN чужие сайты на той же платформе:")
        for d in kept:
            key = result.keys[d][0]
            mark = f"  -> покрыт {result.covered[key]}" if key in result.covered else ""
            print(f"  {d}{mark}")

    if total > builder.KEENETIC_LIST_LIMIT:
        print(out(f"\n{_keenetic_hint(total)}", "33"))


def _keenetic_hint(total: int) -> str:
    parts = -(-total // builder.KEENETIC_LIST_LIMIT)
    return (f"Встроенные DNS-маршруты Keenetic: лимит {builder.KEENETIC_LIST_LIMIT} записей на список, "
            f"нужно {plural(parts, 'список', 'списка', 'списков')}. "
            "Команды с разбивкой: python domains.py keenetic --interface <имя>")


def cmd_keenetic(args: argparse.Namespace) -> int:
    result = _build(args)
    if result is None:
        return 1
    domains = [r.domain for r in result.routes]
    try:
        commands, groups = builder.keenetic_commands(domains, args.group, args.interface, args.limit, args.reject)
    except ValueError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 2
    text = "\n".join(commands) + "\n"
    if args.output:
        atomic_write(args.output, text)
        print(f"Команды записаны в {_rel(args.output)}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    print(
        f"{plural(len(domains), 'домен', 'домена', 'доменов')} -> "
        f"{plural(len(groups), 'список', 'списка', 'списков')} (лимит {args.limit}): {', '.join(groups)}. "
        "Вставьте команды в CLI роутера (SSH/Telnet).",
        file=sys.stderr,
    )
    return 0


def _sync_routes(list_path: Path, shared_path: Path, before: builder.BuildResult) -> builder.BuildResult:
    """После правки list.txt: показывает, как изменились маршруты, и пересобирает list_2nd_level.txt."""
    doc = ListFile.load(list_path)
    shared = names.ZoneSet.load(shared_path)
    after = builder.build(doc, shared)
    old, new = {r.domain for r in before.routes}, {r.domain for r in after.routes}
    print("Маршруты:" if old != new else out("Маршруты не изменились", "2"))
    for d in sorted(new - old):
        print(out(f"  + {d}", "32"))
    for d in sorted(old - new):
        print(out(f"  - {d}", "31"))

    target = list_path.with_name(OUT_NAME)
    if target.exists():
        if _lint_errors(doc):
            print(out(f"{target.name} не пересобран: в {list_path.name} есть ошибки (python domains.py lint)", "33"))
        else:
            text = builder.render(after)
            if _read_text(target) != text:
                atomic_write(target, text)
                print(f"{target.name} пересобран: {plural(len(after.routes), 'маршрут', 'маршрута', 'маршрутов')}")
    if len(after.routes) > builder.KEENETIC_LIST_LIMIT >= len(before.routes):
        print(out(_keenetic_hint(len(after.routes)), "33"))
    return after


def _edit_list(args: argparse.Namespace, change: Callable[[ListFile], bool]) -> builder.BuildResult | None:
    doc = _load(args.file)
    shared = names.ZoneSet.load(args.shared)
    before = builder.build(doc, shared)
    if not change(doc):
        return None
    return _sync_routes(args.file, args.shared, before)


class Progress:
    def __init__(self) -> None:
        self.enabled = sys.stderr.isatty()

    def __call__(self, stage: str, done: int, total: int) -> None:
        if not self.enabled:
            return
        width = 30
        filled = width * done // total if total else width
        sys.stderr.write(f"\r  {stage:<6}[{'#' * filled}{'.' * (width - filled)}] {done}/{total}  ")
        sys.stderr.flush()

    def finish(self) -> None:
        if self.enabled:
            sys.stderr.write("\r" + " " * 70 + "\r")
            sys.stderr.flush()


def _run_check(args: argparse.Namespace, domains: list[str], **overrides) -> checker.CheckReport:
    params = dict(
        resolvers=args.resolver, doh=args.doh, timeout=args.timeout, concurrency=args.concurrency,
        probe=not args.no_probe, rdap=args.rdap,
        rdap_client=Rdap(cache=args.file.parent / RDAP_CACHE),
    )
    params.update(overrides)
    return asyncio.run(checker.run_check(domains, **params))


def _check_targets(args: argparse.Namespace) -> tuple[list[str], dict[str, list[Entry]], ListFile | None]:
    if args.domains:
        return _normalize_all(args.domains), {}, None

    doc = _load(args.file)
    entries = [e for e in doc.entries if e.domain]
    if args.section:
        needle = args.section.lower()
        entries = [e for e in entries if e.section and needle in e.section.lower()]
        if not entries:
            raise CliError(f'раздел "{args.section}" не найден')
    where: dict[str, list[Entry]] = {}
    for e in entries:
        where.setdefault(e.domain, []).append(e)
    return list(where), where, doc


def _location(domain: str, where: dict[str, list[Entry]], doc: ListFile | None) -> tuple[str, str]:
    places = where.get(domain)
    if not places or doc is None:
        return "", ""
    first = places[0]
    extra = f" (+{len(places) - 1})" if len(places) > 1 else ""
    return f"{doc.path.name}:{first.line_no}{extra}", first.section or ""


def confirmations(result: checker.Result, streak: Streak | None) -> list[str]:
    """Независимые подтверждения проблемы: каналы этой проверки плюс история прошлых дней."""
    found = list(result.confirmed)
    if streak and streak.status == result.status.value and streak.count >= 2:
        found.append(f"история ({streak.count}-я проверка подряд с {streak.since})")
    return found


def cmd_check(args: argparse.Namespace) -> int:
    domains, where, doc = _check_targets(args)
    use_history = doc is not None and not args.no_history
    history = History.load(args.file.with_name(STATE_NAME) if use_history else None)
    if args.failed:
        if doc is None:
            raise CliError("--failed работает только со списком, без перечисления доменов")
        domains = [d for d in domains if history.get(d)]
        if not domains:
            print("В истории нет проблемных доменов: все работали при прошлой проверке")
            return 0
    if not domains:
        print("Нечего проверять")
        return 0

    print(f"Проверка: {plural(len(domains), 'домен', 'домена', 'доменов')}")
    progress = Progress()
    try:
        report = _run_check(args, domains, progress=progress)
    except checker.PreflightError as exc:
        progress.finish()
        print(out("Самопроверка DNS не пройдена, результаты были бы недостоверны:", "31"))
        print(exc)
        return 2
    progress.finish()

    if use_history:
        history.update((r.domain, r.status.value, r.status in checker.REVIEW | checker.REMOVE)
                       for r in report.results if r.status is not Status.UNKNOWN)
        history.save()

    for channel in report.channels:
        print(out(f"  {channel}", "2"))
    for warning in report.warnings:
        print(out(f"Внимание: {warning}", "33"))

    by_status: dict[Status, list[checker.Result]] = {s: [] for s in Status}
    for r in report.results:
        by_status[r.status].append(r)

    print(f"\nГотово за {report.duration:.1f} с\n")
    for status in Status:
        label, color = STATUS_INFO[status]
        n = len(by_status[status])
        if n or status is Status.OK:
            print(f"  {out(f'{label:<30}', color)} {n:>5}")

    groups = [
        ("Не существуют, кандидаты на удаление", checker.REMOVE, True),
        ("Требуют ручной проверки", checker.REVIEW, True),
        ("Не удалось проверить (повторите позже или --timeout побольше)", {Status.UNKNOWN}, True),
        ("Живые, но сервер не отвечает или нет адресов (обычно API и служебные имена, оставить)",
         {Status.NO_CONNECT, Status.NO_ADDRESS}, args.verbose),
    ]
    hidden = 0
    for title, statuses, show in groups:
        items = [r for s in Status if s in statuses for r in by_status[s]]
        if not items:
            continue
        if not show:
            hidden += len(items)
            continue
        print(f"\n{out(title, '1')}:")
        for r in sorted(items, key=lambda r: _sort_key(r, where)):
            _print_result(r, where, doc, history.get(r.domain))
    if hidden:
        print(out(f"\nЕще {plural(hidden, 'живой домен', 'живых домена', 'живых доменов')}, "
                  "где сервер молчит или нет адресов: -v", "2"))

    if report.expiring:
        print(f"\n{out('Скоро истекает регистрация', '1')}:")
        for e in report.expiring:
            print(f"  {e.zone}: {e.expires} ({plural(e.days, 'день', 'дня', 'дней')})")

    if args.json or args.html:
        data = report_data(report, where, doc, history)
        if args.json:
            atomic_write(args.json, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        if args.html:
            atomic_write(args.html, html_report.render_html(data))
        print("\nОтчет: " + ", ".join(_rel(p) for p in (args.json, args.html) if p))

    if doc is None:
        return 1 if any(by_status[s] for s in FAILING) else 0
    return _offer_removal(args, doc, by_status, history)


def _print_result(r: checker.Result, where, doc: ListFile | None, streak: Streak | None) -> None:
    loc, section = _location(r.domain, where, doc)
    _, color = STATUS_INFO[r.status]
    pad = f"{loc:<16} " if doc else ""
    indent = "  " + " " * len(pad)
    section_txt = out(f"  [{section}]", "2") if section else ""
    print(f"  {pad}{out(r.domain, color)}{section_txt}")
    print(f"{indent}{r.note}")
    if r.evidence:
        print(out(f"{indent}{'; '.join(r.evidence)}", "2"))
    confirmed = confirmations(r, streak)
    if confirmed:
        print(out(f"{indent}подтверждено: {', '.join(confirmed)}", "2"))


def _sort_key(r: checker.Result, where: dict[str, list[Entry]]) -> tuple[int, str]:
    places = where.get(r.domain)
    return (places[0].line_no if places else 0, r.domain)


def _offer_removal(args, doc: ListFile, by_status, history: History) -> int:
    dead = [r for s in checker.REMOVE for r in by_status[s]]
    review = [r for s in checker.REVIEW for r in by_status[s]]
    if not dead and not review:
        return 0

    to_remove: set[str] = set()
    if args.yes:
        strong = [r for r in dead if len(confirmations(r, history.get(r.domain))) >= MIN_CONFIRMATIONS]
        weak = [r.domain for r in dead if r not in strong]
        to_remove = {r.domain for r in strong}
        if weak:
            print(out(
                f"\n--yes: не удалено {plural(len(weak), 'домен', 'домена', 'доменов')}, подтвержденных одним "
                f"каналом (повторите проверку в другой день или удалите вручную): {', '.join(weak)}", "33",
            ))
    elif sys.stdin.isatty():
        to_remove = _ask_removal(dead, review, doc.path.name)
    elif dead:
        print("\nУдаление пропущено: нет интерактивного терминала (для автоудаления NXDOMAIN: --yes)")

    if to_remove:
        shared_path = args.file.with_name(SHARED_NAME)
        before = builder.build(doc, names.ZoneSet.load(shared_path))
        removed = edit.remove(doc, to_remove)
        print(out(f"\nУдалено строк из {doc.path.name}: {removed}", "32"))
        history.forget(to_remove)
        history.save()
        _sync_routes(args.file, shared_path, before)

    left = [r for s in FAILING for r in by_status[s] if r.domain not in to_remove]
    return 1 if left else 0


def _ask_removal(dead: list[checker.Result], review: list[checker.Result], name: str) -> set[str]:
    try:
        if dead:
            question = f"Удалить из {name}: {plural(len(dead), 'несуществующий домен', 'несуществующих домена', 'несуществующих доменов')}?"
        else:
            question = "Точно мертвых нет, но есть сомнительные."
        answer = input(f"\n{question} [y - да, s - выбрать по одному, n - нет]: ").strip().lower()
        if answer in ("y", "д") and dead:
            return {r.domain for r in dead}
        if answer not in ("s", "ы"):
            return set()
        chosen = set()
        for r in dead + review:
            label, _ = STATUS_INFO[r.status]
            if input(f"  {r.domain} ({label}: {r.note}) - удалить? [y/N]: ").strip().lower() in ("y", "д"):
                chosen.add(r.domain)
        return chosen
    except EOFError:
        return set()


def report_data(report: checker.CheckReport, where, doc: ListFile | None, history: History) -> dict:
    rows = []
    for r in report.results:
        places = where.get(r.domain, [])
        streak = history.get(r.domain)
        rows.append({
            "domain": r.domain,
            "status": r.status.value,
            "label": STATUS_INFO[r.status][0],
            "group": status_group(r.status),
            "note": r.note,
            "evidence": r.evidence,
            "confirmed": confirmations(r, streak),
            "addresses": r.addresses,
            "votes": r.votes,
            "section": places[0].section if places else None,
            "line": places[0].line_no if places else None,
            "locations": [{"line": e.line_no, "section": e.section} for e in places],
            "streak": vars(streak) if streak else None,
        })
    return {
        "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source": doc.path.name if doc else None,
        "resolvers": report.servers,
        "channels": report.channels,
        "warnings": report.warnings,
        "expiring": [vars(e) for e in report.expiring],
        "duration_sec": round(report.duration, 2),
        "results": rows,
    }


def _choose_section(doc: ListFile, domain: str) -> str | None:
    titles = [s.title for s in doc.sections if s.title]
    print(f"\nВ какой раздел добавить {domain}?")
    for i, title in enumerate(titles, 1):
        print(f"  {i:>3}. {title}")
    for _ in range(3):
        answer = input("Номер, часть названия или новое название (пусто - пропустить): ").strip()
        if not answer:
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(titles):
            return titles[int(answer) - 1]
        try:
            return edit.find_section(doc, answer).title
        except edit.EditError as exc:
            if "не найден" not in str(exc):
                print(out(str(exc), "33"))
                continue
        if input(f'Создать раздел "{answer}"? [Y/n]: ').strip().lower() in ("", "y", "д"):
            return answer
    return None


def _dns_screen(args: argparse.Namespace, domains: list[str]) -> list[str]:
    """Быстрая проверка перед добавлением: ловит опечатки (NXDOMAIN)."""
    print(f"Проверка DNS: {', '.join(domains)}")
    try:
        report = asyncio.run(checker.run_check(domains, probe=False, rdap="off", concurrency=16))
    except checker.PreflightError:
        print(out("DNS недоступен, домены добавляются без проверки", "33"))
        return domains
    keep = []
    for r in report.results:
        label, color = STATUS_INFO[r.status]
        if r.status is Status.NXDOMAIN and not args.force:
            print(out(f"  {r.domain}: {label} ({r.note}), пропущен. Опечатка? Добавить все равно: --force", "31"))
            continue
        if r.status is not Status.OK:
            print(out(f"  {r.domain}: {label} ({r.note})", color))
        keep.append(r.domain)
    return keep


def cmd_add(args: argparse.Namespace) -> int:
    doc = _load(args.file)
    shared = names.ZoneSet.load(args.shared)
    routes = builder.build(doc, shared)
    fresh = []
    for domain in _normalize_all(args.domains, strict=False):
        found = edit.coverage(doc, routes, domain, shared)
        if found.exact:
            print(f"{domain}: уже есть, {_where(doc, found.exact[0])}")
        elif found.parents and not args.force:
            print(f"{domain}: уже покрыт {found.parents[0].domain} ({_where(doc, found.parents[0])}), "
                  "добавить все равно: --force")
        elif found.route and not args.force:
            print(f"{domain}: уже маршрутизируется через {found.route.domain}, добавить все равно: --force")
        else:
            fresh.append(domain)
    if not fresh:
        return 0
    if not args.no_check:
        fresh = _dns_screen(args, fresh)
        if not fresh:
            return 1

    placements = []
    for domain in fresh:
        placements.append((domain, _pick_section(args, doc, domain, shared)))
    placements = [(d, t) for d, t in placements if t]
    if not placements:
        return 1

    def change(d: ListFile) -> bool:
        edit.add(d, placements)
        return True

    _edit_list(args, change)
    doc = ListFile.load(args.file)
    for domain, _ in placements:
        entry = edit.matching(doc, domain)[-1]
        print(out(f"Добавлен {domain}: {_where(doc, entry)}", "32"))
    return 0


def _pick_section(args: argparse.Namespace, doc: ListFile, domain: str, shared: names.ZoneSet) -> str | None:
    if args.new:
        return args.new
    if args.section:
        try:
            return edit.find_section(doc, args.section).title
        except edit.EditError as exc:
            raise CliError(str(exc)) from None
    guessed = edit.guess_section(doc, domain, shared)
    if guessed:
        return guessed.title
    if sys.stdin.isatty():
        try:
            title = _choose_section(doc, domain)
        except EOFError:
            title = None
        if title is None:
            print(f"{domain}: пропущен")
        return title
    raise CliError(f'не удалось подобрать раздел для {domain}: укажите -s РАЗДЕЛ или --new "НАЗВАНИЕ"')


def cmd_rm(args: argparse.Namespace) -> int:
    domains = _normalize_all(args.domains)
    doc = _load(args.file)
    shared = names.ZoneSet.load(args.shared)
    targets: set[str] = set()
    missing = 0
    for domain in domains:
        found = edit.matching(doc, domain, args.sub)
        if found:
            for e in found:
                print(f"Удаляется {e.domain}: {_where(doc, e)}")
            targets.update(e.domain for e in found)
            continue
        missing += 1
        parents = edit.coverage(doc, builder.build(doc, shared), domain, shared).parents
        hint = f", но покрыт {parents[0].domain} ({_where(doc, parents[0])})" if parents else ""
        print(out(f"{domain}: в {doc.path.name} нет{hint}", "33"))
        if not args.sub and any(names.is_within(e.domain, domain) for e in doc.entries if e.domain):
            print(out("  есть его поддомены: удалить вместе с ними: --sub", "2"))
    if not targets:
        return 1

    after = _edit_list(args, lambda d: bool(edit.remove(d, targets)))
    state = History.load(args.file.with_name(STATE_NAME))
    if any(state.get(d) for d in targets):
        state.forget(targets)
        state.save()

    doc = ListFile.load(args.file)
    by_line = {e.line_no: e for e in doc.entries}
    for domain in domains:
        route = next((r for r in after.routes if names.is_within(domain, r.domain)), None) if after else None
        if route and route.line_no in by_line:
            print(out(f"{domain} по-прежнему идет через VPN: маршрут {route.domain} дает запись "
                      f"{by_line[route.line_no].domain} ({doc.path.name}:{route.line_no})", "33"))
    return 1 if missing else 0


def cmd_where(args: argparse.Namespace) -> int:
    doc = _load(args.file)
    shared = names.ZoneSet.load(args.shared)
    result = builder.build(doc, shared)
    not_routed = 0
    for domain in _normalize_all(args.domains, strict=False):
        found = edit.coverage(doc, result, domain, shared)
        print(out(domain, "1"))
        for e in found.exact:
            print(f"  в списке: {_where(doc, e)}")
        for e in found.parents:
            print(f"  покрыт записью {e.domain}: {_where(doc, e)}")
        if found.route:
            via = "" if found.route.domain == domain else f" через {found.route.domain}"
            print(out(f"  маршрутизируется{via} ({OUT_NAME}, раздел {found.route.section or '-'})", "32"))
            continue
        not_routed += 1
        print(out("  не маршрутизируется", "31"))
        if found.shared_zone:
            print(out(f"  {found.shared_zone} - общая зона (облако или CDN): добавляйте полное имя, "
                      f"python domains.py add {domain}", "2"))
        else:
            print(out(f"  добавить: python domains.py add {domain}", "2"))
    return 1 if not_routed else 0


def cmd_status(args: argparse.Namespace) -> int:
    doc = _load(args.file)
    issues = linter.lint(doc)
    errors = sum(1 for i in issues if i.level is linter.Level.ERROR)
    warnings = sum(1 for i in issues if i.level is linter.Level.WARNING)
    print(out(f"{_rel(args.file)}", "1") + f": {plural(len(doc.domains()), 'домен', 'домена', 'доменов')}, "
          f"{plural(len([s for s in doc.sections if s.title]), 'раздел', 'раздела', 'разделов')}")
    if errors or warnings:
        color = "31" if errors else "33"
        print(out(f"  lint: ошибок {errors}, предупреждений {warnings} (python domains.py lint)", color))
    else:
        print(out("  lint: чисто", "32"))

    target = args.file.with_name(OUT_NAME)
    if not errors:
        result = builder.build(doc, names.ZoneSet.load(args.shared))
        fresh = _read_text(target) == builder.render(result)
        state = out("актуален", "32") if fresh else out("устарел (python domains.py build)", "31")
        print(f"{target.name}: {plural(len(result.routes), 'маршрут', 'маршрута', 'маршрутов')}, {state}")
        if len(result.routes) > builder.KEENETIC_LIST_LIMIT:
            print(out(f"  {_keenetic_hint(len(result.routes))}", "2"))

    history = History.load(args.file.with_name(STATE_NAME))
    if history.last_run:
        bad = sorted(history.domains.items(), key=lambda kv: -kv[1].count)
        line = f"Последняя проверка: {history.last_run}"
        if bad:
            line += f", не работают: {len(bad)} (перепроверить: python domains.py check --failed)"
        print(line)
        for domain, streak in bad[:5]:
            print(out(f"  {domain}: {streak.status}, с {streak.since}"
                      + (f", {streak.count}-я проверка подряд" if streak.count > 1 else ""), "2"))
    else:
        print("Проверок еще не было: python domains.py check")

    print(f"\n{out('Частые команды', '1')}:")
    for cmd, text in (
        ("add example.com", "добавить домен (раздел подбирается сам)"),
        ("rm example.com", "удалить домен и пересобрать маршруты"),
        ("where example.com", "чем покрыт домен, пойдет ли он через VPN"),
        ("check", "проверить все домены: DNS, DoH, RDAP, HTTPS"),
        ("check --html report.html", "то же с HTML-отчетом"),
        ("lint --fix", "исправить мусор и дубли"),
        ("--help", "все команды"),
    ):
        print(f"  python domains.py {cmd:<26} {out(text, '2')}")
    return 1 if errors else 0


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="domains.py",
        description="Список доменов для выборочной маршрутизации (Keenetic, kvas и др.): проверка, сборка, экспорт. "
                    "Без аргументов показывает сводку.",
    )
    sub = p.add_subparsers(dest="command", metavar="КОМАНДА")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-f", "--file", type=Path, default=DEFAULT_LIST, help="исходный список (list.txt)")
    common.add_argument("-v", "--verbose", action="store_true", help="подробный вывод")

    building = argparse.ArgumentParser(add_help=False)
    building.add_argument("--shared", type=Path,
                          help=f"зоны общей инфраструктуры (по умолчанию {SHARED_NAME} рядом со списком)")

    s = sub.add_parser("status", parents=[common, building], help="сводка: список, сборка, последняя проверка")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("add", parents=[common, building], help="добавить домены (раздел подбирается сам)")
    s.add_argument("domains", nargs="+", metavar="DOMAIN", help="домен или URL")
    s.add_argument("-s", "--section", help="раздел (поиск по подстроке)")
    s.add_argument("--new", metavar="TITLE", help="добавить в новый раздел")
    s.add_argument("--no-check", action="store_true", help="не проверять DNS перед добавлением")
    s.add_argument("--force", action="store_true", help="добавить, даже если NXDOMAIN или уже покрыт")
    s.set_defaults(func=cmd_add)

    s = sub.add_parser("rm", parents=[common, building], help="удалить домены")
    s.add_argument("domains", nargs="+", metavar="DOMAIN")
    s.add_argument("--sub", action="store_true", help="вместе с поддоменами")
    s.set_defaults(func=cmd_rm)

    s = sub.add_parser("where", parents=[common, building], help="чем покрыт домен и пойдет ли он через VPN")
    s.add_argument("domains", nargs="+", metavar="DOMAIN", help="домен или URL")
    s.set_defaults(func=cmd_where)

    s = sub.add_parser("lint", parents=[common], help="проверить синтаксис, дубли и мусор (без сети)")
    s.add_argument("--fix", action="store_true", help="исправить автоматически исправимое")
    s.add_argument("--strict", action="store_true", help="считать предупреждения ошибками")
    s.set_defaults(func=cmd_lint)

    s = sub.add_parser("build", parents=[common, building], help=f"собрать {OUT_NAME}")
    s.add_argument("-o", "--out", type=Path, help=f"куда писать результат (по умолчанию {OUT_NAME} рядом со списком)")
    s.add_argument("--check", action="store_true", help="только проверить, что результат актуален (для CI)")
    s.set_defaults(func=cmd_build)

    s = sub.add_parser("check", parents=[common], help="найти мертвые домены: DNS, DoH, RDAP, HTTPS")
    s.add_argument("domains", nargs="*", metavar="DOMAIN", help="проверить эти домены вместо списка")
    s.add_argument("-s", "--section", help="проверить только раздел (поиск по подстроке)")
    s.add_argument("--failed", action="store_true", help="только домены, которые не работали в прошлый раз")
    s.add_argument("-r", "--resolver", action="append", help="DNS-резолвер: IP или https://... (можно несколько раз)")
    s.add_argument("--doh", action="append", metavar="URL", help="DoH-резолвер для перепроверки (можно несколько раз)")
    s.add_argument("--no-doh", action="store_true", help="не перепроверять отрицательные ответы через DoH")
    s.add_argument("--rdap", choices=("auto", "all", "off"), default="auto",
                   help="запросы в реестр: auto - для подозрительных, all - для всех (плюс сроки регистрации)")
    s.add_argument("--no-probe", action="store_true", help="без HTTPS/HTTP-пробы (только DNS и RDAP)")
    s.add_argument("--timeout", type=float, default=checker.DNS_TIMEOUT, help="таймаут DNS-запроса, с")
    s.add_argument("-c", "--concurrency", type=int, default=checker.DEFAULT_CONCURRENCY,
                   help="параллельных проверок")
    s.add_argument("--json", type=Path, help="сохранить полный отчет в JSON")
    s.add_argument("--html", type=Path, help="сохранить автономный HTML-отчет с фильтрами")
    s.add_argument("--no-history", action="store_true", help=f"не читать и не обновлять {STATE_NAME}")
    s.add_argument("-y", "--yes", action="store_true",
                   help=f"удалить NXDOMAIN без вопросов (только подтвержденные {MIN_CONFIRMATIONS}+ каналами)")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("keenetic", parents=[common, building], help="команды CLI Keenetic (DNS-маршруты)")
    s.add_argument("-i", "--interface", required=True, help="интерфейс VPN, например Wireguard0")
    s.add_argument("-g", "--group", default="vpn", help="имя списка доменов (по умолчанию vpn)")
    s.add_argument("--limit", type=int, default=builder.KEENETIC_LIST_LIMIT, help="записей на список")
    s.add_argument("--reject", action="store_true", help="блокировать трафик, если VPN упал (kill switch)")
    s.add_argument("-o", "--output", type=Path, help="записать команды в файл")
    s.set_defaults(func=cmd_keenetic)
    return p


def _defaults(args: argparse.Namespace) -> None:
    if getattr(args, "shared", "") is None:
        args.shared = args.file.with_name(SHARED_NAME)
    if getattr(args, "out", "") is None:
        args.out = args.file.with_name(OUT_NAME)
    if args.command == "check":
        args.resolver = args.resolver or list(checker.DEFAULT_RESOLVERS)
        args.doh = () if args.no_doh else (args.doh or list(checker.DOH_RESOLVERS))


def main(argv: Sequence[str] | None = None) -> int:
    if os.name == "nt":
        os.system("")  # включает ANSI-цвета в консоли Windows
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    args = parser.parse_args(argv or ["status"])
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    _defaults(args)
    if getattr(args, "limit", 1) < 1 or getattr(args, "concurrency", 1) < 1:
        print("Ошибка: --limit и --concurrency должны быть больше 0", file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except (CliError, edit.EditError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nПрервано пользователем", file=sys.stderr)
        return 130
