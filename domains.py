#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["aiodns>=4.0", "tldextract>=5.1", "idna>=3.4"]
# ///
"""Точка входа: python domains.py --help (или uv run domains.py, зависимости поставятся сами)."""
import sys

if sys.version_info < (3, 10):
    sys.exit(f"Нужен Python 3.10 или новее, сейчас {sys.version.split()[0]}")

try:
    from domainlist.cli import main
except ModuleNotFoundError as exc:
    if exc.name not in ("aiodns", "tldextract", "idna", "pycares"):
        raise
    sys.exit(
        f"Не установлен модуль {exc.name}. Варианты:\n"
        "  pip install -r requirements.txt\n"
        "  uv run domains.py ...   (uv сам поставит зависимости во временное окружение)"
    )

if __name__ == "__main__":
    sys.exit(main())
