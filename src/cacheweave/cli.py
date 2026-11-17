from __future__ import annotations

import argparse
import sys

from . import odc_carve, odc_recover


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cacheweave")
    parser.add_argument("command", nargs="?", choices=("recover", "carve"))
    values = list(sys.argv[1:] if argv is None else argv)
    if not values or values[0] in ("-h", "--help"):
        parser.print_help()
        return 0
    command = values.pop(0)
    if command not in ("recover", "carve"):
        parser.error(f"invalid choice: {command!r} (choose from 'recover', 'carve')")
    if command == "recover":
        return odc_recover.main(values, prog="cacheweave recover")
    return odc_carve.main(values, prog="cacheweave carve")
