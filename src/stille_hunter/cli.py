# SPDX-License-Identifier: Apache-2.0
"""stille-hunter unified CLI: `stille-hunter generate ...` / `check ...`.

Thin dispatcher. `generate` and `check` each own their own argument parsing in
their module's main(); this just routes the subcommand to the right one.
"""
from __future__ import annotations

import sys

from . import __version__


_USAGE = """\
stille-hunter <command> [options]

commands:
  generate   Generate leak-canary user records to seed into your data.
  check      Check a canary ledger against leak sources.

Run 'stille-hunter <command> --help' for command options.
"""


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        sys.stdout.write(_USAGE)
        return
    if argv[0] in ("-V", "--version"):
        print(f"stille-hunter {__version__}")
        return

    cmd, rest = argv[0], argv[1:]
    if cmd == "generate":
        from .generate import main as gen_main
        gen_main(rest)
    elif cmd == "check":
        from .check import main as check_main
        check_main(rest)
    else:
        sys.stderr.write(f"unknown command: {cmd}\n\n{_USAGE}")
        sys.exit(2)


if __name__ == "__main__":
    main()
