# SPDX-License-Identifier: Apache-2.0
"""Build the Discord webhook payload announcing a stille-hunter release.

Usage: python discord_payload.py VERSION NOTES_FILE RELEASE_URL > payload.json

Discord caps a message at 2000 characters, so long release notes are cut at a
line boundary and point to the release page for the rest. Mentions are
disabled, so text like @everyone in the notes can never ping anyone.
"""
import json
import sys

LIMIT = 2000


def build(version: str, notes: str, release_url: str) -> dict:
    pypi_url = f"https://pypi.org/project/stille-hunter/{version}/"
    head = f"**stille-hunter {version}** released\n\n"
    tail = f"\n\nRelease notes: {release_url}\nPyPI: {pypi_url}"
    more = "\n\n... (full notes on the release page)"

    body = notes.strip()
    room = LIMIT - len(head) - len(tail)
    if len(body) > room:
        room -= len(more)
        cut = body[:room]
        if "\n" in cut:
            cut = cut[: cut.rindex("\n")]
        body = cut.rstrip() + more

    return {"content": head + body + tail, "allowed_mentions": {"parse": []}}


def main(argv: list[str]) -> int:
    version, notes_file, release_url = argv[1:4]
    with open(notes_file, encoding="utf-8") as f:
        notes = f.read()
    json.dump(build(version, notes, release_url), sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
