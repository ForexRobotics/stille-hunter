# SPDX-License-Identifier: Apache-2.0
"""The guides cover every CLI option and every plugin contract member.

Options are read from each command's own --help, so a new option without a
line in docs/user-guide.md fails here.
"""
import re
from pathlib import Path

import pytest

from stille_hunter.check import Canary, Hit
from stille_hunter.cli import main
from stille_hunter.generate import _TYPES, load_type_plugins

DOCS = Path(__file__).parents[1] / "docs"
USER = (DOCS / "user-guide.md").read_text(encoding="utf-8")
PLUGIN = (DOCS / "plugin-guide.md").read_text(encoding="utf-8")


def _options(argv, capsys) -> set[str]:
    with pytest.raises(SystemExit):
        main(argv + ["--help"])
    return set(re.findall(r"(?<![\w-])--[a-z][a-z-]+", capsys.readouterr().out)) - {"--help"}


def _commands():
    load_type_plugins(("stille_hunter.types",))
    cmds = [["check"], ["inbox"], ["history"], ["ledger", "list"], ["ledger", "retire"],
            ["ledger", "rotate"]]
    return cmds + [["generate", "--type", t] for t in sorted(_TYPES)]


@pytest.mark.parametrize("argv", _commands(), ids=lambda a: " ".join(a))
def test_every_option_is_in_the_user_guide(argv, capsys):
    missing = sorted(o for o in _options(argv, capsys)
                     if not re.search(re.escape(o) + r"(?![a-z-])", USER))
    assert not missing, f"{' '.join(argv)}: not in docs/user-guide.md: {missing}"


def test_every_command_has_a_section():
    for cmd in ("generate", "check", "inbox", "history", "ledger"):
        assert f"## {cmd}" in USER
    for sub in ("list", "retire", "rotate"):
        assert f"ledger {sub}" in USER


def test_plugin_guide_covers_the_contracts():
    for member in ("name", "description", "add_arguments(parser)", "generate(args, count)",
                   "record_id", "_detect", "_ledger", "new_token()", "weighted_choice",
                   "supports", "available()", "check(canaries)", "self.stats",
                   "self.progress", "tokens()", "stille_hunter.types",
                   "stille_hunter.sources", "@register_type", "@register"):
        assert member in PLUGIN, member
    for field in list(Canary.__dataclass_fields__) + list(Hit.__dataclass_fields__):
        assert f"`{field}`" in PLUGIN, field
    for limit in ("Read-only, search-only", "Never download or keep leaked data",
                  "Self-contained"):
        assert limit in PLUGIN


def test_plugin_guide_examples_run(tmp_path, monkeypatch, capsys):
    """The example type, source and test in the plugin guide work as written."""
    import importlib
    import json
    import sys

    from stille_hunter import check, generate
    pkg = tmp_path / "my_package"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    example_test = None
    for block in re.findall(r"```python\n(.*?)```", PLUGIN, re.S):
        m = re.match(r"# (my_package/\w+\.py)\n", block)
        if m:
            (tmp_path / m.group(1)).write_text(block, encoding="utf-8")
        elif block.startswith("from stille_hunter import check"):
            example_test = block
    monkeypatch.syspath_prepend(str(tmp_path))
    try:
        importlib.import_module("my_package.env_secret")
        importlib.import_module("my_package.internal_search")
        generate.main(["--type", "env_secret", "--var", "STRIPE_WEBHOOK_SECRET", "--count", "2",
                       "--tag", "ci-env", "--out", str(tmp_path / "es")])
        row = json.loads((tmp_path / "es.ledger.jsonl").read_text().splitlines()[0])
        assert row["type"] == "env_secret" and row["record_id"] in row["env_secret"]
        seeded = json.loads((tmp_path / "es.jsonl").read_text().splitlines()[0])
        assert seeded["env_line"].startswith("STRIPE_WEBHOOK_SECRET=whsec_")

        namespace: dict = {}
        exec(compile(example_test, "plugin-guide example", "exec"), namespace)
        namespace["test_internal_search_finds_a_marker"](monkeypatch)
    finally:
        generate._TYPES.pop("env_secret", None)
        check._REGISTRY.pop("internal_search", None)
        for name in ("my_package", "my_package.env_secret", "my_package.internal_search"):
            sys.modules.pop(name, None)
