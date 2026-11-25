# SPDX-License-Identifier: Apache-2.0
"""Plugin discovery shared by canary types and check sources.

Two ways a plugin is found:

  * a module inside a known package (stille_hunter.types / .sources, and
    stille_hunter_pro.types / .sources when installed), imported so its
    @register_type / @register decorator runs;
  * an **entry point** in the group ``stille_hunter.types`` or
    ``stille_hunter.sources``, declared by any installed distribution. This is
    how a third-party package ships a plugin without being part of this one:

        # pyproject.toml of your package
        [project.entry-points."stille_hunter.sources"]
        mysource = "my_package.my_source"      # a module that @register's

Loading never stops at a broken plugin: each failure is returned as a
"name: error" string for the caller to report.
"""
from __future__ import annotations

import importlib
import pkgutil

TYPE_GROUP = "stille_hunter.types"
SOURCE_GROUP = "stille_hunter.sources"


def load_packages(packages) -> list[str]:
    problems: list[str] = []
    for pkg_name in packages:
        try:
            pkg = importlib.import_module(pkg_name)
        except ImportError:
            continue  # package not installed (fine for the optional pro one)
        for mod in pkgutil.iter_modules(pkg.__path__):
            if mod.name.startswith("_"):
                continue
            try:
                importlib.import_module(f"{pkg_name}.{mod.name}")
            except Exception as e:
                problems.append(f"{pkg_name}.{mod.name}: {e}")
    return problems


def load_entry_points(group: str) -> list[str]:
    """Import every module (or object) declared under an entry-point group."""
    from importlib.metadata import entry_points
    problems: list[str] = []
    try:
        eps = entry_points(group=group)
    except Exception as e:  # a broken installed distribution's metadata
        return [f"{group}: {e}"]
    for ep in eps:
        try:
            ep.load()
        except Exception as e:
            problems.append(f"{group}:{ep.name} ({ep.value}): {e}")
    return problems
