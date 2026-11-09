# SPDX-License-Identifier: Apache-2.0
"""Built-in leak-check sources for stille-hunter.

Each module here defines one or more CheckSource subclasses decorated with
@register. They are imported and registered automatically by
stille_hunter.check.load_plugins(). Add a source by dropping a module here
(or, for proprietary sources, in the stille_hunter_pro.sources package).
"""
