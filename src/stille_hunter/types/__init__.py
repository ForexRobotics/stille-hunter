# SPDX-License-Identifier: Apache-2.0
"""Built-in canary types for stille-hunter.

Each module here defines one or more CanaryType subclasses decorated with
@register_type. They are imported and registered automatically by
stille_hunter.generate.load_type_plugins(). Add a type by dropping a module
here (or, for proprietary types, in the stille_hunter_pro.types package).
"""
