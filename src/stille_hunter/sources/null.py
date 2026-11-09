# SPDX-License-Identifier: Apache-2.0
"""Reference no-op source. Proves the pipeline runs; never reports a hit.

Useful for testing the frame and as the simplest possible example of the
CheckSource contract.
"""
from __future__ import annotations

from typing import Iterable

from ..check import CheckSource, Hit, Canary, register


@register
class NullSource(CheckSource):
    name = "null"
    supports = ("email", "user_id", "password_hash", "record_id")

    def check(self, canaries: list[Canary]) -> Iterable[Hit]:
        return []  # a stub finds nothing
