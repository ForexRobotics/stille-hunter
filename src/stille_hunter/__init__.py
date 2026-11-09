# SPDX-License-Identifier: Apache-2.0
"""stille-hunter: leak-canary generation and matching.

Public, Apache-2.0 part of stille-hunter. Generate realistic fake user records
to seed as leak canaries (generate), and check a canary ledger against leak
sources (check). Proprietary sources (Tor dark-web crawl, commercial threat
feeds) live in a separate package and plug into the same CheckSource contract.
"""
__version__ = "0.1.0"
