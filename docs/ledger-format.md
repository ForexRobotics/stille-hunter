# Ledger format

The **ledger** is the private counterpart to the seeded data. For every canary
record planted into your data, the ledger holds the one row that lets you trace
a leak back to where it came from. It is the data contract between the generator
(`generate`), the checker (`check`), and any downstream consumer such as a
management console.

> **The ledger is secret.** It maps each canary token to the place it was
> planted. Anyone holding it can identify every canary at once, defeating the
> point. Never commit it, never plant it, keep it out of the seeded data. The
> repo's `.gitignore` excludes `*.ledger.*` for this reason.

## Rows

One row per canary. JSONL (one JSON object per line) or CSV.

| field | meaning |
|-------|---------|
| `record_id` | The unique token for this canary (6 hex chars). Also embedded in `email` and `user_id`. |
| `seed_tag` | Where this batch was planted, e.g. `www-customers`. Set at generation with `--tag`. |
| `detect` | `inbox` = on a domain you control (catch-all mail can catch it) · `search` = free-mail, search-only. |
| `locale` | Region profile used: `jp`, `us`, `gb`, … |
| `email` | The canary email address (token embedded in the local-part). |
| `user_id` | The canary login id (token suffix). |
| `password_hash` | sha256 of a per-record fake secret; the token is recoverable by searching the digest. |
| `created_at` | ISO-8601 UTC timestamp of generation. |

## How a consumer uses it

- **Search detection** (`check`): take the searchable markers — `email`,
  `user_id`, `password_hash`, `record_id` — and look each up in a leak source.
  A match means that canary (and therefore its `seed_tag` location) leaked.
- **Inbox detection** (mail catch-all): when mail arrives for a canary address,
  match the local-part's token against `record_id` to find the `seed_tag`.

By default `check` only searches `detect: search` rows; pass `--include-inbox`
to also search the self-domain ones.

## Stability

Field names and meanings are the contract. New fields may be added; existing
ones will not change meaning without a version bump. Consumers should ignore
unknown fields rather than fail on them.
