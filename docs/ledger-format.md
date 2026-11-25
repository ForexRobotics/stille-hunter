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

Every row has these fields:

| field | meaning |
|-------|---------|
| `record_id` | The unique token for this canary (6 hex chars), woven into its markers. |
| `seed_tag` | Where this batch was planted, e.g. `www-customers`. Set at generation with `--tag`. |
| `detect` | `inbox` = on a domain you control (catch-all mail can catch it) · `search` = found by searching. |
| `type` | The canary type that made the row (`member`, `aws_key`, ...). Written since v0.6; for older rows, tools infer it from the markers present. |
| `table` | *(optional)* The table the rows were planted in, when generated with `--table`. Recorded, not searched. |
| `created_at` | ISO-8601 UTC timestamp of generation. |
| `retired_at` | *(optional)* ISO-8601 UTC timestamp when the canary was retired. A retired row stays in the ledger as the record of what was planted, but `check` and `inbox` skip it. |
| `retired_reason` | *(optional)* Why it was retired, e.g. `rotated`. |

Each canary type adds its own fields — the markers a source searches for, and
some context:

| type | fields |
|------|--------|
| `member` | `locale`, `email`, `user_id`, `password_hash` |
| `db_dump` | `locale`, `email`, `marker` (the reference code, e.g. `CUS-A3F8C10421`) |
| `aws_key` | `aws_access_key_id`, `aws_secret_access_key`, optional `region` |
| `api_token` | `provider`, `api_token` |
| `azure_credential` | `azure_client_id`, `azure_tenant_id`, `azure_client_secret` |
| `mcp_config` | `mcp_server`, `mcp_token` |
| `kubeconfig` | `cluster_name`, `kube_token` |

## How a consumer uses it

- **Search detection** (`check`): take the searchable markers — `email`,
  `password_hash`, a key, token or `marker`, `record_id` — and look each up in a
  leak source. Each source picks the kinds it can search (`check --list-sources`).
  A match means that canary (and therefore its `seed_tag` location) leaked.
  Context fields such as `table`, `locale` or `azure_tenant_id` are never searched.
- **Inbox detection** (mail catch-all, `stille-hunter inbox`): when mail arrives
  for a canary address, match the address (or the local-part's token against
  `record_id`) to find the `seed_tag`. See [inbox.md](inbox.md).

By default `check` only searches `detect: search` rows; pass `--include-inbox`
to also search the self-domain ones. Rows with `retired_at` are never checked.

## Managing a ledger

`stille-hunter ledger` works on ledgers in place (atomically, keeping the
file's permissions):

- `ledger list LEDGER...` - canaries per seed tag: active, retired, types,
  inbox count, table, creation dates. Counts only, never values.
- `ledger retire LEDGER --tag TAG | --id RECORD_ID [--reason TEXT]` - stamp
  `retired_at` so checks skip those canaries. `--dry-run` shows the count.
- `ledger rotate LEDGER --tag TAG --out PATH [generate options]` - generate a
  replacement batch of the same type and size for the tag (carrying over its
  locale, inbox domain and table unless told otherwise), append it to the
  ledger, then retire the old batch. If generating fails, nothing is retired.

## Stability

Field names and meanings are the contract. New fields may be added; existing
ones will not change meaning without a version bump. Consumers should ignore
unknown fields rather than fail on them.
