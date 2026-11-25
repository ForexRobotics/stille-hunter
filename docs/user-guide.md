# User guide

stille-hunter plants fake-but-realistic records - **canaries** - in your own
data, then watches for them where leaked data turns up. A canary that appears
in a breach index, in public code or in someone's mailing list proves that the
place you planted it leaked, and when.

This guide covers every command. For a quick start see the
[README](../README.md); for writing plugins, the [plugin guide](plugin-guide.md).

## The limits

stille-hunter stays on your own turf. It only generates data you plant
yourself, and only **looks up** your own canaries in public or authorized
places. It never logs in anywhere it is not authorized, never downloads or
keeps leaked data, and never touches anyone else's systems. Canaries are inert:
they authenticate to nothing and charge nothing.

## Concepts

| term | meaning |
|---|---|
| **canary** | one fake record or secret, with a unique 6-hex **token** woven into its markers |
| **seed tag** | where a batch was planted, e.g. `www-members` (`--tag`) - the answer to "what leaked?" |
| **ledger** | the secret map from each canary to its seed tag ([format](ledger-format.md)) |
| **marker** | a searchable value of a canary: its email, a key, a token, a reference code |
| **detect** | `search` - found by looking it up; `inbox` - an address on your own domain, caught by mail |
| **source** | a place to look: HIBP, GitHub code search, your catch-all mailbox, ... |

## Install

```bash
pip install stille-hunter          # Python 3.10+, no third-party dependencies
stille-hunter --version
```

## Where to keep things

The ledgers, the config and the history are secret: they say where every
canary is. Keep them in one private folder outside any app or repository:

```
~/.stille/                 (chmod 700)
  config.json              source keys, "notify", "inbox"   (chmod 600)
  ledgers/*.ledger.jsonl   one per planted batch
  history.jsonl            written by check --history
  reports/                 written by check --report
```

## generate

```bash
stille-hunter generate [--type TYPE] [options]
stille-hunter generate --list-types
```

Writes two files: the **seeded data** to plant, and the **ledger** to keep.

| option | meaning |
|---|---|
| `--type` | canary type (default `member`); `--list-types` lists them |
| `--count N` | how many (default 10) |
| `--tag TAG` | seed tag: where you will plant them (default `default`) |
| `--format` | `jsonl` (default), `csv`, `json` (an array, e.g. for a Laravel seeder), `sql` (INSERTs) |
| `--table NAME` | table the rows go into; required for `sql`, recorded in the ledger always |
| `--dialect` | `mysql` (default) or `postgres`, for `sql` |
| `--columns` | select and rename seeded fields: `field=column,field2` |
| `--out PATH` | seeded file, without extension (default `canary_seeded`) |
| `--ledger-out PATH` | where the ledger goes (default: next to the seeded file); folders are created |

### Types

| type | plants | its own options |
|---|---|---|
| `member` | a member record: name, email, password hash, phone, address, card, rank, ... | `--locale`, `--self-domain`, `--self-ratio` (default 0.4), `--brand`, `--luhn` |
| `db_dump` | table rows with a searchable reference code (`CUS-A3F8C10421`) | `--locale` |
| `aws_key` | an inert AWS access-key pair | `--prefix`, `--region` |
| `api_token` | an inert API token | `--provider github\|openai\|stripe\|slack\|generic`, `--mix` |
| `azure_credential` | an inert service-principal credential | - |
| `mcp_config` | an MCP server config with an inert token | `--server github\|slack`, `--mix` |
| `kubeconfig` | a kubeconfig with an inert token and a private-address server | `--cluster-name` |

**Locales** (`member`, `db_dump`): `jp` (default), `us`, `gb`, `ca`, `de`, `tw`
(`zh-TW` is the same as `tw`). Names, addresses, postcodes, phones and mail
domains match the region; markers stay ASCII so they can be searched.

**Safety of `member`:** card numbers use test BINs and fail the Luhn check by
default (`--luhn valid` only if your schema validates it), no CVV, no national
IDs, adults only.

**`--self-domain DOMAIN`** puts part of the `member` canaries (`--self-ratio`)
on a domain you control: they are `detect: inbox` and caught by mail. Use a
real domain you can receive mail on - placeholders such as `example.com` are
refused. See [inbox.md](inbox.md).

### Into a database

stille-hunter never connects to your database; you run its output yourself.

```bash
stille-hunter generate --type member --count 20 --format sql --table members \
  --columns "user_id,full_name=name,email,password_hash=password" --tag www-members \
  --ledger-out ~/.stille/ledgers/www-members.ledger.jsonl
```

`--format json` writes an array for a framework seeder (the README has a
Laravel example). Delete the seeded file once loaded.

## check

```bash
stille-hunter check LEDGER [LEDGER ...] --sources hibp,github --config ~/.stille/config.json
```

| option | meaning |
|---|---|
| `--sources a,b` | sources to use (default `null`, which finds nothing); `--list-sources` lists them with the marker kinds each searches |
| `--config PATH` | JSON config: per-source settings, `notify`, `inbox` |
| `--include-inbox` | also look up `detect: inbox` canaries (normally left to `inbox`) |
| `--out PATH` | write hits as JSON lines |
| `--report PATH` | `.html` or `.json` report of the run; repeatable; never contains canary values |
| `--report-title TEXT` | title of the report (default: host name) |
| `--history PATH` | append one line for this run to a history file |
| `--no-notify` | do not notify for this run |
| `--notify-test` | send a test notification and exit (no ledger needed) |

Several ledgers are checked in one run (one notification, one report).
Retired canaries are skipped. A source that is not configured (no API key) is
skipped with the reason; a source that fails is reported and does not stop
the others.

**Exit codes:** `0` clean, `1` a canary was found, `2` usage error - so cron
or CI can alert on `1`.

### Sources

| source | config (under its name) | looks up |
|---|---|---|
| `null` | - | nothing (a reference stub) |
| `hibp` | `api_key` (HIBP Core or higher), optional `user_agent`, `min_interval` (default 6.5 s), `include_unverified` (default true) | canary emails in known breaches |
| `github` | `token` (any PAT), optional `user_agent`, `min_interval` (default 6.5 s), `markers` (kinds to search) | secret-looking markers in public code |
| `inbox` | see [inbox](#inbox) | mail to your inbox canaries; needs `--include-inbox` here |

A fresh canary reads clean until a *new* leak includes it. Run `check` on a
schedule.

### Notifications

Under `notify` in the config - a webhook and/or email:

```json
"notify": {
  "webhook": {"url": "https://hooks.slack.com/services/..."},
  "email": {"host": "smtp.example.org", "port": 587, "security": "starttls",
            "username": "...", "password": "...",
            "from": "alerts@example.org", "to": ["secops@example.org"]},
  "on_errors": true
}
```

- The webhook style (Slack, Discord or generic JSON) follows the URL, or set
  `"style"`. `security` is `starttls`, `ssl` or `none`; `to` is a string or a
  list.
- A message goes out when a run finds something, and - unless `"on_errors":
  false` - when a source fails, because a check that silently stopped working
  looks exactly like "nothing leaked". A clean run sends nothing.
- Messages carry the record id, seed tag, source and where - never a canary
  value, never leaked content. Seed tags say where canaries are: use a private
  channel.

```bash
stille-hunter check --notify-test --config ~/.stille/config.json
```

### Reports

`--report run.html` is one self-contained page (light and dark): status, hits,
each source's outcome and what it covered, and the canaries checked by seed
tag and marker. `--report run.json` holds the same for scripts. Reports never
contain canary values and are written readable by their owner only.

## inbox

```bash
stille-hunter inbox LEDGER [LEDGER ...] (--mbox PATH | --maildir PATH | --imap HOST) [options]
stille-hunter inbox LEDGER [LEDGER ...] --config ~/.stille/config.json
```

Matches mail received on your catch-all against the ledger: **recipient
headers only**, never message contents. IMAP is opened read-only and nothing is
marked as read. Options: `--imap-user`, `--imap-port`, `--imap-folder`
(default `INBOX`), `--domain` (repeatable; default from the config, else the
ledger's inbox domains), `--days N`, and `--config`, `--out`, `--report`,
`--report-title`, `--history`, `--no-notify` as for `check`. Same exit codes.

The IMAP password comes from the config (`inbox.imap.password`) or the
`STILLE_IMAP_PASSWORD` environment variable, never from the command line.
Setting up the domain and the catch-all: [inbox.md](inbox.md).

## history

```bash
stille-hunter history ~/.stille/history.jsonl [--days 30] [--json] [--ledger LEDGER ...]
```

Summarises what `check --history` / `inbox --history` recorded: runs and
failures per source, hits per seed tag and per source, and per canary when it
was **first** and **last** seen and whether it is **new** in the period
(`--days`, default 30; `0` = all). A daily check sees the same leak every day;
`NEW` marks the ones that first appeared in the period. `--ledger` marks
canaries you have since retired.

## ledger

```bash
stille-hunter ledger list   LEDGER [LEDGER ...] [--all] [--json]
stille-hunter ledger retire LEDGER (--tag TAG | --id RECORD_ID)... [--reason TEXT] [--dry-run]
stille-hunter ledger rotate LEDGER --tag TAG [--out PATH] [--reason TEXT] [--dry-run] [generate options]
```

- **list** - per seed tag: active and retired canaries, types, inbox
  addresses, table, dates. Counts only, never values. `--all` includes seed
  tags that are fully retired.
- **retire** - when you remove a batch from where it was planted. The rows
  stay in the ledger (they still explain old hits) but `check` and `inbox`
  skip them.
- **rotate** - plant a fresh batch for a seed tag: generates the same type and
  number, keeping the locale, inbox domain and table unless you pass other
  generate options, adds it to the ledger, then retires the old batch. If
  generating fails, nothing is retired. Plant the new seeded file, then remove
  the old canaries.

Ledgers are rewritten atomically and keep their file permissions.

## Running it unattended

Schedule `check` (and `inbox`) daily with notifications on: cron, Windows Task
Scheduler or a private GitHub Actions workflow - see
[unattended.md](unattended.md).

## When a canary is found

The seed tag tells you which dataset leaked: the table, export or server you
planted that batch in. Treat it as an incident in that system - the canary is
the evidence that data left it, and the hit's date says by when. The location
says where it surfaced; for `inbox`, the sender domains say who is using the
list, not who leaked it.

## Config file reference

One JSON file holds everything (`--config`). Each section is optional.

| section | read by | keys |
|---|---|---|
| `hibp` | `check --sources hibp` | `api_key`, `user_agent`, `min_interval`, `include_unverified` |
| `github` | `check --sources github` | `token`, `user_agent`, `min_interval`, `markers` |
| `inbox` | `inbox`, `check --sources inbox` | one of `mbox`, `maildir`, `imap` (`host`, `port`, `user`, `password`, `folder`, `ssl`, `starttls`); `domain`; `days` |
| `notify` | `check`, `inbox` | `webhook` (`url`, `style`), `email` (`host`, `port`, `security`, `username`, `password`, `from`, `to`), `on_errors` |

A plugin source reads the section under its own name. See
`examples/config.example.json`.
