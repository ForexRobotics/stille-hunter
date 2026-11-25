# Inbox detection: a catch-all for your canary addresses

Search detection waits for a leak to show up somewhere searchable. Inbox
detection is faster: canary addresses on a domain **you** control receive mail
the moment someone starts using a leaked list - spam, phishing, credential
stuffing confirmations. Nobody has a legitimate reason to write to those
addresses, so any mail to one is a signal, and the ledger says where it was
planted.

This guide sets up the mailbox that catches that mail, then runs
`stille-hunter inbox` against it.

## How it works

1. Generate canaries with `--self-domain`. Part of them (`--self-ratio`,
   default 40%) get addresses on that domain and are recorded as
   `detect: inbox` in the ledger.

   ```bash
   stille-hunter generate --count 50 --locale jp \
     --self-domain quiet-harbour.net --tag www-members \
     --ledger-out ~/.stille/ledgers/www-members.ledger.jsonl
   ```

2. Mail for **any** address on that domain lands in one mailbox (a
   *catch-all*), because every canary address is different.
3. `stille-hunter inbox` reads that mailbox and matches the recipient
   addresses against the ledger.

`inbox` reads **recipient headers only** (To, Cc, Delivered-To, X-Original-To,
Envelope-To), plus Date and From. It never fetches message bodies from IMAP
(headers are read with `BODY.PEEK`, the folder is opened read-only, nothing is
marked as read or changed) and never keeps message contents. The report says,
per canary: how many messages, first and last date, and the sender domains.

## 1. Choose the domain

- **Use a domain unrelated to your organisation.** An address at
  `acme-corp-security.com` tells whoever holds the leaked list that it is a
  trap, and who set it. A plain, forgettable domain (`quiet-harbour.net`) does
  not.
- Register it separately from your main domains if you can, and keep the
  registration details private (most registrars offer WHOIS privacy).
- Use it **only** for canaries. Real mail on the same domain makes every
  message ambiguous.
- `generate --self-domain` refuses placeholder names such as `example.com`:
  the addresses must be deliverable.

## 2. DNS

Point the domain's mail at the server or provider that will hold the catch-all:

| record | value |
|---|---|
| `MX` | your mail server or the provider's MX hosts (priority as they say) |

This domain never sends mail, so also tell the world that nothing may send as
it. That stops it from being abused for spoofing, and costs nothing:

| record | name | value |
|---|---|---|
| `TXT` (SPF) | `@` | `v=spf1 -all` |
| `TXT` (DMARC) | `_dmarc` | `v=DMARC1; p=reject` |

## 3a. Self-hosted: Postfix delivering to a Maildir

On a server you run, accept the domain and send every address on it to one
local user (here `canary`), who keeps mail in a Maildir.

`/etc/postfix/main.cf`:

```
virtual_alias_domains = quiet-harbour.net
virtual_alias_maps = hash:/etc/postfix/virtual
home_mailbox = Maildir/
```

`/etc/postfix/virtual` - the `@domain` line is the catch-all:

```
@quiet-harbour.net    canary
```

```bash
sudo useradd -m -s /usr/sbin/nologin canary
sudo postmap /etc/postfix/virtual
sudo systemctl reload postfix
```

Open port 25 to the internet for this server, and make sure it is not an open
relay (Postfix's defaults are not). Mail now lands in
`/home/canary/Maildir/`, and `inbox` can read it directly:

```bash
stille-hunter inbox ~/.stille/ledgers/*.ledger.jsonl \
  --maildir /home/canary/Maildir --days 30
```

(Run it as a user that can read that Maildir, or add Dovecot and use IMAP as
below.)

## 3b. Hosted: a provider with catch-all routing

Many mail providers can deliver *all addresses on a domain* to one mailbox -
look for "catch-all" or "default routing" in the domain settings. Two common
patterns:

- **A mailbox provider with custom domains and a catch-all** (for example
  Fastmail, or Google Workspace's routing rules): add the domain, set the MX
  records they give you, enable the catch-all into one mailbox, then read it
  over IMAP.
- **A forwarding service with a catch-all** (for example Cloudflare Email
  Routing): it accepts mail for the domain and forwards everything to one
  verified address. Point that at a dedicated mailbox you can read over IMAP -
  not your personal inbox.

Follow your provider's own documentation for the exact settings; they change
over time. Then:

```bash
export STILLE_IMAP_PASSWORD='...'      # or put it in the config, see below
stille-hunter inbox ~/.stille/ledgers/*.ledger.jsonl \
  --imap imap.your-provider.net --imap-user canary@quiet-harbour.net --days 30
```

Use an app password or a dedicated account where the provider offers one.
`inbox` only logs in, opens the folder read-only and reads headers.

## 4. Run it unattended

Put the mailbox in the same private config as everything else
(`~/.stille/config.json`, `chmod 600`):

```json
{
  "inbox": {
    "domain": "quiet-harbour.net",
    "imap": {
      "host": "imap.your-provider.net",
      "user": "canary@quiet-harbour.net",
      "password": "YOUR_APP_PASSWORD",
      "folder": "INBOX"
    },
    "days": 7
  },
  "notify": { "webhook": { "url": "https://hooks.slack.com/services/..." } }
}
```

Use `"mbox": "/path/to/file"` or `"maildir": "/path/to/Maildir"` instead of
`"imap"` for local mail - exactly one of the three. `"domain"` may be a list;
when it is left out, the domains of the ledger's inbox canaries are used.

```bash
stille-hunter inbox ~/.stille/ledgers/*.ledger.jsonl --config ~/.stille/config.json
```

It behaves like `check`: it prints what it found, can write `--out` and
`--report`, sends the configured notifications, and exits `1` when a canary
was contacted - so the [unattended guide](unattended.md) applies as is. The
same matching is available as a check source, so it can run in one go with the
others:

```bash
stille-hunter check ~/.stille/ledgers/*.ledger.jsonl \
  --sources hibp,github,inbox --include-inbox --config ~/.stille/config.json
```

(`--include-inbox` is needed here: by default `check` leaves inbox canaries
to the inbox.)

Keep `days` a little longer than the interval between runs (a daily run with
`"days": 7` is fine): it limits how much mail is read, and the same message
seen twice only repeats a hit you already know about.

## What a hit means

Mail to a canary address means the list it was planted in has reached someone
who sends mail - most often a spammer or a phisher working from a leaked or
sold list. Use the `seed_tag` in the hit to find where that canary was planted,
and treat that system's data as exposed. The sender domains in the report
point at who is using the list; they are not who leaked it.
