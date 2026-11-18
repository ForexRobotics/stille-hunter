# Running `check` unattended

The point of stille-hunter is to plant canaries, forget about them, and be told
when one surfaces. That means running `check` on a schedule, with
notifications on. This guide covers three ways: cron on a Linux server, Windows
Task Scheduler, and a scheduled GitHub Actions workflow in a **private**
repository.

## 1. Keep the secrets outside any repository

The config (API keys, webhook URL, SMTP password) and the ledgers are secret.
Keep them in one private folder, never in a repository or an app:

```
~/.stille/
  config.json            # source keys + "notify" settings   (chmod 600)
  ledgers/
    www-members.ledger.jsonl
    crm-customers.ledger.jsonl
```

`generate --ledger-out ~/.stille/ledgers/<name>.ledger.jsonl` writes a ledger
straight there.

## 2. Turn on notifications and test them

Add a `notify` section to `config.json` (see `examples/config.example.json`):

```json
"notify": {
  "webhook": {"url": "https://hooks.slack.com/services/..."},
  "email": {"host": "smtp.example.org", "port": 587, "security": "starttls",
            "username": "alerts", "password": "...",
            "from": "alerts@example.org", "to": ["secops@example.org"]},
  "on_errors": true
}
```

Use either channel or both. The webhook style - Slack, Discord, or generic JSON
for anything else - is detected from the URL. Then check that messages arrive:

```bash
stille-hunter check --notify-test --config ~/.stille/config.json
```

A run notifies when it finds a hit, and also when a source **fails** (an
expired API key, a network error): an unattended check that silently stops
working looks exactly like "nothing leaked". A clean run sends nothing. Set
`"on_errors": false` to be told about hits only. Messages name the canary, the
seed tag it was planted under, the source and where it was found - never the
canary's value. Seed tags say where your canaries are, so send them to a
private channel.

## 3a. cron on a Linux server

The simplest option: a server you already run.

```bash
python3 -m venv ~/.stille/venv
~/.stille/venv/bin/pip install stille-hunter
chmod 600 ~/.stille/config.json ~/.stille/ledgers/*
```

`~/.stille/check.sh` checks every ledger:

```bash
#!/bin/sh
for ledger in "$HOME"/.stille/ledgers/*.ledger.jsonl; do
  "$HOME"/.stille/venv/bin/stille-hunter check "$ledger" \
    --sources hibp,github --config "$HOME"/.stille/config.json
done
```

Then `chmod 700 ~/.stille/check.sh` and add a daily entry with `crontab -e`:

```
17 6 * * * $HOME/.stille/check.sh >> $HOME/.stille/check.log 2>&1
```

To keep a page you can open after each run, add
`--report "$HOME/.stille/reports/$(basename "$ledger" .ledger.jsonl).html"` to
the `check` line (create `~/.stille/reports` first). It is overwritten each
run; add `--report ....json` too if a script or an AI assistant should read it.

## 3b. Windows Task Scheduler

Create `%USERPROFILE%\.stille\check.cmd`:

```bat
@echo off
for %%L in ("%USERPROFILE%\.stille\ledgers\*.ledger.jsonl") do (
  "%USERPROFILE%\.stille\venv\Scripts\stille-hunter.exe" check "%%~L" ^
    --sources hibp,github --config "%USERPROFILE%\.stille\config.json" ^
    >> "%USERPROFILE%\.stille\check.log" 2>&1
)
```

and register it from PowerShell (the venv is created with
`py -m venv $env:USERPROFILE\.stille\venv` and
`& $env:USERPROFILE\.stille\venv\Scripts\pip install stille-hunter`):

```powershell
schtasks /Create /TN "stille-hunter check" /SC DAILY /ST 06:17 /TR "$env:USERPROFILE\.stille\check.cmd"
```

The task only runs while the PC is on; a server is the more reliable home.

## 3c. GitHub Actions - private repository only

Run it from a **private** repository you create for this, never from a public
one: workflow logs show the hits, and a public repository's logs are public.
The config and the ledger live in Actions secrets and are written to the
runner's temporary folder for the run only - never committed, never uploaded
as an artifact. A secret holds up to 48 KB, enough for a ledger of a few
hundred canaries.

Store them (from bash; the ledger goes in base64):

```bash
gh secret set STILLE_CONFIG --repo you/canary-checks < ~/.stille/config.json
base64 -w0 ~/.stille/ledgers/www-members.ledger.jsonl \
  | gh secret set STILLE_LEDGER_B64 --repo you/canary-checks
```

or from PowerShell:

```powershell
Get-Content -Raw $env:USERPROFILE\.stille\config.json | gh secret set STILLE_CONFIG --repo you/canary-checks
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:USERPROFILE\.stille\ledgers\www-members.ledger.jsonl")) |
  gh secret set STILLE_LEDGER_B64 --repo you/canary-checks
```

`.github/workflows/canary-check.yml` in that private repository:

```yaml
name: canary check
on:
  schedule:
    - cron: "17 21 * * *"     # 06:17 JST
  workflow_dispatch:
permissions: {}               # needs no access to the repository
jobs:
  check:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: "3.12"
      - run: pip install "stille-hunter==0.3.*"
      - name: Write config and ledger from secrets
        env:
          STILLE_CONFIG: ${{ secrets.STILLE_CONFIG }}
          STILLE_LEDGER_B64: ${{ secrets.STILLE_LEDGER_B64 }}
        run: |
          umask 077
          printf '%s' "$STILLE_CONFIG" > "$RUNNER_TEMP/config.json"
          printf '%s' "$STILLE_LEDGER_B64" | base64 -d > "$RUNNER_TEMP/canaries.ledger.jsonl"
      - run: >
          stille-hunter check "$RUNNER_TEMP/canaries.ledger.jsonl"
          --sources hibp,github --config "$RUNNER_TEMP/config.json"
```

A hit makes the run fail (exit code 1), so GitHub also emails whoever last
changed the schedule - a second alert on top of your `notify` channels.

## Pace and exit codes

Sources are rate-limited, so check daily rather than hourly. HIBP's Core plan
allows about 10 lookups a minute (one email every 6.5 s: 200 canaries take
about 22 minutes); GitHub code search allows 10 searches a minute.

`check` exits with `0` when clean, `1` when a canary was found, and `2` on a
usage error.

## When a canary is found

The seed tag in the message tells you which dataset leaked - the table, export
or server you planted that batch in. Treat it as an incident in that system:
the canary is the evidence that data left it, and when it surfaced.
