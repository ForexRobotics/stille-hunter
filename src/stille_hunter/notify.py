# SPDX-License-Identifier: Apache-2.0
"""Notifications for `check`: tell someone when a canary is found.

Configured under "notify" in the config file (the same file that holds source
API keys, so it is already private and gitignored):

    "notify": {
      "webhook": {"url": "https://hooks.slack.com/services/..."},
      "email": {"host": "smtp.example.org", "port": 587, "security": "starttls",
                "username": "...", "password": "...",
                "from": "alerts@example.org", "to": ["secops@example.org"]},
      "on_errors": true
    }

A notification is sent when a run finds hits, and - unless "on_errors" is
false - when a source fails with an error, because an unattended check that
silently stops working looks exactly like "nothing leaked". A clean run sends
nothing. Webhook style (slack / discord / generic JSON) is detected from the
URL, or set with "style".

What is sent: which canary was found (record id), where it was planted (seed
tag), which source found it and where. Never the canary's secret value and
never any leaked content. Send it to a private channel: seed tags say where
your canaries are.

Standard library only (urllib, smtplib).
"""
from __future__ import annotations

import json
import smtplib
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage

STYLES = ("slack", "discord", "generic")
_LIMITS = {"discord": 2000, "slack": 3500}
_UA = "stille-hunter (notification)"


class NotifyError(Exception):
    """A notification could not be sent or is misconfigured."""


def errored_sources(skipped: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """The skips caused by a source failing (not by it being unconfigured)."""
    return [(name, reason) for name, reason in skipped if reason.startswith("error:")]


def compose(hits, errors, checked: int, sources: list[str]) -> tuple[str, str]:
    """(subject, plain-text body) describing a run's hits and source errors."""
    if hits:
        subject = f"stille-hunter: {len(hits)} canary hit(s) - a seeded dataset leaked"
    else:
        subject = f"stille-hunter: check failed on {len(errors)} source(s)"
    lines = []
    if hits:
        lines.append(f"Leaked canaries found: {len(hits)}")
        for h in hits:
            lines.append(f"- {h.canary.record_id} planted at [{h.canary.seed_tag}] "
                         f"found by {h.source} ({h.token_kind}): {h.location}")
            if h.detail:
                lines.append(f"  {h.detail}")
    if errors:
        if lines:
            lines.append("")
        lines.append("Sources that failed (their canaries were NOT checked):")
        lines.extend(f"- {name}: {reason}" for name, reason in errors)
    lines.append("")
    lines.append(f"Checked {checked} canaries against: {', '.join(sources)}.")
    return subject, "\n".join(lines)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    more = "\n... (truncated; see the check output for the full list)"
    cut = text[: limit - len(more)]
    if "\n" in cut:
        cut = cut[: cut.rindex("\n")]
    return cut + more


def detect_style(url: str, style: str | None = None) -> str:
    if style:
        if style not in STYLES:
            raise NotifyError(f"notify.webhook.style must be one of {', '.join(STYLES)}")
        return style
    if "://hooks.slack.com/" in url:
        return "slack"
    if "://discord.com/api/webhooks/" in url or "://discordapp.com/api/webhooks/" in url:
        return "discord"
    return "generic"


def webhook_payload(style: str, subject: str, body: str, hits, errors,
                    checked: int, sources: list[str]) -> dict:
    if style == "discord":
        text = _truncate(f"**{subject}**\n\n{body}", _LIMITS["discord"])
        return {"content": text, "allowed_mentions": {"parse": []}}
    if style == "slack":
        return {"text": _truncate(f"*{subject}*\n\n{body}", _LIMITS["slack"])}
    return {
        "event": "stille-hunter.check",
        "subject": subject,
        "checked": checked,
        "sources": sources,
        "hits": [{k: v for k, v in h.to_dict().items() if k != "token"} for h in hits],
        "errors": [{"source": n, "reason": r} for n, r in errors],
        "sent_at": datetime.now(timezone.utc).isoformat(),
    }


def send_webhook(cfg: dict, payload: dict, timeout: float = 20) -> None:
    url = cfg.get("url") or ""
    if not url.startswith("https://"):
        raise NotifyError("notify.webhook.url must be an https:// URL")
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if not 200 <= resp.status < 300:
                raise NotifyError(f"webhook answered HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        raise NotifyError(f"webhook answered HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise NotifyError(f"webhook unreachable: {e.reason}") from e


def send_email(cfg: dict, subject: str, body: str, timeout: float = 30) -> None:
    host, sender, to = cfg.get("host"), cfg.get("from"), cfg.get("to")
    if not (host and sender and to):
        raise NotifyError("notify.email needs host, from and to")
    recipients = [to] if isinstance(to, str) else list(to)
    security = cfg.get("security", "starttls")
    if security not in ("starttls", "ssl", "none"):
        raise NotifyError("notify.email.security must be starttls, ssl or none")
    port = int(cfg.get("port", 465 if security == "ssl" else 587))

    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, sender, ", ".join(recipients)
    msg.set_content(body)

    context = ssl.create_default_context()
    try:
        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)
        with server:
            if security == "starttls":
                server.starttls(context=context)
            if cfg.get("username"):
                server.login(cfg["username"], cfg.get("password", ""))
            server.send_message(msg)
    except (OSError, smtplib.SMTPException) as e:
        raise NotifyError(f"email not sent: {e}") from e


def channels(notify_cfg: dict) -> list[str]:
    return [c for c in ("webhook", "email") if notify_cfg.get(c)]


def deliver(notify_cfg: dict, subject: str, body: str, hits, errors,
            checked: int, sources: list[str]) -> list[str]:
    """Send to every configured channel. Returns problems (empty = all sent)."""
    problems = []
    if notify_cfg.get("webhook"):
        try:
            wh = notify_cfg["webhook"]
            style = detect_style(wh.get("url", ""), wh.get("style"))
            send_webhook(wh, webhook_payload(style, subject, body, hits, errors,
                                             checked, sources))
        except NotifyError as e:
            problems.append(f"webhook: {e}")
    if notify_cfg.get("email"):
        try:
            send_email(notify_cfg["email"], subject, body)
        except NotifyError as e:
            problems.append(f"email: {e}")
    return problems


def notify_run(notify_cfg: dict, hits, skipped, checked: int,
               sources: list[str]) -> tuple[bool, list[str]]:
    """Notify about a finished run if it warrants it.

    Returns (sent, problems). Nothing is sent for a clean run."""
    errors = errored_sources(skipped) if notify_cfg.get("on_errors", True) else []
    if not hits and not errors:
        return False, []
    subject, body = compose(hits, errors, checked, sources)
    return True, deliver(notify_cfg, subject, body, hits, errors, checked, sources)


def notify_test(notify_cfg: dict) -> list[str]:
    """Send a test message to every configured channel."""
    subject = "stille-hunter: test notification"
    body = ("This is a test. Notifications are set up correctly.\n"
            "No canary was found; this message was sent with --notify-test.")
    return deliver(notify_cfg, subject, body, [], [], 0, [])
