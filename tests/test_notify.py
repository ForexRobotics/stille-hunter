# SPDX-License-Identifier: Apache-2.0
"""Tests for notifications: what is sent, when, and to which channel."""
import json

import pytest

from stille_hunter import check, notify
from stille_hunter.check import CheckSource, Hit


# ---- capture outgoing traffic ----------------------------------------------
class _Resp:
    status = 204

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def posts(monkeypatch):
    sent = []

    def fake_urlopen(req, timeout=None):
        sent.append({"url": req.full_url, "body": json.loads(req.data.decode())})
        return _Resp()

    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    return sent


@pytest.fixture
def mails(monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None, context=None):
            self.calls = [("connect", host, port)]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            sent.append(self)
            return False

        def starttls(self, context=None):
            self.calls.append(("starttls",))

        def login(self, user, password):
            self.calls.append(("login", user))

        def send_message(self, msg):
            self.msg = msg

    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(notify.smtplib, "SMTP_SSL", FakeSMTP)
    return sent


# ---- test sources: one that finds a canary, one that fails -------------------
@pytest.fixture
def fake_sources():
    class Finds(CheckSource):
        name = "test-finds"

        def check(self, canaries):
            c = canaries[0]
            yield Hit(canary=c, source=self.name, token_kind="email", token=c.email,
                      location="https://paste.example/abc", detail="in a paste")

    class Fails(CheckSource):
        name = "test-fails"

        def check(self, canaries):
            raise RuntimeError("API key rejected (401)")

    check._REGISTRY.update({"test-finds": Finds, "test-fails": Fails})
    yield
    check._REGISTRY.pop("test-finds", None)
    check._REGISTRY.pop("test-fails", None)


def _ledger(tmp_path):
    p = tmp_path / "x.ledger.jsonl"
    p.write_text(json.dumps({
        "record_id": "a3f8c1", "seed_tag": "crm-prod", "detect": "search",
        "email": "a.b.a3f8c1@gmail.com", "password_hash": "secret-hash-value",
    }) + "\n", encoding="utf-8")
    return p


def _config(tmp_path, notify_cfg):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"notify": notify_cfg}), encoding="utf-8")
    return p


def _run(*argv):
    with pytest.raises(SystemExit) as e:
        check.main(list(argv))
    return e.value.code


# ---- behaviour ---------------------------------------------------------------
def test_hit_notifies_discord_without_secret_values(tmp_path, posts, fake_sources):
    cfg = _config(tmp_path, {"webhook": {"url": "https://discord.com/api/webhooks/1/x"}})
    code = _run(str(_ledger(tmp_path)), "--sources", "test-finds", "--config", str(cfg))
    assert code == 1                                   # exit code unchanged: a hit
    (post,) = posts
    body = post["body"]
    assert body["allowed_mentions"] == {"parse": []}
    assert "a3f8c1" in body["content"] and "[crm-prod]" in body["content"]
    assert "https://paste.example/abc" in body["content"]
    assert "a.b.a3f8c1@gmail.com" not in body["content"]   # never the canary value
    assert len(body["content"]) <= 2000


def test_clean_run_sends_nothing(tmp_path, posts):
    cfg = _config(tmp_path, {"webhook": {"url": "https://hooks.slack.com/services/x"}})
    assert _run(str(_ledger(tmp_path)), "--sources", "null", "--config", str(cfg)) == 0
    assert posts == []


def test_source_error_notifies_unless_disabled(tmp_path, posts, fake_sources):
    led = str(_ledger(tmp_path))
    cfg = _config(tmp_path, {"webhook": {"url": "https://hooks.slack.com/services/x"}})
    assert _run(led, "--sources", "test-fails", "--config", str(cfg)) == 0
    (post,) = posts
    assert "test-fails" in post["body"]["text"] and "NOT checked" in post["body"]["text"]

    posts.clear()
    cfg = _config(tmp_path, {"webhook": {"url": "https://hooks.slack.com/services/x"},
                             "on_errors": False})
    _run(led, "--sources", "test-fails", "--config", str(cfg))
    assert posts == []


def test_unconfigured_source_is_not_an_error(tmp_path, posts):
    # github without a token is skipped as "unavailable", not as a failure
    cfg = _config(tmp_path, {"webhook": {"url": "https://hooks.slack.com/services/x"}})
    _run(str(_ledger(tmp_path)), "--sources", "github", "--config", str(cfg))
    assert posts == []


def test_no_notify_flag(tmp_path, posts, fake_sources):
    cfg = _config(tmp_path, {"webhook": {"url": "https://hooks.slack.com/services/x"}})
    _run(str(_ledger(tmp_path)), "--sources", "test-finds", "--config", str(cfg),
         "--no-notify")
    assert posts == []


def test_generic_webhook_payload_omits_token(tmp_path, posts, fake_sources):
    cfg = _config(tmp_path, {"webhook": {"url": "https://example.org/hook"}})
    _run(str(_ledger(tmp_path)), "--sources", "test-finds", "--config", str(cfg))
    body = posts[0]["body"]
    assert body["event"] == "stille-hunter.check" and body["checked"] == 1
    (hit,) = body["hits"]
    assert hit["record_id"] == "a3f8c1" and hit["seed_tag"] == "crm-prod"
    assert "token" not in hit


def test_email_starttls_and_login(tmp_path, mails, fake_sources):
    cfg = _config(tmp_path, {"email": {"host": "smtp.example.org", "username": "u",
                                       "password": "p", "from": "a@example.org",
                                       "to": ["b@example.org", "c@example.org"]}})
    _run(str(_ledger(tmp_path)), "--sources", "test-finds", "--config", str(cfg))
    (smtp,) = mails
    assert smtp.calls == [("connect", "smtp.example.org", 587), ("starttls",),
                          ("login", "u")]
    assert "1 canary hit" in smtp.msg["Subject"]
    assert smtp.msg["To"] == "b@example.org, c@example.org"


def test_notify_test_needs_no_ledger(tmp_path, posts):
    cfg = _config(tmp_path, {"webhook": {"url": "https://hooks.slack.com/services/x"}})
    assert _run("--notify-test", "--config", str(cfg)) == 0
    assert "test notification" in posts[0]["body"]["text"]


def test_notify_test_without_channels_is_an_error(tmp_path):
    assert _run("--notify-test", "--config", str(_config(tmp_path, {}))) == 2


def test_plain_http_webhook_is_refused(tmp_path, posts, fake_sources, capsys):
    cfg = _config(tmp_path, {"webhook": {"url": "http://example.org/hook"}})
    _run(str(_ledger(tmp_path)), "--sources", "test-finds", "--config", str(cfg))
    assert posts == []
    assert "https://" in capsys.readouterr().err


@pytest.mark.parametrize("url,style", [
    ("https://hooks.slack.com/services/T/B/x", "slack"),
    ("https://discord.com/api/webhooks/1/x", "discord"),
    ("https://example.org/hook", "generic"),
])
def test_style_detection(url, style):
    assert notify.detect_style(url) == style
