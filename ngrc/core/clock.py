"""Single time source so tests can control time (monkeypatch `now`)."""
from datetime import UTC, datetime


def now() -> datetime:
    return datetime.now(UTC)
