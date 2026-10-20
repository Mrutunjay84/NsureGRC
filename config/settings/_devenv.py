"""DEV/TEST ONLY helper: load KEY=VALUE pairs from a local file outside the repo (never from the repo).

Used so developers do not have to `export` a dozen variables. Production never imports this module.
"""
from __future__ import annotations

import os
from pathlib import Path


def load_dev_env() -> None:
    path = Path(os.environ.get("NGRC_ENV_FILE", Path.home() / ".config" / "nsuregrc" / "dev.env"))
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())
