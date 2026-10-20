#!/usr/bin/env python3
"""Build the P2-2 independent-review package: a zip of the in-scope source, tests, design ADRs and context documents, plus a manifest
with SHA-256 digests. The *package digest* covers only the reviewed MATERIAL (scope files, tests, ADRs) so that regenerated reports do not
invalidate a review; context documents are bundled and listed but excluded from the digest.

A reviewer records `package_sha256` in docs/review/REVIEW_RECORD.yaml (`reviewed_manifest_sha256`). If any reviewed file changes afterwards,
scripts/check_review_record.py reports that review as STALE. This script does not review anything.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "evidence" / "review_package"
SCOPE = ROOT / "docs" / "review" / "review_scope.yaml"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rel(p: Path) -> str:
    return p.resolve().relative_to(ROOT.parent.parent).as_posix()   # relative to the repository workspace root (E:/NsureGRC-Precode)


def main() -> int:
    spec = yaml.safe_load(SCOPE.read_text(encoding="utf-8"))
    material: dict[str, Path] = {}
    for s in spec["scopes"]:
        for f in [*s["files"], *s["tests"]]:
            material[rel(ROOT / f)] = ROOT / f
    adrs = {rel((ROOT / d).resolve()): (ROOT / d).resolve() for d in spec["supporting_docs"] if "PHASE0" in d}
    context = {rel((ROOT / d).resolve()): (ROOT / d).resolve() for d in spec["supporting_docs"] if "PHASE0" not in d}
    context.update({rel(ROOT / "docs" / "review" / "review_scope.yaml"): ROOT / "docs" / "review" / "review_scope.yaml"})
    missing = [k for k, v in {**material, **adrs, **context}.items() if not v.is_file()]
    if missing:
        print("MISSING scope files:", *missing, sep="\n  ")
        return 2

    reviewed = {**material, **adrs}
    entries = []
    for group, files in (("reviewed", reviewed), ("context", context)):
        for name, path in sorted(files.items()):
            data = path.read_bytes()
            entries.append({"path": name, "group": group, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                            "lines": data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)})
    digest_input = "\n".join(f"{e['sha256']}  {e['path']}" for e in entries if e["group"] == "reviewed")
    package_sha = hashlib.sha256(digest_input.encode()).hexdigest()

    def git(*args: str) -> str | None:
        try:
            return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True, timeout=30).stdout.strip() or None  # noqa: S603,S607
        except (OSError, subprocess.SubprocessError):
            return None

    manifest = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"), "package_sha256": package_sha,
        "digest_covers": "files in group 'reviewed' (scope files, tests, Phase 0 ADRs): sha256 over sorted '<sha256>  <path>' lines",
        "git_commit": git("rev-parse", "HEAD"), "git_dirty": bool(git("status", "--porcelain")),
        "uv_lock_sha256": sha(ROOT / "uv.lock"), "python": sys.version.split()[0],
        "scopes": [{"id": s["id"], "title": s["title"], "design_refs": s["design_refs"], "files": s["files"], "tests": s["tests"]} for s in spec["scopes"]],
        "files": entries,
        "note": "This manifest identifies what was handed to a reviewer. It is not a review, and the digest protects against accidental "
                "change, not a malicious rewrite (it is not signed).",
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "review_package_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    zpath = OUT / f"nsuregrc_review_package_{package_sha[:12]}.zip"
    for old in OUT.glob("nsuregrc_review_package_*.zip"):
        old.unlink()
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("MANIFEST.json", json.dumps(manifest, indent=2))
        for e in entries:
            z.write(ROOT.parent.parent / e["path"], arcname=e["path"])
    print(f"package_sha256={package_sha}\nfiles: reviewed={sum(e['group'] == 'reviewed' for e in entries)} "
          f"context={sum(e['group'] == 'context' for e in entries)}\nzip={zpath.name} ({zpath.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
