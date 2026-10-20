"""TEST-ONLY helpers for the evidence / search suites. Lives under tests/ so no test-support code ships in the application package."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from django.conf import settings

from ngrc.evidence.scanner import EICAR

PDF = b"%PDF-1.7\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
EICAR_FILE = b"harmless test file\n" + EICAR + b"\n"


@dataclass
class Made:
    id: str
    rev: str
    sha256: str
    size: int
    state: str
    content: bytes


def create(user, *, title="Quarterly access review", description="", data_class="C") -> str:
    r = user.api.post("/tenant/evidence/", {"title": title, "description": description, "data_class": data_class})
    assert r.status_code == 201, r.content
    return r.json()["id"]


def upload(user, evidence_id, content=PDF, *, filename="report.pdf", content_type="application/pdf"):
    return user.api.upload(f"/tenant/evidence/{evidence_id}/revisions/", content, content_type, filename)


def make_evidence(user, *, content=PDF, filename="report.pdf", content_type="application/pdf", title="Quarterly access review",
                  description="", data_class="C") -> Made:
    eid = create(user, title=title, description=description, data_class=data_class)
    r = upload(user, eid, content, filename=filename, content_type=content_type)
    assert r.status_code == 201, r.content
    j = r.json()
    return Made(eid, j["id"], j["sha256"], j["size_bytes"], j["state"], content)


def download_url(m: Made) -> str:
    return f"/tenant/evidence/{m.id}/revisions/{m.rev}/download/"


def stored_path(tenant_id, rev_id) -> Path:
    return Path(settings.EVIDENCE_STORE_DIR) / "tenants" / str(tenant_id) / "evidence" / str(rev_id)
