"""Upload content inspection (D-P0-007 s5): the declared type must be on the allow-list AND agree with what the bytes are.

Allow-list (P0): PDF, PNG, JPEG, plain text / CSV, and OOXML documents (docx/xlsx/pptx). Everything else - executables, scripts, HTML, SVG,
generic archives - is refused. OOXML files are ZIP containers, so they are checked for archive bombs (entry count, total uncompressed size,
compression ratio) and path escapes WITHOUT extracting anything. Known limit: nested archives inside an OOXML package are not unpacked or inspected.
"""
from __future__ import annotations

import io
import zipfile

OOXML = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word/",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xl/",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "ppt/",
}
ALLOWED = {"application/pdf", "image/png", "image/jpeg", "text/plain", "text/csv", *OOXML}
MAX_ZIP_ENTRIES, MAX_ZIP_UNCOMPRESSED, MAX_ZIP_RATIO = 2000, 200 * 1024 * 1024, 200
_EXEC_MAGIC = (b"MZ", b"\x7fELF", b"#!", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


class Rejected(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def inspect(declared: str, head: bytes, full: bytes | None = None) -> str:
    """Return the detected type (equal to `declared`) or raise Rejected. `full` is only needed for ZIP-based formats."""
    declared = (declared or "").split(";")[0].strip().lower()
    if declared not in ALLOWED:
        raise Rejected("type_not_allowed")
    if head.startswith(_EXEC_MAGIC):
        raise Rejected("executable_content")
    if declared == "application/pdf":
        ok = head.startswith(b"%PDF-")
    elif declared == "image/png":
        ok = head.startswith(b"\x89PNG\r\n\x1a\n")
    elif declared == "image/jpeg":
        ok = head.startswith(b"\xff\xd8\xff")
    elif declared in {"text/plain", "text/csv"}:
        ok = b"\x00" not in head and _is_utf8(head)
    else:
        return _inspect_ooxml(declared, head, full)
    if not ok:
        raise Rejected("content_does_not_match_declared_type")
    return declared


def _is_utf8(b: bytes) -> bool:
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:  # a multi-byte character cut at the end of the sniffed prefix is not an error
        try:
            b[:-3].decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False


def _inspect_ooxml(declared: str, head: bytes, full: bytes | None) -> str:
    if not head.startswith(b"PK\x03\x04") or full is None:
        raise Rejected("content_does_not_match_declared_type")
    try:
        z = zipfile.ZipFile(io.BytesIO(full))
        infos = z.infolist()
    except zipfile.BadZipFile as exc:
        raise Rejected("corrupt_archive") from exc
    if len(infos) > MAX_ZIP_ENTRIES:
        raise Rejected("archive_too_many_entries")
    total = 0
    for i in infos:
        n = i.filename
        if n.startswith(("/", "\\")) or ".." in n.replace("\\", "/").split("/") or i.flag_bits & 0x1:
            raise Rejected("archive_unsafe_entry")
        total += i.file_size
        if total > MAX_ZIP_UNCOMPRESSED or (i.compress_size and i.file_size / i.compress_size > MAX_ZIP_RATIO and i.file_size > 1_000_000):
            raise Rejected("archive_bomb")
    names = {i.filename for i in infos}
    if "[Content_Types].xml" not in names or not any(n.startswith(OOXML[declared]) for n in names):
        raise Rejected("content_does_not_match_declared_type")
    return declared
