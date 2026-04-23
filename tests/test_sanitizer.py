"""
tests/test_sanitizer.py
-----------------------
Run with:  python -m pytest tests/ -v
"""

import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from sanitizer import (
    sha256_file, get_extension, file_size_mb,
    scan_file, sanitize_file, _keyword_scan, _office_has_macros
)


# ── helpers ────────────────────────────────────────────────────────────────────
def _write_tmp(content: bytes, suffix: str) -> str:
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tf.write(content)
    tf.close()
    return tf.name


# ── sha256 ─────────────────────────────────────────────────────────────────────
def test_sha256_consistent():
    path = _write_tmp(b"hello world", ".txt")
    h1 = sha256_file(path)
    h2 = sha256_file(path)
    assert h1 == h2
    assert len(h1) == 64
    os.unlink(path)


def test_sha256_differs():
    p1 = _write_tmp(b"aaa", ".txt")
    p2 = _write_tmp(b"bbb", ".txt")
    assert sha256_file(p1) != sha256_file(p2)
    os.unlink(p1); os.unlink(p2)


# ── extension ──────────────────────────────────────────────────────────────────
def test_get_extension():
    assert get_extension("/tmp/file.PDF")  == ".pdf"
    assert get_extension("/tmp/image.JPG") == ".jpg"
    assert get_extension("/tmp/doc.docx")  == ".docx"


# ── scan: blocked extension ────────────────────────────────────────────────────
def test_scan_blocks_exe():
    path = _write_tmp(b"MZ\x90\x00" + b"\x00"*60, ".exe")
    r = scan_file(path)
    assert r.verdict == "FAIL"
    assert any("Blocked" in t for t in r.threats)
    os.unlink(path)


# ── scan: clean text ───────────────────────────────────────────────────────────
def test_scan_clean_txt():
    path = _write_tmp(b"Hello, world. This is clean content.", ".txt")
    r = scan_file(path)
    assert r.verdict == "PASS"
    assert r.threats == []
    os.unlink(path)


# ── scan: keyword threat ───────────────────────────────────────────────────────
def test_scan_keyword_threat():
    path = _write_tmp(b"run this: powershell -enc abc123", ".txt")
    r = scan_file(path)
    assert r.verdict == "FAIL"
    assert any("powershell" in t for t in r.threats)
    os.unlink(path)


# ── macro detection ────────────────────────────────────────────────────────────
def test_macro_detection():
    # Create a fake XLSX ZIP with vbaProject.bin inside
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
    tmp.close()
    with zipfile.ZipFile(tmp.name, "w") as z:
        z.writestr("xl/vbaProject.bin", b"\x00" * 10)
        z.writestr("[Content_Types].xml", b"<Types/>")
    assert _office_has_macros(tmp.name) is True
    os.unlink(tmp.name)


def test_no_macro():
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
    tmp.close()
    with zipfile.ZipFile(tmp.name, "w") as z:
        z.writestr("[Content_Types].xml", b"<Types/>")
        z.writestr("xl/workbook.xml", b"<workbook/>")
    assert _office_has_macros(tmp.name) is False
    os.unlink(tmp.name)


# ── text sanitize ──────────────────────────────────────────────────────────────
def test_sanitize_text_strips_control_chars():
    content = b"Hello\x00World\x01\x02\x03"
    path    = _write_tmp(content, ".txt")
    out_dir = tempfile.mkdtemp()

    result = sanitize_file(path, out_dir)
    assert result.success

    with open(result.output_path, "r", encoding="utf-8") as f:
        cleaned = f.read()
    assert "\x00" not in cleaned
    assert "Hello" in cleaned
    assert "World" in cleaned

    os.unlink(path)
    import shutil; shutil.rmtree(out_dir)


# ── audit logger ───────────────────────────────────────────────────────────────
def test_audit_chain():
    from audit_logger import log_event, verify_chain, read_log

    # Write a couple of events
    log_event("TEST", "file_a.txt", "unit test entry 1", "PASS")
    log_event("TEST", "file_b.txt", "unit test entry 2", "PASS")

    assert verify_chain() is True


if __name__ == "__main__":
    print("Running basic tests…")
    test_sha256_consistent()
    test_sha256_differs()
    test_get_extension()
    test_scan_blocks_exe()
    test_scan_clean_txt()
    test_scan_keyword_threat()
    test_macro_detection()
    test_no_macro()
    test_sanitize_text_strips_control_chars()
    test_audit_chain()
    print("All tests passed ✅")
