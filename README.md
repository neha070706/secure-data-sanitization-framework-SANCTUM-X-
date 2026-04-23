# 🛡️ Secure Data Sanitization Framework
### Air-Gap Transfer with Full Sanitization & Audit Trail

> Hackathon Project — Cybersecurity Track

---

## What It Does

Transfers files safely between two **air-gapped networks** (completely isolated networks with no internet).  
Every file is scanned, sanitized, encrypted, and logged before it physically crosses the gap.

**Real-world problem:** The Stuxnet worm (2010) destroyed Iranian nuclear centrifuges by exploiting
the one weak point of air-gapped networks — the USB drives used to bring data in.
This framework eliminates that attack surface.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate demo sample files
python generate_samples.py

# 3. Run the app
streamlit run app/main.py
```

Then open `http://localhost:8501` in your browser.

---

## Project Structure

```
secure-sanitization-framework/
├── app/
│   ├── main.py              ← Streamlit UI (all 5 pages)
│   ├── sanitizer.py         ← Core sanitization engine (PDF, image, Office, text)
│   ├── transfer_manager.py  ← AES-256 bundle creation & decryption
│   └── audit_logger.py      ← Immutable SHA-256 chained audit log
├── rules/
│   └── default_rules.json   ← Extension allowlist, threat keywords, size limits
├── uploads/                 ← Incoming files (Network A — untrusted)
├── quarantine/              ← Files that failed threat scan
├── sanitized/               ← Clean output files + encrypted bundles
├── audit_logs/              ← Tamper-evident JSONL audit trail
├── tests/
│   └── test_sanitizer.py    ← Unit tests (run with pytest)
├── generate_samples.py      ← Creates demo files for the presentation
└── requirements.txt
```

---

## The 5-Stage Pipeline

| Stage | What Happens |
|-------|-------------|
| 1. Ingest | Upload files; SHA-256 baseline established |
| 2. Threat Scan | Extension check · keyword scan · macro detection · LSB heuristic |
| 3. Sanitize | Strip metadata · remove macros · re-encode images |
| 4. Package | AES-256 encrypted bundle + SHA-256 manifest |
| 5. Audit Log | Immutable chained log — every action recorded |

---

## Sanitization Details

| File Type | Actions Applied |
|-----------|----------------|
| PDF | Strip author/GPS metadata, remove JavaScript actions |
| JPEG / PNG | Strip EXIF (incl. GPS), re-encode to destroy steganography |
| DOCX | Remove VBA macros, clear author properties |
| XLSX | Remove VBA macros, reveal hidden sheets |
| TXT / CSV | Strip null bytes and control characters |
| EXE / BAT / PS1 | **Blocked and quarantined — never allowed** |

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## Tech Stack

| Layer | Tool |
|-------|------|
| UI | Streamlit |
| PDF sanitize | pikepdf |
| Image sanitize | Pillow |
| Office sanitize | python-docx + openpyxl |
| Encryption | cryptography (Fernet / AES-256) |
| Hashing | hashlib (SHA-256, built-in) |
| Audit log | stdlib only — no external deps |

---

## Hackathon Pitch

> *"80% of critical infrastructure runs on air-gapped networks.
> The only way in is physical media — and that's exactly how Stuxnet attacked Iran.
> We built an open-source framework that inspects, sanitizes, and cryptographically
> verifies every byte before it crosses the air gap."*
