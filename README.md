# Secure Data Sanitization Framework (SANCTUM-X)

Secure framework for transferring files across air-gapped environments with sanitization, encryption, and audit logging.

## Overview

This project is a Streamlit-based security workflow for handling files before they move between isolated networks.
It is designed to reduce the risk introduced by removable media and other controlled transfer paths.

Core capabilities:

- File ingestion and inspection
- Threat scanning for suspicious content and risky file types
- Sanitization for PDFs, images, Office files, and plain text
- Encrypted bundle creation for transfer
- Tamper-evident audit logging

## Quick Start

```bash
pip install -r requirements.txt
copy config\warehouse_config.example.json config\warehouse_config.json
python generate_samples.py
streamlit run app/main.py
```

Open `http://localhost:8501` in your browser.

For Windows PowerShell, you can also run:

```powershell
Copy-Item config\warehouse_config.example.json config\warehouse_config.json
```

## Project Structure

```text
secure-sanitization-framework/
|-- app/
|   |-- main.py
|   |-- sanitizer.py
|   |-- transfer_manager.py
|   |-- audit_logger.py
|   `-- warehouse_connector.py
|-- rules/
|   `-- default_rules.json
|-- uploads/
|-- quarantine/
|-- sanitized/
|-- decrypted/
|-- reports/
|-- audit_logs/
|-- sample_files/
|-- tests/
|   `-- test_sanitizer.py
|-- generate_samples.py
|-- requirements.txt
`-- README.md
```

## Processing Pipeline

1. Ingest files and calculate baseline hashes.
2. Scan for blocked extensions, suspicious patterns, macros, and hidden content indicators.
3. Sanitize supported file types by stripping metadata and removing active content where possible.
4. Package output into an encrypted transfer bundle.
5. Record each action in a chained audit log.

## Supported Handling

| File type | Example actions |
|---|---|
| PDF | Remove metadata and unsafe actions |
| PNG / JPEG | Strip EXIF and re-encode image data |
| DOCX | Remove macro-related embedded content and clear properties |
| XLSX | Remove VBA or embedded objects and expose hidden sheets when applicable |
| TXT / CSV | Clean control characters and null bytes |
| Executables / scripts | Block and quarantine |

## Tech Stack

- Streamlit
- pikepdf
- Pillow
- python-docx
- openpyxl
- cryptography
- jsonlines

## Tests

```bash
python -m pytest tests/ -v
```

## Notes

- The main UI lives in `app/main.py`.
- Audit logs are stored under `audit_logs/`.
- Generated encrypted bundles and sanitized outputs are stored under `sanitized/`.
- Local warehouse settings should be kept in `config/warehouse_config.json`, created from `config/warehouse_config.example.json`.
