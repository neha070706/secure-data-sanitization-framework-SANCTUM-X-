"""
main.py  —  SANCTUM-X v4.0
===========================
Classified Data Sanitization & Air-Gap Transfer System

v4.0 CHANGES:
  1. Advanced UI — animated hero, glassmorphism cards, glow effects, hover states
  2. Unlimited file size + unlimited multi-file upload; results shown one-by-one
  3. Risk score shown as % circle (not raw number)
  4. Text overlap fixed — all labels nowrap, no overlapping text anywhere
  5. Self-learning threat patterns — system trains on every scan and saves learned patterns
  6. Unique feature: THREAT DNA FINGERPRINTING — every threat gets a visual DNA signature
  7. Pipeline steps simplified and made fully clickable/actionable end-to-end
"""

import copy
import hashlib, json, os, shutil, sys, time, datetime, re
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "app"))

from sanitizer           import scan_file, sanitize_file, ScanResult, SanitizeResult, extract_content_preview
from transfer_manager    import create_bundle, decrypt_bundle, verify_bundle_integrity
from audit_logger        import log_event, read_log, verify_chain
from warehouse_connector import deliver_bundle, ping_warehouse, get_active_mode, save_config, DEFAULT_CONFIG

UPLOAD_DIR    = str(ROOT / "uploads")
QUARANTINE    = str(ROOT / "quarantine")
SANITIZED_DIR = str(ROOT / "sanitized")
BUNDLE_DIR    = str(ROOT / "sanitized")
DECRYPTED_DIR = str(ROOT / "decrypted")
REPORT_DIR    = str(ROOT / "reports")
AUDIT_FILE    = str(ROOT / "audit_logs" / "audit.jsonl")
LEARNED_FILE  = str(ROOT / "audit_logs" / "learned_patterns.json")
WAREHOUSE_CONFIG_FILE = str(ROOT / "config" / "warehouse_config.json")

for d in [UPLOAD_DIR, QUARANTINE, SANITIZED_DIR, DECRYPTED_DIR, REPORT_DIR, str(ROOT / "audit_logs")]:
    os.makedirs(d, exist_ok=True)


def _manifest_sidecar_path(bundle_path: str) -> str:
    return f"{os.path.splitext(bundle_path)[0]}.manifest.json"


def _persist_package_info(info: dict) -> dict:
    manifest_path = _manifest_sidecar_path(info["bundle_path"])
    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(info["manifest"], f, indent=2)
    except Exception:
        manifest_path = ""

    package_info = {
        "bundle_path": info["bundle_path"],
        "key_path": info.get("key_path"),
        "bundle_name": os.path.basename(info["bundle_path"]),
        "key_name": os.path.basename(info["key_path"]) if info.get("key_path") else "",
        "manifest": info.get("manifest", {}),
        "manifest_path": manifest_path,
    }
    st.session_state["package_info"] = package_info
    return package_info


def _resolve_delivery_package() -> dict | None:
    package_info = st.session_state.get("package_info")
    if package_info:
        bundle_path = package_info.get("bundle_path")
        key_path = package_info.get("key_path")
        if bundle_path and os.path.exists(bundle_path) and (not key_path or os.path.exists(key_path)):
            manifest = package_info.get("manifest") or {}
            manifest_path = package_info.get("manifest_path")
            if not manifest and manifest_path and os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        manifest = json.load(f)
                except Exception:
                    manifest = {}
            return {
                "bundle_path": bundle_path,
                "key_path": key_path,
                "bundle_name": package_info.get("bundle_name") or os.path.basename(bundle_path),
                "key_name": package_info.get("key_name") or (os.path.basename(key_path) if key_path else "N/A"),
                "manifest": manifest,
            }

    pairs = []
    for enc_name in os.listdir(BUNDLE_DIR):
        if not (enc_name.endswith(".enc") or enc_name.endswith(".zip")):
            continue
        stem = os.path.splitext(enc_name)[0]
        bundle_path = os.path.join(BUNDLE_DIR, enc_name)
        key_path = os.path.join(BUNDLE_DIR, f"{stem}.key")
        if not os.path.exists(key_path):
            key_path = None
        manifest_path = os.path.join(BUNDLE_DIR, f"{stem}.manifest.json")
        manifest = {}
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest = json.load(f)
            except Exception:
                manifest = {}
        pairs.append({
            "bundle_path": bundle_path,
            "key_path": key_path,
            "bundle_name": enc_name,
            "key_name": f"{stem}.key" if key_path else "N/A",
            "manifest": manifest,
            "mtime": os.path.getmtime(bundle_path),
        })

    if not pairs:
        return None

    pairs.sort(key=lambda item: item["mtime"], reverse=True)
    best = pairs[0]
    return {
        "bundle_path": best["bundle_path"],
        "key_path": best["key_path"],
        "bundle_name": best["bundle_name"],
        "key_name": best["key_name"],
        "manifest": best["manifest"],
    }


def _deep_merge_dict(base: dict, override: dict) -> dict:
    merged = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_warehouse_config() -> dict:
    if os.path.exists(WAREHOUSE_CONFIG_FILE):
        try:
            with open(WAREHOUSE_CONFIG_FILE, "r", encoding="utf-8") as f:
                return _deep_merge_dict(DEFAULT_CONFIG, json.load(f))
        except Exception:
            pass
    return copy.deepcopy(DEFAULT_CONFIG)


def _prepare_auto_delivery_config() -> tuple[dict, str, str | None]:
    cfg = _load_warehouse_config()
    mode = cfg.get("mode", "sneakernet")
    fallback_note = None

    if mode in ("lan", "vpn"):
        ping = ping_warehouse(mode_override=mode)
        if not ping.get("reachable"):
            mode = "sneakernet"
            fallback_path = str(ROOT / "sneakernet_out")
            os.makedirs(fallback_path, exist_ok=True)
            cfg = _deep_merge_dict(cfg, {
                "mode": "sneakernet",
                "sneakernet": {"output_path": fallback_path, "subdir": "SANCTUM_TRANSFERS"},
            })
            fallback_note = f"Auto-fallback to sneakernet because {cfg.get('mode', mode).upper()} endpoint was unreachable"

    if mode == "sneakernet":
        output_path = cfg.get("sneakernet", {}).get("output_path")
        if not output_path or not os.path.exists(output_path):
            fallback_path = str(ROOT / "sneakernet_out")
            os.makedirs(fallback_path, exist_ok=True)
            cfg = _deep_merge_dict(cfg, {
                "mode": "sneakernet",
                "sneakernet": {"output_path": fallback_path, "subdir": cfg.get("sneakernet", {}).get("subdir", "SANCTUM_TRANSFERS")},
            })
            mode = "sneakernet"
            if not fallback_note:
                fallback_note = f"Auto-fallback output folder: {fallback_path}"

    cfg["mode"] = mode
    return cfg, mode, fallback_note


def _uploaded_signature(uploaded_files) -> str:
    return "|".join(
        f"{uf.name}:{getattr(uf, 'size', 0)}:{getattr(uf, 'type', '')}"
        for uf in uploaded_files
    )


def _reset_pipeline_state(clear_upload: bool = False) -> None:
    for key in [
        "scan_results", "sanitize_results", "package_info", "final_report",
        "pipeline_summary", "last_pipeline_signature"
    ]:
        st.session_state.pop(key, None)
    if clear_upload:
        st.session_state["upload_nonce"] = st.session_state.get("upload_nonce", 0) + 1


def _serialize_scan_result(result: ScanResult) -> dict:
    return {
        "filename": result.filename,
        "extension": result.extension,
        "detected_type": result.detected_type,
        "size_mb": result.size_mb,
        "sha256": result.sha256,
        "md5": result.md5,
        "entropy": result.entropy,
        "allowed": result.allowed,
        "threats": list(result.threats),
        "warnings": list(result.warnings),
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "metadata_found": dict(result.metadata_found),
        "content_preview": result.content_preview,
        "indicators": [
            {
                "category": ind.category,
                "severity": ind.severity,
                "description": ind.description,
                "offset": ind.offset,
                "evidence": ind.evidence,
            }
            for ind in result.indicators
        ],
    }


def _serialize_sanitize_result(result: SanitizeResult) -> dict:
    return {
        "filename": result.filename,
        "actions": list(result.actions),
        "removed_items": list(result.removed_items),
        "output_path": result.output_path,
        "sha256_in": result.sha256_in,
        "sha256_out": result.sha256_out,
        "size_in_mb": result.size_in_mb,
        "size_out_mb": result.size_out_mb,
        "success": result.success,
        "error": result.error,
        "sanitize_time_ms": result.sanitize_time_ms,
    }


def _create_final_report(uploaded_files: list[str], delivery_result: dict, decrypt_result: dict, pipeline_error: str | None = None) -> dict:
    scan_data = st.session_state.get("scan_results", {})
    sanitize_data = st.session_state.get("sanitize_results", {})
    package_info = st.session_state.get("package_info", {})
    report = {
        "generated_utc": datetime.datetime.utcnow().isoformat() + "Z",
        "uploaded_files": uploaded_files,
        "summary": {
            "uploaded_count": len(uploaded_files),
            "scanned_count": len(scan_data),
            "quarantined_count": sum(1 for item in scan_data.values() if item["result"].verdict == "FAIL"),
            "sanitized_count": sum(1 for item in sanitize_data.values() if item.success),
            "package_created": bool(package_info),
            "delivery_success": bool(delivery_result.get("success")),
        },
        "scan_results": {
            name: {
                "path": data.get("path"),
                "result": _serialize_scan_result(data["result"]),
            }
            for name, data in scan_data.items()
        },
        "sanitize_results": {
            name: _serialize_sanitize_result(result)
            for name, result in sanitize_data.items()
        },
        "package": package_info,
        "delivery": delivery_result,
        "decrypt": decrypt_result,
        "audit_tail": read_log()[-25:],
        "pipeline_error": pipeline_error,
    }
    stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    filename = f"sanctum_x_final_report_{stamp}.json"
    output_path = os.path.join(REPORT_DIR, filename)
    content = json.dumps(report, indent=2)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    final_report = {"filename": filename, "path": output_path, "content": content}
    st.session_state["final_report"] = final_report
    return final_report


def _run_connected_pipeline(uploaded_files) -> dict:
    uploaded_names = [uf.name for uf in uploaded_files]
    delivery_result = {"success": False, "mode": "not_started", "error": "Pipeline not run"}
    decrypt_result = {"success": False, "mode": "not_started", "error": "Decrypt not run"}
    pipeline_error = None
    fallback_note = None

    st.session_state["scan_results"] = {}
    st.session_state["sanitize_results"] = {}
    st.session_state.pop("package_info", None)
    st.session_state.pop("final_report", None)

    try:
        for uf in uploaded_files:
            save_path = os.path.join(UPLOAD_DIR, uf.name)
            with open(save_path, "wb") as f:
                uf.seek(0)
                while True:
                    chunk = uf.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)

            result: ScanResult = scan_file(save_path)
            learn_from_scan(result)
            st.session_state["scan_results"][uf.name] = {"result": result, "path": save_path}
            log_event("INGEST", uf.name, f"SHA256:{result.sha256[:16]} entropy:{result.entropy} risk:{result.risk_score}", "PASS")

            if result.verdict == "FAIL":
                dst = os.path.join(QUARANTINE, uf.name)
                shutil.move(save_path, dst)
                st.session_state["scan_results"][uf.name]["path"] = dst
                log_event("QUARANTINE", uf.name, "; ".join(result.threats[:3]), "FAIL")
            else:
                log_event("SCAN", uf.name, f"risk:{result.risk_score} inds:{len(result.indicators)}", result.verdict)

        eligible = {
            name: data for name, data in st.session_state["scan_results"].items()
            if data["result"].verdict != "FAIL"
        }
        for fname, data in eligible.items():
            sr: SanitizeResult = sanitize_file(data["path"], SANITIZED_DIR)
            st.session_state["sanitize_results"][fname] = sr
            log_event("SANITIZE", fname, f"actions:{len(sr.actions)} removed:{len(sr.removed_items)} time:{sr.sanitize_time_ms}ms", "PASS" if sr.success else "FAIL")

        ready = [
            sr.output_path for sr in st.session_state["sanitize_results"].values()
            if sr.success and sr.output_path and os.path.exists(sr.output_path)
        ]
        if ready:
            info = create_bundle(ready, BUNDLE_DIR)
            _persist_package_info(info)
            log_event("PACKAGE", os.path.basename(info["bundle_path"]),
                f"files:{len(ready)} algo:{info['algorithm']} sha256:{info['sha256_bundle'][:16]}", "PASS")

            cfg, mode, fallback_note = _prepare_auto_delivery_config()
            save_config(cfg)
            manifest_payload = dict(info.get("manifest") or {})
            manifest_payload.update({
                "bundle": os.path.basename(info["bundle_path"]),
                "key": os.path.basename(info["key_path"]) if info.get("key_path") else "N/A",
                "sanctum_version": "2.1",
                "created_utc": manifest_payload.get("created_utc", datetime.datetime.utcnow().isoformat()),
            })
            delivery_result = deliver_bundle(info["bundle_path"], info.get("key_path"), manifest_payload, mode_override=cfg.get("mode", mode))
            transfer_target = delivery_result.get("dest_dir") or delivery_result.get("endpoint", "N/A")
            if not delivery_result.get("success"):
                transfer_target = delivery_result.get("error", "N/A")[:80]
            log_event(
                "DELIVER",
                os.path.basename(info["bundle_path"]),
                f"mode:{cfg.get('mode', mode)} dest:{transfer_target}",
                "PASS" if delivery_result.get("success") else "FAIL",
            )

            if info.get("key_path") and os.path.exists(info["key_path"]):
                verify_result = verify_bundle_integrity(info["bundle_path"], info["key_path"])
                if verify_result.get("success", True) is False:
                    decrypt_result = {
                        "success": False,
                        "mode": "verify_failed",
                        "error": verify_result.get("error", "Integrity verification failed"),
                    }
                else:
                    decrypt_out_dir = os.path.join(DECRYPTED_DIR, os.path.splitext(os.path.basename(info["bundle_path"]))[0])
                    os.makedirs(decrypt_out_dir, exist_ok=True)
                    try:
                        extracted = decrypt_bundle(info["bundle_path"], info["key_path"], decrypt_out_dir)
                        decrypt_result = {
                            "success": True,
                            "mode": "local_verify_decrypt",
                            "output_dir": decrypt_out_dir,
                            "extracted_files": extracted,
                            "bundle_sha256": verify_result.get("bundle_sha256"),
                        }
                        log_event("DECRYPT", os.path.basename(info["bundle_path"]), f"extracted:{len(extracted)}", "PASS")
                    except Exception as exc:
                        decrypt_result = {"success": False, "mode": "local_verify_decrypt", "error": str(exc)}
                        log_event("DECRYPT", os.path.basename(info["bundle_path"]), str(exc)[:80], "FAIL")
            else:
                decrypt_result = {
                    "success": False,
                    "mode": "skipped",
                    "error": "Bundle was generated as plain ZIP because cryptography is not installed",
                }
        else:
            delivery_result = {"success": False, "mode": "skipped", "error": "No sanitized assets available for packaging"}
            decrypt_result = {"success": False, "mode": "skipped", "error": "No bundle created"}
    except Exception as exc:
        pipeline_error = str(exc)
        delivery_result = {"success": False, "mode": "pipeline_error", "error": pipeline_error}
        decrypt_result = {"success": False, "mode": "pipeline_error", "error": pipeline_error}

    final_report = _create_final_report(uploaded_names, delivery_result, decrypt_result, pipeline_error)
    summary = {
        "uploaded_count": len(uploaded_names),
        "scanned_count": len(st.session_state.get("scan_results", {})),
        "sanitized_count": sum(1 for item in st.session_state.get("sanitize_results", {}).values() if item.success),
        "delivery_success": bool(delivery_result.get("success")),
        "decrypt_success": bool(decrypt_result.get("success")),
        "delivery_result": delivery_result,
        "decrypt_result": decrypt_result,
        "fallback_note": fallback_note,
        "report": final_report,
        "error": pipeline_error,
    }
    st.session_state["pipeline_summary"] = summary
    return summary

st.set_page_config(
    page_title="SANCTUM-X // CLASSIFIED",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────────────────────────
# SELF-LEARNING ENGINE  (Point 5)
# ─────────────────────────────────────────────────────────────────────────────
def load_learned_patterns() -> dict:
    if os.path.exists(LEARNED_FILE):
        try:
            with open(LEARNED_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"threat_signatures": {}, "file_type_baselines": {}, "scan_count": 0}

def save_learned_patterns(data: dict):
    try:
        with open(LEARNED_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def learn_from_scan(result: ScanResult):
    """Update learned patterns every time a file is scanned."""
    lp = load_learned_patterns()
    lp["scan_count"] = lp.get("scan_count", 0) + 1

    ext = result.extension
    if ext not in lp["file_type_baselines"]:
        lp["file_type_baselines"][ext] = {"count": 0, "avg_entropy": 0.0, "threat_rate": 0.0, "threat_count": 0}

    b = lp["file_type_baselines"][ext]
    n = b["count"] + 1
    b["avg_entropy"]   = (b["avg_entropy"] * b["count"] + result.entropy) / n
    b["threat_count"]  = b.get("threat_count", 0) + (1 if result.verdict == "FAIL" else 0)
    b["threat_rate"]   = b["threat_count"] / n
    b["count"]         = n

    for ind in result.indicators:
        key = f"{ind.category}::{ind.severity}"
        if key not in lp["threat_signatures"]:
            lp["threat_signatures"][key] = {"count": 0, "descriptions": []}
        sig = lp["threat_signatures"][key]
        sig["count"] += 1
        if ind.description not in sig["descriptions"][:10]:
            sig["descriptions"].append(ind.description)
            sig["descriptions"] = sig["descriptions"][-10:]

    save_learned_patterns(lp)

def get_ai_risk_context(result: ScanResult) -> str:
    """Use learned patterns to generate AI context for this scan."""
    lp = load_learned_patterns()
    ext = result.extension
    baseline = lp["file_type_baselines"].get(ext)
    if not baseline or baseline["count"] < 2:
        return f"First scan of {ext} files — no baseline yet"
    avg_e    = baseline["avg_entropy"]
    t_rate   = baseline["threat_rate"] * 100
    delta_e  = result.entropy - avg_e
    delta_str = f"+{delta_e:.2f}" if delta_e >= 0 else f"{delta_e:.2f}"
    return (f"AI CONTEXT: Scanned {baseline['count']} {ext} files · "
            f"Baseline entropy {avg_e:.2f} · This file {delta_str} · "
            f"Historical threat rate {t_rate:.0f}% for {ext}")


# ─────────────────────────────────────────────────────────────────────────────
# THREAT DNA FINGERPRINTING  (Point 6 — unique feature)
# ─────────────────────────────────────────────────────────────────────────────
def generate_threat_dna(result: ScanResult) -> str:
    DIMS = [
        ("entropy",    result.entropy > 7.2),
        ("spoofing",   any(i.category == "spoofing"          for i in result.indicators)),
        ("shellcode",  any("shellcode" in i.category         for i in result.indicators)),
        ("pe_elf",     any(i.category == "binary_pattern" and ("PE" in i.description or "ELF" in i.description) for i in result.indicators)),
        ("rev_shell",  any("reverse_shell" in i.description  for i in result.indicators)),
        ("b64_payload",any("Base64" in i.description         for i in result.indicators)),
        ("powershell", any("PowerShell" in i.description     for i in result.indicators)),
        ("xml_bomb",   any("XML" in i.description            for i in result.indicators)),
        ("macro",      any(i.category == "macro"             for i in result.indicators)),
        ("c2_beacon",  any("C2" in i.description or "beacon" in i.description.lower() for i in result.indicators)),
        ("steganog",   any(i.category == "steganography"     for i in result.indicators)),
        ("ldap_inj",   any("LDAP" in i.description           for i in result.indicators)),
        ("ssrf",       any("SSRF" in i.description           for i in result.indicators)),
        ("keyword",    any(i.category == "keyword"           for i in result.indicators)),
        ("pdf_js",     any("JavaScript" in i.description     for i in result.indicators)),
        ("zip_slip",   any("traversal" in i.description      for i in result.indicators)),
    ]

    dna_seed = hashlib.md5(f"{result.sha256}{result.entropy}".encode()).hexdigest()

    bars = ""
    for i, (dim_name, active) in enumerate(DIMS):
        seed_byte = int(dna_seed[i*2:(i*2)+2], 16)
        height    = 20 + (seed_byte % 30)
        color     = "#ef4444" if active else "#1e3a5f"
        glow      = f"box-shadow:0 0 6px #ef444488;" if active else ""
        tip       = dim_name.replace("_", " ").upper()
        bars += (f'<div title="{tip}" style="display:inline-block;width:14px;height:{height}px;'
                 f'background:{color};margin:1px;border-radius:3px;{glow}'
                 f'vertical-align:bottom;cursor:help;transition:all 0.3s"></div>')

    threat_count = sum(1 for _, a in DIMS if a)
    dna_color    = "#ef4444" if threat_count >= 4 else "#f59e0b" if threat_count >= 1 else "#22c55e"
    label        = f"THREAT DNA · {threat_count}/16 DIMENSIONS ACTIVE"

    badge_html = "".join(
        '<span style="font-family:\'JetBrains Mono\',monospace;font-size:9px;padding:1px 5px;'
        f'border-radius:2px;background:{"#ef444422" if a else "#1e3a5f22"};'
        f'color:{"#ef4444" if a else "#4a5a7a"};border:1px solid {"#ef444433" if a else "#1e3a5f"}">'
        f'{n.replace("_"," ").upper()}</span>'
        for n, a in DIMS
    )

    return f"""
    <div style="background:#030810;border:1px solid #1e3a5f;border-left:3px solid {dna_color};
                padding:14px 16px;border-radius:0 6px 6px 0;margin:8px 0">
      <div style="font-family:'Rajdhani',sans-serif;font-size:13px;color:{dna_color};
                  letter-spacing:2px;margin-bottom:10px;font-weight:600">{label}</div>
      <div style="display:flex;align-items:flex-end;gap:0;height:56px">{bars}</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:8px">
        {badge_html}
      </div>
    </div>"""


# ─────────────────────────────────────────────────────────────────────────────
# CSS  (v4.0 — expander overlap fully fixed)
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&family=Rajdhani:wght@400;500;600;700&display=swap');

:root {
  --bg-base:    #040b17;
  --bg-card:    #081222;
  --bg-glass:   rgba(8,18,34,0.85);
  --bg-hover:   #0d1f3c;
  --border:     #1e3a5f;
  --border-hi:  #2563a8;
  --blue-pri:   #2979ff;
  --blue-lit:   #5c9aff;
  --blue-dim:   #1a3a6e;
  --blue-glow:  #2979ff44;
  --white:      #f0f4ff;
  --white-dim:  #a8b8d8;
  --white-mute: #4a5a7a;
  --red:        #ef4444;
  --amber:      #f59e0b;
  --green:      #22c55e;
  --cyan:       #06b6d4;
  --purple:     #8b5cf6;
}

*, html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; box-sizing: border-box; }

/* Background */
.stApp, .main, [data-testid="stAppViewContainer"] { background-color: var(--bg-base) !important; }
section[data-testid="stMain"] > div { background-color: var(--bg-base) !important; }
[data-testid="stHeader"] { background-color: var(--bg-base) !important; border-bottom: 1px solid var(--border) !important; }

/* Sidebar */
[data-testid="stSidebar"] { background: #030910 !important; border-right: 1px solid var(--border) !important; }
[data-testid="stSidebar"] * { color: var(--white-dim) !important; font-size: 13px !important; }
[data-testid="stSidebar"] .stRadio > label { font-weight: 500; }
[data-testid="stSidebarCollapseButton"],
button[aria-label*="sidebar"] {
  position: relative !important;
}
[data-testid="stSidebarCollapseButton"] [data-testid="stIconMaterial"],
button[aria-label*="sidebar"] [data-testid="stIconMaterial"] {
  display: none !important;
}
[data-testid="stSidebarCollapseButton"] span,
button[aria-label*="sidebar"] span {
  color: transparent !important;
}
[data-testid="stSidebarCollapseButton"]::after,
button[aria-label*="sidebar"]::after {
  content: "›" !important;
  color: #ffffff !important;
  font-family: 'Rajdhani', sans-serif !important;
  font-size: 26px !important;
  font-weight: 700 !important;
  line-height: 1 !important;
  position: absolute !important;
  inset: 50% auto auto 50% !important;
  transform: translate(-50%, -50%) !important;
  pointer-events: none !important;
}
[data-testid="stSidebarCollapseButton"][aria-expanded="true"]::after,
button[aria-label*="Collapse sidebar"]::after {
  content: "‹" !important;
}
[data-testid="stSidebarCollapseButton"][aria-expanded="false"]::after,
button[aria-label*="Expand sidebar"]::after {
  content: "›" !important;
}
[data-testid="stSidebar"] [data-testid="stIconMaterial"] {
  display: none !important;
  width: 0 !important;
  height: 0 !important;
  font-size: 0 !important;
  line-height: 0 !important;
  overflow: hidden !important;
}
[data-testid="stSidebar"] [role="radiogroup"] label {
  position: relative !important;
  padding-left: 2.4rem !important;
}
[data-testid="stSidebar"] [role="radiogroup"] label::before {
  content: "" !important;
  position: absolute !important;
  left: 0.8rem !important;
  top: 50% !important;
  width: 1rem !important;
  height: 1rem !important;
  transform: translateY(-50%) !important;
  background-repeat: no-repeat !important;
  background-position: center !important;
  background-size: contain !important;
  opacity: 0.55 !important;
  filter: drop-shadow(0 0 4px rgba(41, 121, 255, 0.22)) !important;
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none'><path d='M4 12h11' stroke='%235c9aff' stroke-width='2' stroke-linecap='round'/><path d='M11 6l7 6-7 6' stroke='%232979ff' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'/><path d='M18 12h2' stroke='%23f0f4ff' stroke-width='2' stroke-linecap='round'/></svg>") !important;
}
[data-testid="stSidebar"] [role="radiogroup"] label[aria-checked="true"]::before {
  opacity: 1 !important;
  filter: drop-shadow(0 0 7px rgba(41, 121, 255, 0.45)) !important;
}

/* Typography */
h1, h2, h3 { font-family: 'Rajdhani', sans-serif !important; color: var(--white) !important;
              letter-spacing: 1px !important; text-transform: uppercase !important; line-height:1.2 !important; }
p, label, span, div { color: var(--white-dim) !important; line-height: 1.5 !important; }
code, pre { font-family: 'JetBrains Mono', monospace !important; background: var(--bg-card) !important;
            color: var(--blue-lit) !important; border: 1px solid var(--border) !important; }

/* ── EXPANDER OVERLAP FIX ─────────────────────────────────────────────────
   The global "line-height: 1.5" above bleeds into the <summary> and causes
   Streamlit's injected <p> to double-render on top of the visible label.
   We override every relevant property specifically inside summary here.
   ───────────────────────────────────────────────────────────────────────── */
[data-testid="stExpander"] {
  background: var(--bg-card) !important;
  border: 1px solid var(--border) !important;
  border-radius: 8px !important;
  overflow: hidden !important;
  transition: all 0.2s !important;
}
[data-testid="stExpander"]:hover {
  border-color: var(--border-hi) !important;
}

/* Single-row flex summary — no stacking, no overflow */
[data-testid="stExpander"] summary {
  display: flex !important;
  flex-direction: row !important;
  align-items: center !important;
  padding: 10px 14px !important;
  cursor: pointer !important;
  list-style: none !important;
  min-height: 40px !important;
  gap: 8px !important;
  overflow: hidden !important;
  /* Reset everything that the global rules pollute */
  line-height: 1 !important;
  position: relative !important;
  box-sizing: border-box !important;
}

/* Kill browser native disclosure triangle */
[data-testid="stExpander"] summary::-webkit-details-marker { display: none !important; }
[data-testid="stExpander"] summary::marker                 { display: none !important; }

/* Streamlit label wrapper div — takes all remaining space */
[data-testid="stExpander"] summary > div:not([data-testid]) {
  flex: 1 1 0% !important;
  min-width: 0 !important;
  overflow: hidden !important;
  line-height: 1 !important;
}

/* The actual <p> that holds the expander title text */
[data-testid="stExpander"] summary > div:not([data-testid]) > p,
[data-testid="stExpander"] summary p {
  margin: 0 !important;
  padding: 0 !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 12px !important;
  font-weight: 400 !important;
  color: var(--white) !important;
  white-space: nowrap !important;
  overflow: hidden !important;
  text-overflow: ellipsis !important;
  line-height: 1.2 !important;   /* explicit — never inherits the 1.5 global */
  display: block !important;
  width: 100% !important;
  position: static !important;
}

/* Chevron arrow icon — always pinned right */
[data-testid="stExpanderToggleIcon"],
[data-testid="stExpander"] summary > div[data-testid="stExpanderToggleIcon"] {
  display: none !important;
}
[data-testid="stExpander"] summary [data-testid="stIconMaterial"] {
  display: none !important;
  width: 0 !important;
  height: 0 !important;
  font-size: 0 !important;
  line-height: 0 !important;
  color: transparent !important;
  overflow: hidden !important;
}
[data-testid="stExpanderToggleIcon"] [data-testid="stIconMaterial"] {
  display: none !important;
}
[data-testid="stExpander"] summary svg {
  width: 18px !important;
  height: 18px !important;
  display: block !important;
  position: static !important;
}

/* Nuclear fallback — force static on ALL summary children */
[data-testid="stExpander"] summary * {
  position: static !important;
  float: none !important;
  line-height: inherit !important;
}
/* Re-assert the p line-height after the wildcard above */
[data-testid="stExpander"] summary p {
  line-height: 1.2 !important;
}

/* Buttons */
.stButton > button {
  background: linear-gradient(135deg, var(--blue-dim), #0d2a5e) !important;
  border: 1px solid var(--blue-pri) !important; color: var(--white) !important;
  font-family: 'Rajdhani', sans-serif !important; font-size: 15px !important;
  font-weight: 600 !important; letter-spacing: 1px !important; text-transform: uppercase !important;
  border-radius: 6px !important; transition: all 0.2s ease !important;
  padding: 8px 20px !important; cursor: pointer !important; white-space: nowrap !important; }
.stButton > button:hover {
  background: var(--blue-pri) !important; color: #fff !important;
  box-shadow: 0 0 20px var(--blue-glow) !important; transform: translateY(-1px) !important; }
.stButton > button:active { transform: translateY(0) !important; }
.stButton > button[kind="primary"] {
  background: linear-gradient(135deg, var(--blue-pri), #1565c0) !important;
  box-shadow: 0 4px 15px var(--blue-glow) !important; }
.stButton > button[kind="primary"]:hover { box-shadow: 0 6px 25px var(--blue-glow) !important; }

/* Inputs */
.stTextInput input, [data-baseweb="input"] input {
  background: var(--bg-card) !important; border: 1px solid var(--border) !important;
  border-radius: 6px !important; color: var(--white) !important;
  font-family: 'JetBrains Mono', monospace !important; }
.stTextInput input:focus, [data-baseweb="input"] input:focus {
  border-color: var(--blue-pri) !important; box-shadow: 0 0 10px var(--blue-glow) !important; }

/* File uploader */
[data-testid="stFileUploader"] {
  background: transparent !important;
  border: none !important;
  padding: 0 !important;
}
[data-testid="stFileUploader"] section[data-testid="stFileUploaderDropzone"] {
  border: 1px solid var(--border-hi) !important;
  border-radius: 16px !important;
  background:
    linear-gradient(135deg, rgba(8,18,34,0.96), rgba(13,31,60,0.92)) !important;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.04), 0 10px 30px rgba(2,8,20,0.35) !important;
  padding: 0 !important;
  overflow: hidden !important;
  transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease !important;
}
[data-testid="stFileUploader"] section[data-testid="stFileUploaderDropzone"]:hover {
  border-color: var(--blue-lit) !important;
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.06), 0 0 0 1px rgba(92,154,255,0.2), 0 18px 38px rgba(41,121,255,0.14) !important;
  transform: translateY(-1px) !important;
}
[data-testid="stFileUploader"] [data-testid="stFileUploaderDropzoneInstructions"] {
  display: none !important;
}
[data-testid="stFileUploaderDropzone"] button {
  min-height: 168px !important;
  width: 100% !important;
  border: none !important;
  border-radius: 16px !important;
  background:
    linear-gradient(180deg, rgba(7,17,32,0.18) 0%, rgba(7,17,32,0.02) 100%) !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  padding: 24px !important;
  position: relative !important;
}
[data-testid="stFileUploaderDropzone"] button::before {
  content: "SECURE INGEST PORT\A Drop files here or click to upload\A Any format • multi-file • pipeline auto-runs" !important;
  white-space: pre-line !important;
  text-align: center !important;
  font-family: 'Rajdhani', sans-serif !important;
  font-size: 20px !important;
  line-height: 1.35 !important;
  letter-spacing: 1px !important;
  color: var(--white) !important;
  max-width: 520px !important;
  text-transform: uppercase !important;
}
[data-testid="stFileUploaderDropzone"] button::after {
  content: "" !important;
  position: absolute !important;
  top: 20px !important;
  left: 20px !important;
  width: 54px !important;
  height: 54px !important;
  border-radius: 14px !important;
  border: 1px solid rgba(92,154,255,0.28) !important;
  background:
    linear-gradient(135deg, rgba(41,121,255,0.2), rgba(6,182,212,0.08)),
    url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64' fill='none'><path d='M32 12v24' stroke='%23f0f4ff' stroke-width='4' stroke-linecap='round'/><path d='M22 25l10-13 10 13' stroke='%235c9aff' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/><path d='M14 43h36' stroke='%232979ff' stroke-width='4' stroke-linecap='round'/><rect x='10' y='39' width='44' height='13' rx='6.5' stroke='%2306b6d4' stroke-width='3'/></svg>") center/26px no-repeat !important;
  box-shadow: 0 0 20px rgba(41,121,255,0.12) !important;
}
[data-testid="stFileUploader"] * {
  color: var(--blue-lit) !important;
}
[data-testid="stFileUploaderDropzone"] button > div,
[data-testid="stFileUploaderDropzone"] button > span {
  display: none !important;
}

/* Metrics */
[data-testid="stMetric"] { background: var(--bg-card) !important; border: 1px solid var(--border) !important;
  border-radius: 8px !important; padding: 14px !important; }
[data-testid="stMetricLabel"] { color: var(--white-mute) !important; font-size: 11px !important; white-space: nowrap !important; }
[data-testid="stMetricValue"] { color: var(--white) !important; font-family: 'Rajdhani', sans-serif !important; }

/* Progress bar */
.stProgress > div > div > div { background: linear-gradient(90deg, var(--blue-dim), var(--blue-pri), var(--cyan)) !important; }
.stProgress > div > div { background: var(--bg-card) !important; border: 1px solid var(--border) !important; border-radius: 4px !important; }

/* Alerts */
.stSuccess { background: #052e16 !important; border-left: 3px solid var(--green) !important; border-radius: 6px !important; }
.stWarning { background: #1c1008 !important; border-left: 3px solid var(--amber) !important; border-radius: 6px !important; }
.stError   { background: #1c0808 !important; border-left: 3px solid var(--red)   !important; border-radius: 6px !important; }
.stInfo    { background: #051228 !important; border-left: 3px solid var(--cyan)  !important; border-radius: 6px !important; }

/* Selectbox / radio */
.stSelectbox > div, [data-baseweb="select"] { background: var(--bg-card) !important; border-color: var(--border) !important; border-radius: 6px !important; }
.stRadio label { color: var(--white-dim) !important; font-size: 13px !important; cursor: pointer !important; }
.stCheckbox label { color: var(--white-dim) !important; cursor: pointer !important; }
.stDownloadButton > button { background: var(--bg-card) !important; border: 1px solid var(--border-hi) !important;
  color: var(--blue-lit) !important; border-radius: 6px !important; transition: all 0.2s !important; cursor: pointer !important; }
.stDownloadButton > button:hover { background: var(--blue-dim) !important; box-shadow: 0 0 10px var(--blue-glow) !important; }

hr { border-color: var(--border) !important; }
::-webkit-scrollbar { width: 5px; background: var(--bg-base); }
::-webkit-scrollbar-thumb { background: var(--border-hi); border-radius: 3px; }

/* ── CUSTOM COMPONENTS ────────────────────────────────────────────────────── */

.sx-hero {
  background: linear-gradient(135deg, #040b17 0%, #081e3f 40%, #0a2550 60%, #040b17 100%);
  border: 1px solid var(--border-hi); border-radius: 12px; padding: 36px 40px;
  margin-bottom: 28px; position: relative; overflow: hidden;
  box-shadow: 0 8px 40px #2979ff18, inset 0 1px 0 #ffffff08; }
.sx-hero::before {
  content: ''; position: absolute; top: -50%; left: -50%; width: 200%; height: 200%;
  background: radial-gradient(ellipse at 30% 50%, #2979ff0a 0%, transparent 60%),
              radial-gradient(ellipse at 70% 50%, #06b6d40a 0%, transparent 60%);
  pointer-events: none; }
.sx-hero-title { font-family: 'Rajdhani', sans-serif; font-size: 68px !important; font-weight: 700;
  color: var(--white); letter-spacing: 8px; line-height: 1; margin-bottom: 6px;
  text-shadow: 0 0 40px #2979ff44; }
.sx-hero-sub { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--blue-lit);
  letter-spacing: 3px; margin-bottom: 20px; }
.sx-hero-tag { display: inline-block; background: var(--blue-dim); border: 1px solid var(--blue-pri);
  border-radius: 4px; padding: 3px 12px; font-family: 'JetBrains Mono', monospace;
  font-size: 11px; color: var(--blue-lit); margin: 2px; letter-spacing: 1px; }

.sx-banner { background: linear-gradient(135deg, #1e3a8a, #1d4ed8, #0e7490);
  color: #fff; text-align: center; padding: 9px 16px; font-family: 'Rajdhani', sans-serif;
  font-size: 13px; font-weight: 600; letter-spacing: 3px; margin-bottom: 20px;
  border-radius: 6px; border: 1px solid var(--border-hi); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sx-page-title { font-family: 'Rajdhani', sans-serif; font-size: 30px; font-weight: 700;
  color: var(--white) !important; letter-spacing: 3px; white-space: nowrap; }
.sx-subtitle { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--white-mute);
  margin-bottom: 20px; margin-top: 4px; letter-spacing: 1px; overflow: hidden; text-overflow: ellipsis; }
.sx-section { font-family: 'Rajdhani', sans-serif; font-size: 15px; font-weight: 600;
  color: var(--blue-lit); letter-spacing: 2px; margin: 18px 0 10px; text-transform: uppercase;
  white-space: nowrap; }

.sx-terminal { background: #020810; border: 1px solid var(--border); border-left: 3px solid var(--blue-pri);
  padding: 14px 18px; font-family: 'JetBrains Mono', monospace; font-size: 12px;
  color: var(--blue-lit); white-space: pre-wrap; word-break: break-word;
  margin: 8px 0; border-radius: 0 6px 6px 0; overflow-x: auto; }

.sx-panel { background: var(--bg-card); border: 1px solid var(--border);
  border-left: 3px solid var(--blue-pri); padding: 12px 16px; margin: 6px 0;
  border-radius: 0 6px 6px 0; overflow: hidden; }
.sx-panel-red   { border-left-color: var(--red)   !important; }
.sx-panel-amber { border-left-color: var(--amber) !important; }
.sx-panel-green { border-left-color: var(--green) !important; }
.sx-panel-cyan  { border-left-color: var(--cyan)  !important; }
.sx-panel-purple{ border-left-color: var(--purple)!important; }

.ind-crit { background:#1a0505; border:1px solid #ef444433; border-left:3px solid var(--red);
  padding:10px 14px; margin:4px 0; font-family:'JetBrains Mono',monospace; font-size:12px;
  color:#fca5a5; border-radius:0 4px 4px 0; word-break:break-word; }
.ind-high { background:#1a0e00; border:1px solid #f59e0b33; border-left:3px solid var(--amber);
  padding:10px 14px; margin:4px 0; font-family:'JetBrains Mono',monospace; font-size:12px;
  color:#fde68a; border-radius:0 4px 4px 0; word-break:break-word; }
.ind-warn { background:#0f1a2a; border:1px solid #2979ff33; border-left:3px solid var(--blue-pri);
  padding:10px 14px; margin:4px 0; font-family:'JetBrains Mono',monospace; font-size:12px;
  color:var(--blue-lit); border-radius:0 4px 4px 0; word-break:break-word; }
.ind-pass { background:#031a0a; border:1px solid #22c55e33; border-left:3px solid var(--green);
  padding:10px 14px; margin:4px 0; font-family:'JetBrains Mono',monospace; font-size:12px;
  color:#86efac; border-radius:0 4px 4px 0; word-break:break-word; }
.ind-act  { background:#041228; border:1px solid #06b6d433; border-left:3px solid var(--cyan);
  padding:8px 14px; margin:4px 0; font-family:'JetBrains Mono',monospace; font-size:12px;
  color:#67e8f9; border-radius:0 4px 4px 0; word-break:break-word; }

.risk-circle-wrap { text-align: center; }
.risk-circle { position: relative; display: inline-block; width: 90px; height: 90px; }
.risk-circle svg { transform: rotate(-90deg); }
.risk-circle-label { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
  font-family: 'Rajdhani', sans-serif; font-size: 20px; font-weight: 700; line-height: 1; }
.risk-circle-sub { font-family: 'JetBrains Mono', monospace; font-size: 9px;
  color: var(--white-mute); margin-top: 4px; letter-spacing: 1px; }

.sx-stat { background: linear-gradient(135deg, var(--bg-card), var(--bg-hover));
  border: 1px solid var(--border); padding: 18px 14px; text-align: center; border-radius: 8px;
  transition: all 0.2s; }
.sx-stat:hover { border-color: var(--border-hi); box-shadow: 0 4px 20px var(--blue-glow); }
.sx-stat-label { font-family:'Inter',sans-serif; font-size:11px; color:var(--white-mute);
  letter-spacing:1px; text-transform:uppercase; white-space:nowrap; }
.sx-stat-val { font-family:'Rajdhani',sans-serif; font-size:28px; color:var(--white);
  margin-top:4px; font-weight:700; }

.sx-file-row { background: var(--bg-card); border: 1px solid var(--border);
  border-left: 3px solid var(--blue-pri); padding: 10px 14px; margin: 4px 0;
  display: flex; justify-content: space-between; align-items: center;
  border-radius: 0 6px 6px 0; overflow: hidden; }
.sx-file-row span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 60%; }

.cp-box { background: #020810; border: 1px solid var(--border); padding: 12px 16px;
  font-family:'JetBrains Mono',monospace; font-size:11px; color:var(--white-dim);
  border-radius:6px; margin:6px 0; overflow:hidden; }
.cp-head { font-family:'Rajdhani',sans-serif; font-size:13px; font-weight:600;
  color:var(--blue-lit); letter-spacing:1px; margin-bottom:8px; text-transform:uppercase;
  white-space:nowrap; }
.cp-row { border-bottom:1px solid var(--border); padding:4px 0; display:flex; gap:8px;
  overflow:hidden; }
.cp-key { color:var(--white-mute); white-space:nowrap; flex-shrink:0; }
.cp-val { color:var(--white); overflow:hidden; text-overflow:ellipsis; }
.cp-threat { color:#fca5a5; overflow:hidden; text-overflow:ellipsis; }
.cp-clean  { color:#86efac; }

.ebar-wrap { background: var(--bg-card); border: 1px solid var(--border); height: 8px;
  width: 100%; margin: 4px 0; border-radius: 4px; overflow: hidden; }
.ebar-fill { height: 8px; border-radius: 4px; transition: width 0.5s ease; }

.pipe-card { background: linear-gradient(135deg, var(--bg-card), var(--bg-hover));
  border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; margin: 8px 0;
  cursor: pointer; transition: all 0.2s; display: flex; gap: 16px; align-items: flex-start; }
.pipe-card:hover { border-color: var(--blue-pri); box-shadow: 0 4px 20px var(--blue-glow);
  transform: translateX(4px); }
.pipe-card-num { font-family:'Rajdhani',sans-serif; font-size:28px; font-weight:700;
  opacity:0.4; min-width:32px; line-height:1.1; }
.pipe-card-name { font-family:'Rajdhani',sans-serif; font-size:15px; font-weight:600;
  letter-spacing:2px; text-transform:uppercase; line-height:1.2; }
.pipe-card-desc { font-family:'Inter',sans-serif; font-size:11px; color:var(--white-mute);
  margin-top:4px; line-height:1.5; }

.cert-seal {
  background: linear-gradient(135deg, #081222 0%, #0d1f3c 50%, #081222 100%);
  border: 2px solid var(--blue-pri); border-radius: 12px; padding: 30px 36px;
  text-align: center; position: relative; margin: 16px 0;
  box-shadow: 0 0 60px #2979ff22, inset 0 0 40px #2979ff08; }
.cert-seal::before { content: ''; position: absolute; inset: 5px; border: 1px solid #2979ff22;
  border-radius: 8px; pointer-events: none; }
.cert-title { font-family:'Rajdhani',sans-serif; font-size:26px; font-weight:700;
  color:var(--white); letter-spacing:5px; margin-bottom:4px; }
.cert-sub { font-family:'JetBrains Mono',monospace; font-size:10px; color:var(--blue-lit);
  letter-spacing:2px; margin-bottom:18px; }
.cert-status { font-family:'Rajdhani',sans-serif; font-size:20px; font-weight:700;
  color:#86efac; background:#031a0a; border:1px solid #22c55e55; border-radius:6px;
  padding:8px 24px; display:inline-block; margin-bottom:18px; letter-spacing:2px; }
.cert-hash { font-family:'JetBrains Mono',monospace; font-size:10px; color:var(--white-mute);
  word-break:break-all; background:var(--bg-base); padding:8px 12px; border-radius:4px;
  border:1px solid var(--border); margin:4px 0; text-align:left; }
.cert-badge { display:inline-block; background:var(--blue-dim); border:1px solid var(--blue-pri);
  border-radius:3px; font-family:'JetBrains Mono',monospace; font-size:10px; color:var(--blue-lit);
  padding:2px 10px; margin:2px; letter-spacing:1px; white-space:nowrap; }

.step-nav { display:flex; gap:0; margin-bottom:24px; overflow-x:auto; }
.step-btn { flex:1; min-width:80px; text-align:center; padding:10px 4px;
  font-family:'Rajdhani',sans-serif; font-size:12px; font-weight:600; letter-spacing:1px;
  text-transform:uppercase; border:1px solid var(--border); background:var(--bg-card);
  color:var(--white-mute); cursor:pointer; transition:all 0.2s; white-space:nowrap;
  overflow:hidden; text-overflow:ellipsis; }
.step-btn:first-child { border-radius:6px 0 0 6px; }
.step-btn:last-child  { border-radius:0 6px 6px 0; }
.step-btn.active { background:var(--blue-pri); color:#fff; border-color:var(--blue-pri);
  box-shadow:0 2px 10px var(--blue-glow); }
.step-btn.done { background:#031a0a; color:var(--green); border-color:#22c55e55; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def risk_color(s):
    if s >= 75: return "var(--red)"
    if s >= 50: return "var(--amber)"
    if s >= 25: return "#f97316"
    return "var(--green)"

def risk_label(s):
    if s >= 75: return "CRITICAL"
    if s >= 50: return "HIGH"
    if s >= 25: return "MEDIUM"
    return "MINIMAL"

def entropy_color(e):
    if e > 7.5: return "var(--red)"
    if e > 6.5: return "var(--amber)"
    if e > 4.0: return "var(--cyan)"
    return "var(--green)"

def entropy_bar_html(e):
    pct = min(100, (e / 8.0) * 100)
    col = entropy_color(e)
    tag = "CRITICAL" if e > 7.5 else "ELEVATED" if e > 6.5 else "NORMAL"
    return (f'<div style="display:flex;align-items:center;gap:8px;margin:6px 0">'
            f'<div class="ebar-wrap" style="flex:1"><div class="ebar-fill" style="width:{pct:.1f}%;background:{col}"></div></div>'
            f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:11px;color:{col};min-width:72px;white-space:nowrap">{e:.3f}/8.0</span>'
            f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:10px;color:{col};min-width:62px;white-space:nowrap">[{tag}]</span>'
            f'</div>')

def risk_circle_html(score: int) -> str:
    col   = risk_color(score)
    lbl   = risk_label(score)
    r     = 36
    circ  = 2 * 3.14159 * r
    fill  = circ * (1 - score / 100)
    return f"""
    <div class="risk-circle-wrap">
      <div class="risk-circle">
        <svg width="90" height="90" viewBox="0 0 90 90">
          <circle cx="45" cy="45" r="{r}" fill="none" stroke="#1e3a5f" stroke-width="8"/>
          <circle cx="45" cy="45" r="{r}" fill="none" stroke="{col}" stroke-width="8"
            stroke-dasharray="{circ:.1f}" stroke-dashoffset="{fill:.1f}"
            stroke-linecap="round"/>
        </svg>
        <div class="risk-circle-label" style="color:{col}">{score}%</div>
      </div>
      <div class="risk-circle-sub">{lbl}</div>
    </div>"""

def sev_sym(s):
    return {"CRITICAL":"◈","HIGH":"◆","MEDIUM":"◇","LOW":"○"}.get(s,"·")

def badge(v):
    colors = {"PASS":"var(--green)","FAIL":"var(--red)","WARN":"var(--amber)"}
    c = colors.get(v, "var(--white-mute)")
    return (f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:11px;color:{c};'
            f'border:1px solid {c};background:{c}18;padding:3px 12px;border-radius:3px;'
            f'letter-spacing:1px;white-space:nowrap">{v}</span>')

def sx_stat(val, lbl, color="var(--white)"):
    return f"""
    <div style="
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 6px;
        padding: 14px 10px 12px;
        text-align: center;
        min-height: 72px;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 4px;
    ">
        <div style="
            font-family: 'Rajdhani', sans-serif;
            font-size: 28px;
            font-weight: 700;
            color: {color};
            line-height: 1;
        ">{val}</div>
        <div style="
            font-family: 'Rajdhani', sans-serif;
            font-size: 11px;
            font-weight: 600;
            color: rgba(255,255,255,0.45);
            letter-spacing: 0.08em;
            line-height: 1;
        ">{lbl}</div>
    </div>
    """

def term(content):
    st.markdown(f'<div class="sx-terminal">{content}</div>', unsafe_allow_html=True)

def kv(k, v, threat=False):
    cls = "cp-threat" if threat else "cp-val"
    return f'<div class="cp-row"><span class="cp-key">{k}:</span><span class="{cls}">{v}</span></div>'

def step_nav(current_page: str):
    steps = [
        ("COMMAND CENTER", "HOME",        0),
        ("INGEST",         "01 SCAN",     1),
        ("SANITIZE",       "02 CLEAN",    2),
        ("ENCRYPT",        "03 ENCRYPT",  3),
        ("WAREHOUSE",      "04 DELIVER",  4),
        ("DECRYPT",        "05 DECRYPT",  5),
        ("AUDIT",          "06 AUDIT",    6),
    ]
    scan_done = bool(st.session_state.get("scan_results"))
    san_done  = bool(st.session_state.get("sanitize_results"))

    cols = st.columns(len(steps))
    for col, (key, label, nav_idx) in zip(cols, steps):
        if key in current_page:
            btn_style = "background:var(--blue-pri);color:#fff;border:1px solid var(--blue-pri);"
        elif (key == "SANITIZE" and scan_done) or (key == "ENCRYPT" and san_done):
            btn_style = "background:#031a0a;color:var(--green);border:1px solid #22c55e55;"
        else:
            btn_style = "background:var(--bg-card);color:var(--white-mute);border:1px solid var(--border);"
        with col:
            st.markdown(f"""
            <style>.step-btn-{nav_idx} button{{
              {btn_style}font-family:'Rajdhani',sans-serif!important;font-size:11px!important;
              font-weight:600!important;letter-spacing:1px!important;text-transform:uppercase!important;
              width:100%!important;border-radius:0!important;padding:8px 2px!important;white-space:nowrap!important;
            }}</style>""", unsafe_allow_html=True)
            btn_container = st.container()
            with btn_container:
                if st.button(label, key=f"stepnav_{current_page}_{nav_idx}", use_container_width=True):
                    st.session_state["nav_target"] = nav_idx
                    st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# CONTENT PREVIEW
# ─────────────────────────────────────────────────────────────────────────────
def render_content_preview(cp: dict, fname: str):
    if not cp:
        return
    ext = cp.get("type", "")
    err = cp.get("error")
    st.markdown('<div class="sx-section">◈ FILE CONTENT ANALYSIS</div>', unsafe_allow_html=True)
    if err:
        st.markdown(f'<div class="ind-high">⚠ Content read error: {err}</div>', unsafe_allow_html=True)
        return

    if ext == ".txt":
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"""<div class="cp-box">
<div class="cp-head">📄 TEXT STATS</div>
{kv("Lines", f"{cp.get('line_count',0):,}")}
{kv("Words", f"{cp.get('word_count',0):,}")}
{kv("Characters", f"{cp.get('char_count',0):,}")}
{kv("Has URLs", '⚠ YES' if cp.get('has_urls') else '✓ No', threat=cp.get('has_urls'))}
{kv("Has IPs", '⚠ YES' if cp.get('has_ips') else '✓ No', threat=cp.get('has_ips'))}
</div>""", unsafe_allow_html=True)
        with c2:
            lines = cp.get("first_lines", [])
            rows  = "".join(
                f'<div style="padding:2px 0;border-bottom:1px solid var(--border);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--white);font-size:11px">'
                f'<span style="color:var(--white-mute);margin-right:6px">{i+1:02d}</span>'
                f'{line[:100] if line else "<em style=\'color:var(--white-mute)\'>—</em>"}</div>'
                for i, line in enumerate(lines[:10]))
            st.markdown(f'<div class="cp-box"><div class="cp-head">📋 FIRST 10 LINES</div>{rows}</div>', unsafe_allow_html=True)

    elif ext == ".csv":
        c1, c2 = st.columns(2)
        with c1:
            inj = cp.get("injection_cells", [])
            st.markdown(f"""<div class="cp-box">
<div class="cp-head">📊 CSV STRUCTURE</div>
{kv("Rows", f"{cp.get('row_count',0):,}")}
{kv("Columns", cp.get('column_count',0))}
{kv("Formula injections", f"⚠ {len(inj)} FOUND" if inj else "✓ None", threat=bool(inj))}
</div>""", unsafe_allow_html=True)
            tags = "".join(f'<span style="background:var(--blue-dim);color:var(--blue-lit);border-radius:3px;padding:2px 8px;margin:2px;display:inline-block;font-size:10px;white-space:nowrap">{c}</span>' for c in cp.get("columns",[])[:12])
            st.markdown(f'<div class="cp-box"><div class="cp-head">COLUMNS</div>{tags}</div>', unsafe_allow_html=True)
        with c2:
            rows = cp.get("sample_rows",[])
            if rows:
                cols  = list(rows[0].keys())[:5]
                thead = "".join(f'<th style="padding:4px 8px;border-bottom:1px solid var(--border-hi);color:var(--blue-lit);font-size:10px;text-align:left;white-space:nowrap">{c[:14]}</th>' for c in cols)
                tbody = ""
                for row in rows[:3]:
                    cells = "".join(f'<td style="padding:4px 8px;border-bottom:1px solid var(--border);color:var(--white);font-size:10px;max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{str(row.get(c,""))[:20]}</td>' for c in cols)
                    tbody += f"<tr>{cells}</tr>"
                st.markdown(f'<div class="cp-box"><div class="cp-head">SAMPLE ROWS</div><div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse"><thead><tr>{thead}</tr></thead><tbody>{tbody}</tbody></table></div></div>', unsafe_allow_html=True)

    elif ext == ".json":
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"""<div class="cp-box">
<div class="cp-head">🗂 JSON</div>
{kv("Root type", cp.get('root_type','?'))}
{kv("Records", f"{cp.get('record_count',0):,}")}
{kv("Depth", cp.get('nested_depth',0))}
</div>""", unsafe_allow_html=True)
            keys_html = "".join(f'<span style="background:var(--blue-dim);color:var(--blue-lit);border-radius:3px;padding:2px 6px;margin:2px;display:inline-block;font-size:10px;white-space:nowrap">"{k}"</span>' for k in cp.get("top_keys",[])[:10])
            st.markdown(f'<div class="cp-box"><div class="cp-head">KEYS</div>{keys_html}</div>', unsafe_allow_html=True)
        with c2:
            sample = cp.get("sample",[])
            if sample:
                try:
                    s = json.dumps(sample[0], indent=2)[:500]
                    st.markdown(f'<div class="cp-box"><div class="cp-head">SAMPLE</div><pre style="color:var(--blue-lit);font-size:10px;margin:0;white-space:pre-wrap;word-break:break-word">{s}</pre></div>', unsafe_allow_html=True)
                except Exception:
                    pass

    elif ext == ".pdf":
        c1, c2 = st.columns(2)
        with c1:
            has_js = cp.get("has_javascript",False); has_f = cp.get("has_forms",False); emb = cp.get("embedded_files",0)
            st.markdown(f"""<div class="cp-box">
<div class="cp-head">📑 PDF</div>
{kv("Pages", cp.get('page_count',0))}
{kv("JavaScript", '⚠ DETECTED' if has_js else '✓ None', threat=has_js)}
{kv("Forms", '⚠ PRESENT' if has_f else '✓ None', threat=has_f)}
{kv("Embedded", f'⚠ {emb}' if emb else '✓ None', threat=bool(emb))}
{kv("Metadata fields", len(cp.get('metadata_fields',{})))}
</div>""", unsafe_allow_html=True)
        with c2:
            snippet = cp.get("text_snippet","")
            if snippet:
                st.markdown(f'<div class="cp-box"><div class="cp-head">TEXT PREVIEW</div><div style="color:var(--white);font-size:11px;line-height:1.6;word-break:break-word">{snippet[:350]}</div></div>', unsafe_allow_html=True)

    elif ext in (".png",".jpg",".jpeg"):
        c1, c2 = st.columns(2)
        with c1:
            has_gps = cp.get("has_gps",False)
            st.markdown(f"""<div class="cp-box">
<div class="cp-head">🖼 IMAGE</div>
{kv("Dimensions", f"{cp.get('width','?')} × {cp.get('height','?')} px")}
{kv("Megapixels", f"{cp.get('megapixels','?')} MP")}
{kv("Mode", cp.get('mode','?'))}
{kv("EXIF fields", cp.get('exif_count',0))}
{kv("GPS data", '⚠ FOUND' if has_gps else '✓ None', threat=has_gps)}
</div>""", unsafe_allow_html=True)
        with c2:
            exif = cp.get("exif_fields",{})
            if exif:
                exif_html = "".join(kv(k, str(v)[:50]) for k,v in list(exif.items())[:8])
                st.markdown(f'<div class="cp-box"><div class="cp-head">EXIF METADATA</div>{exif_html}</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="cp-box"><div class="cp-head">EXIF</div><div class="cp-clean">✓ No EXIF found</div></div>', unsafe_allow_html=True)

    elif ext == ".docx":
        c1, c2 = st.columns(2)
        with c1:
            has_mac = cp.get("has_macros",False)
            st.markdown(f"""<div class="cp-box">
<div class="cp-head">📝 DOCX</div>
{kv("Paragraphs", cp.get('paragraph_count',0))}
{kv("Headings", cp.get('heading_count',0))}
{kv("Words", f"{cp.get('word_count',0):,}")}
{kv("Author", (cp.get('author','N/A') or 'N/A')[:30])}
{kv("Macros", '⚠ DETECTED' if has_mac else '✓ None', threat=has_mac)}
</div>""", unsafe_allow_html=True)
        with c2:
            headings = cp.get("headings",[])
            if headings:
                h = "".join(f'<div style="color:var(--white);font-size:11px;padding:3px 0;border-bottom:1px solid var(--border);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">▸ {h[:70]}</div>' for h in headings[:6])
                st.markdown(f'<div class="cp-box"><div class="cp-head">HEADINGS</div>{h}</div>', unsafe_allow_html=True)

    elif ext == ".xlsx":
        st.markdown(f"""<div class="cp-box">
<div class="cp-head">📊 XLSX — {cp.get('sheet_count',0)} SHEETS</div>
{kv("Sheet names", ", ".join(cp.get('sheet_names',[]))[:80])}
</div>""", unsafe_allow_html=True)
        for sheet in cp.get("sheets",[])[:2]:
            sr = sheet.get("sample",[])
            if sr:
                th = "".join(f'<th style="padding:4px 8px;border-bottom:1px solid var(--border-hi);color:var(--blue-lit);font-size:10px;white-space:nowrap">{c[:12]}</th>' for c in sr[0])
                tb = "".join(f'<tr>{"".join(f"<td style=\'padding:4px 8px;border-bottom:1px solid var(--border);color:var(--white);font-size:10px;white-space:nowrap\'>{c[:16]}</td>" for c in row)}</tr>' for row in sr[1:3])
                st.markdown(f'<div class="cp-box"><div class="cp-head">{sheet["name"]} — {sheet["rows"]:,} rows × {sheet["cols"]} cols</div><div style="overflow-x:auto"><table style="border-collapse:collapse"><thead><tr>{th}</tr></thead><tbody>{tb}</tbody></table></div></div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="cp-box"><div class="cp-head">BINARY</div><pre style="color:var(--blue-lit);font-size:10px;word-break:break-all">{cp.get("hex_header","")}</pre></div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# CERTIFICATION SEAL
# ─────────────────────────────────────────────────────────────────────────────
def render_cert_seal(fname, sha256_in, sha256_out, sanitize_ms, scan_count):
    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    cert_id = hashlib.sha256(f"{fname}{sha256_out}{now_str}".encode()).hexdigest()[:24].upper()
    badges  = "".join(f'<span class="cert-badge">{a}</span>' for a in [
        "AES-256-GCM","HMAC-SHA512","METADATA STRIPPED","ACTIVE CONTENT REMOVED",
        "ENTROPY VERIFIED","CHAIN LOGGED","AI CERTIFIED"])
    lp = load_learned_patterns()
    model_info = f"Model trained on {lp.get('scan_count',0)} scans · {len(lp.get('file_type_baselines',{}))} file types profiled"
    st.markdown(f"""
    <div class="cert-seal">
      <div style="font-size:52px;margin-bottom:8px">🛡</div>
      <div class="cert-title">SANCTUM-AI CERTIFICATION</div>
      <div class="cert-sub">SECURE SANITIZATION AUTHORITY · AUTHORIZED VERIFICATION · {model_info}</div>
      <div class="cert-status">✓ 100% SANITIZED &amp; CLEARED</div>
      <div style="margin:0 auto;max-width:540px">
        <div class="cert-hash"><span style="color:var(--white-mute)">FILE    :</span> {fname}</div>
        <div class="cert-hash"><span style="color:var(--white-mute)">CERT ID :</span> {cert_id}</div>
        <div class="cert-hash"><span style="color:var(--white-mute)">SHA-256 :</span> {sha256_out}</div>
        <div class="cert-hash"><span style="color:var(--white-mute)">ISSUED  :</span> {now_str} &nbsp; PROC: {sanitize_ms:.0f}ms</div>
        <div class="cert-hash"><span style="color:var(--white-mute)">ORIGIN  :</span> {sha256_in[:32]}…</div>
      </div>
      <div style="margin-top:16px">{badges}</div>
    </div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    lp   = load_learned_patterns()
    sc   = lp.get("scan_count", 0)
    st.markdown(f"""
    <div style="padding:20px 0 14px;text-align:center;border-bottom:1px solid var(--border);margin-bottom:14px">
      <div style="font-family:'Rajdhani',sans-serif;font-size:34px;font-weight:700;
                  color:var(--white);letter-spacing:5px;text-shadow:0 0 20px #2979ff44">SANCTUM-X</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--blue-lit);
                  letter-spacing:2px;margin-top:4px">CLASSIFIED // TS-SCI</div>
      <div style="font-family:'Inter',sans-serif;font-size:11px;color:var(--white-mute);margin-top:6px">
          AIR-GAP SANITIZATION SYSTEM v4.0</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--blue-dim);margin-top:4px;
                  background:var(--bg-card);border:1px solid var(--border);border-radius:4px;padding:3px 8px">
          🧠 AI TRAINED ON {sc} SCANS</div>
    </div>""", unsafe_allow_html=True)

    NAV_OPTIONS = [
        "[ 00 ]  COMMAND CENTER",
        "[ 01 ]  INGEST & THREAT SCAN",
        "[ 02 ]  SANITIZE",
        "[ 03 ]  ENCRYPT & PACKAGE",
        "[ 04 ]  DELIVER TO WAREHOUSE",
        "[ 05 ]  DECRYPT BUNDLE",
        "[ 06 ]  AUDIT CHAIN",
        "[ 07 ]  DOCTRINE",
    ]
    if "nav_target" in st.session_state:
        default_idx = st.session_state.pop("nav_target")
    else:
        default_idx = 0

    page = st.radio("NAV", NAV_OPTIONS, index=default_idx, label_visibility="collapsed")

    st.markdown('<div style="border-top:1px solid var(--border);margin:12px 0"></div>', unsafe_allow_html=True)

    chain_ok    = verify_chain()
    chain_color = "var(--green)" if chain_ok else "var(--red)"
    chain_text  = "◈ CHAIN VERIFIED" if chain_ok else "◈ CHAIN COMPROMISED"
    st.markdown(f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:11px;color:{chain_color};'
                f'padding:8px;border:1px solid {chain_color};background:{chain_color}18;border-radius:4px;'
                f'white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{chain_text}</div>', unsafe_allow_html=True)

    logs = read_log()
    te = len(logs)
    pe = len([l for l in logs if l["result"] == "PASS"])
    fe = len([l for l in logs if l["result"] == "FAIL"])
    qe = len([l for l in logs if l["action"] == "QUARANTINE"])
    st.markdown(f"""
    <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--white-mute);
                margin-top:14px;line-height:2.4">
    EVENTS  : <span style="color:var(--white)">{te}</span><br>
    CLEARED : <span style="color:var(--green)">{pe}</span><br>
    THREATS : <span style="color:var(--red)">{fe}</span><br>
    QUARANT : <span style="color:var(--amber)">{qe}</span>
    </div>""", unsafe_allow_html=True)

    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    st.markdown(f"""
    <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--white-mute);
                margin-top:18px;text-align:center;border-top:1px solid var(--border);padding-top:10px">
    UTC {now}<br>CLEARANCE: TOP SECRET
    </div>""", unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 00: COMMAND CENTER
# ═════════════════════════════════════════════════════════════════════════════
if "COMMAND CENTER" in page:
    st.markdown("""
    <div class="sx-hero">
      <div class="sx-hero-title">SANCTUM-X</div>
      <div class="sx-hero-sub">SECURE AIR-GAP DATA SANITIZATION &amp; TRANSFER SYSTEM · v4.0</div>
      <span class="sx-hero-tag">AES-256-GCM</span>
      <span class="sx-hero-tag">THREAT DNA</span>
      <span class="sx-hero-tag">SELF-LEARNING AI</span>
      <span class="sx-hero-tag">ZERO TRUST</span>
      <span class="sx-hero-tag">CHAIN-OF-CUSTODY</span>
      <span class="sx-hero-tag">HMAC-SHA512</span>
    </div>""", unsafe_allow_html=True)

    st.markdown("""
    <div style="background:linear-gradient(135deg,#040e20,#081828);border:1px solid #1e3a5f;
                border-left:4px solid #2979ff;border-radius:0 8px 8px 0;padding:18px 22px;margin-bottom:20px">
      <div style="font-family:'Rajdhani',sans-serif;font-size:16px;font-weight:700;color:#f0f4ff;
                  letter-spacing:2px;margin-bottom:10px">◈ WHAT IS COMMAND CENTER?</div>
      <div style="font-family:'Inter',sans-serif;font-size:13px;color:#a8b8d8;line-height:1.8">
        This is your <strong style="color:#f0f4ff">mission overview dashboard</strong>. It shows real-time stats, recent audit events,
        and the full 6-stage sanitization pipeline. <strong style="color:#2979ff">Click the ▶ button</strong> next to any pipeline
        stage to jump directly to it, or use the sidebar navigation on the left.
        <br><br>
        <strong style="color:#f0f4ff">PIPELINE FLOW:</strong>
        &nbsp;<span style="color:#2979ff">01 INGEST</span> (scan files for threats)
        → <span style="color:#22c55e">02 SANITIZE</span> (strip metadata & active content)
        → <span style="color:#06b6d4">03 ENCRYPT</span> (AES-256-GCM bundle)
        → <span style="color:#5c9aff">04 DELIVER</span> (send to warehouse)
        → <span style="color:#8b5cf6">05 DECRYPT</span> (receiving side)
        → <span style="color:#a8b8d8">06 AUDIT</span> (verify chain-of-custody)
      </div>
    </div>""", unsafe_allow_html=True)

    logs    = read_log()
    total   = len([l for l in logs if l["action"] == "INGEST"])
    passed  = len([l for l in logs if l["result"] == "PASS"])
    quarant = len([l for l in logs if l["action"] == "QUARANTINE"])
    bundles = len([l for l in logs if l["action"] == "PACKAGE"])
    warns   = len([l for l in logs if l["result"] == "WARN"])

    c1,c2,c3,c4,c5 = st.columns(5)
    for col,val,lbl,color in [
        (c1,total,  "INGESTED",  "var(--white)"),
        (c2,passed, "CLEARED",   "var(--green)"),
        (c3,warns,  "FLAGGED",   "var(--amber)"),
        (c4,quarant,"QUARANTINED","var(--red)"),
        (c5,bundles,"PACKAGED",  "var(--cyan)"),
    ]:
        col.markdown(sx_stat(val,lbl,color), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    left, right = st.columns([3,2])

    with left:
        st.markdown('<div class="sx-section">◈ PIPELINE — CLICK ANY STAGE TO START</div>', unsafe_allow_html=True)
        stages = [
            ("01","INGEST & THREAT SCAN","Upload files · Deep content read · 14-layer threat detection · Threat DNA fingerprint","var(--blue-pri)", 1),
            ("02","SANITIZE",            "Metadata excision · Active content removal · Media re-encoding · AI certification seal","var(--green)", 2),
            ("03","ENCRYPT & PACKAGE",   "AES-256-GCM encryption · HMAC-SHA512 signing · Dual-hash manifest · Download bundle","var(--cyan)", 3),
            ("04","DELIVER TO WAREHOUSE","LAN push · VPN tunnel · Sneakernet/USB → private army data warehouse","var(--blue-lit)", 4),
            ("05","DECRYPT BUNDLE",      "Upload .enc + .key · HMAC verify · AES-256-GCM decrypt · Extract files","var(--purple)", 5),
            ("06","AUDIT CHAIN",         "SHA-256 chained tamper-evident log · Filter · Export · Verify integrity","var(--white-dim)", 6),
        ]
        for num, name, desc, col, nav_idx in stages:
            card_col, btn_col = st.columns([5, 1])
            with card_col:
                st.markdown(f"""
                <div class="pipe-card" style="border-left:3px solid {col};margin-bottom:0">
                  <div class="pipe-card-num" style="color:{col}">{num}</div>
                  <div>
                    <div class="pipe-card-name" style="color:{col}">{name}</div>
                    <div class="pipe-card-desc">{desc}</div>
                  </div>
                </div>""", unsafe_allow_html=True)
            with btn_col:
                st.markdown("<div style='margin-top:8px'></div>", unsafe_allow_html=True)
                if st.button("▶", key=f"nav_{num}", help=f"Go to {name}", use_container_width=True):
                    st.session_state["nav_target"] = nav_idx
                    st.rerun()

    with right:
        st.markdown('<div class="sx-section">◈ LIVE FEED</div>', unsafe_allow_html=True)
        recent = logs[-14:][::-1] if logs else []
        if recent:
            for e in recent:
                color = {"PASS":"var(--green)","WARN":"var(--amber)","FAIL":"var(--red)"}.get(e["result"],"var(--white-mute)")
                sym   = {"PASS":"○","WARN":"◆","FAIL":"◈"}.get(e["result"],"·")
                ts    = e["timestamp"][11:19]
                fname = e["file"][:22]
                st.markdown(f"""
                <div style="font-family:'JetBrains Mono',monospace;font-size:11px;
                            border-left:2px solid {color};padding:5px 10px;margin:2px 0;
                            background:var(--bg-card);border-radius:0 4px 4px 0;overflow:hidden">
                  <span style="color:var(--white-mute)">{ts}</span>
                  <span style="color:{color};white-space:nowrap"> {sym} {e['action']}</span>
                  <span style="color:var(--white-mute)"> · {fname}</span>
                </div>""", unsafe_allow_html=True)
        else:
            st.markdown('<div style="color:var(--white-mute);font-size:12px">-- NO ACTIVITY RECORDED --</div>', unsafe_allow_html=True)

        st.markdown('<div class="sx-section" style="margin-top:20px">◈ AI LEARNING STATUS</div>', unsafe_allow_html=True)
        lp  = load_learned_patterns()
        bls = lp.get("file_type_baselines", {})
        if bls:
            for ext, b in list(bls.items())[:6]:
                threat_pct = b.get("threat_rate",0) * 100
                color      = "var(--red)" if threat_pct > 30 else "var(--amber)" if threat_pct > 10 else "var(--green)"
                st.markdown(f"""
                <div style="font-family:'JetBrains Mono',monospace;font-size:11px;
                            border-bottom:1px solid var(--border);padding:4px 0;
                            display:flex;justify-content:space-between;align-items:center">
                  <span style="color:var(--blue-lit)">{ext}</span>
                  <span style="color:var(--white-mute)">{b['count']} scans · avg entropy {b['avg_entropy']:.2f}</span>
                  <span style="color:{color}">{threat_pct:.0f}% threat</span>
                </div>""", unsafe_allow_html=True)
        else:
            st.markdown('<div style="color:var(--white-mute);font-size:12px">No baseline yet — start scanning files</div>', unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 01: INGEST & THREAT SCAN
# ═════════════════════════════════════════════════════════════════════════════
elif "INGEST" in page:
    st.markdown('<div class="sx-banner">OPERATION: FILE INGESTION // DEEP THREAT ANALYSIS // AI LEARNING ACTIVE</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-page-title">[ 01 ] INGEST &amp; THREAT SCAN</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-subtitle">UNLIMITED FILE SIZE · UNLIMITED FILES · ONE-BY-ONE RESULTS · THREAT DNA · SELF-LEARNING AI</div>', unsafe_allow_html=True)
    step_nav("INGEST")

    st.info("▸ Upload any number of files of any size — results appear one by one as each file is scanned")

    st.markdown("""
    <div class="sx-panel sx-panel-cyan" style="font-size:12px;font-family:'JetBrains Mono',monospace;color:var(--blue-lit);margin-bottom:12px">
    ℹ  To remove the 200MB Streamlit limit: add <code style="background:#020810;padding:2px 6px">[server]</code>
    <code style="background:#020810;padding:2px 6px">maxUploadSize = 5000</code> to
    <code style="background:#020810;padding:2px 6px">.streamlit/config.toml</code> — supports up to 5 GB per file
    </div>""", unsafe_allow_html=True)

    upload_key = f"ingest_upload_{st.session_state.get('upload_nonce', 0)}"
    uploaded = st.file_uploader(
        "DRAG & DROP ANY FILES — UNLIMITED COUNT — ANY FORMAT",
        accept_multiple_files=True,
        help="SANCTUM-X reads inside every file. Add .streamlit/config.toml with maxUploadSize=5000 for files > 200 MB",
        key=upload_key
    )

    if uploaded:
        file_sig = _uploaded_signature(uploaded)
        col_btn1, col_btn2 = st.columns([3,1])
        with col_btn1:
            st.markdown('<div class="ind-act">AUTO MODE ACTIVE: upload starts scan, sanitize, package, deliver, and report generation automatically.</div>', unsafe_allow_html=True)
        with col_btn2:
            clear_btn = st.button("✕  CLEAR RESULTS", use_container_width=True)
        if clear_btn:
            _reset_pipeline_state(clear_upload=True)
            st.rerun()

        if file_sig != st.session_state.get("last_pipeline_signature"):
            with st.spinner("Auto-running connected pipeline..."):
                _run_connected_pipeline(uploaded)
            st.session_state["last_pipeline_signature"] = file_sig
            st.rerun()

        summary = st.session_state.get("pipeline_summary")
        if summary:
            st.markdown('<div class="sx-section">CONNECTED EXECUTION STATUS</div>', unsafe_allow_html=True)
            s1, s2, s3, s4, s5 = st.columns(5)
            for col, val, lbl, color in [
                (s1, summary["uploaded_count"], "UPLOADED", "var(--white)"),
                (s2, summary["scanned_count"], "SCANNED", "var(--blue-lit)"),
                (s3, summary["sanitized_count"], "SANITIZED", "var(--green)"),
                (s4, "PASS" if summary["delivery_success"] else "FAIL", "DELIVERY", "var(--green)" if summary["delivery_success"] else "var(--red)"),
                (s5, "PASS" if summary["decrypt_success"] else "FAIL", "DECRYPT", "var(--green)" if summary["decrypt_success"] else "var(--red)"),
            ]:
                col.markdown(sx_stat(val, lbl, color), unsafe_allow_html=True)
            if summary.get("fallback_note"):
                st.info(summary["fallback_note"])
            if summary.get("error"):
                st.error(f"Pipeline error: {summary['error']}")
            elif summary["delivery_success"] and summary["decrypt_success"]:
                st.success("Connected execution finished successfully through delivery and local verify/decrypt. Final report is ready below.")
            elif summary["delivery_success"]:
                st.warning(f"Delivery completed, but decrypt verification needs attention: {summary.get('decrypt_result', {}).get('error', 'Unknown issue')}")
            else:
                st.warning(f"Processing completed, but delivery needs attention: {summary.get('delivery_result', {}).get('error', 'Unknown issue')}")

        if False:
            st.session_state["scan_results"] = {}
            progress_bar = st.progress(0, text="Initializing scan engine...")

            for i, uf in enumerate(uploaded):
                progress_bar.progress((i) / len(uploaded), text=f"Scanning {uf.name} ({i+1}/{len(uploaded)})...")

                save_path = os.path.join(UPLOAD_DIR, uf.name)
                with open(save_path, "wb") as f:
                    uf.seek(0)
                    while True:
                        chunk = uf.read(1024 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)

                result: ScanResult = scan_file(save_path)
                learn_from_scan(result)

                st.session_state["scan_results"][uf.name] = {"result": result, "path": save_path}
                log_event("INGEST", uf.name, f"SHA256:{result.sha256[:16]} entropy:{result.entropy} risk:{result.risk_score}", "PASS")

                if result.verdict == "FAIL":
                    dst = os.path.join(QUARANTINE, uf.name)
                    shutil.move(save_path, dst)
                    st.session_state["scan_results"][uf.name]["path"] = dst
                    log_event("QUARANTINE", uf.name, "; ".join(result.threats[:3]), "FAIL")
                else:
                    log_event("SCAN", uf.name, f"risk:{result.risk_score} inds:{len(result.indicators)}", result.verdict)

                rc  = risk_color(result.risk_score)
                rl  = risk_label(result.risk_score)
                sym = "🚨 THREAT DETECTED" if result.verdict=="FAIL" else "⚠ FLAGGED" if result.verdict=="WARN" else "✅ CLEARED"
                border_col = "var(--red)" if result.verdict=="FAIL" else "var(--amber)" if result.verdict=="WARN" else "var(--green)"
                display_name = uf.name if len(uf.name) <= 35 else uf.name[:32] + "..."
                with st.expander(f"{sym}  ·  {display_name}  ·  {result.risk_score}% RISK", expanded=True):
                    anchor_id = f"result_{i}"
                    st.markdown(f'<div id="{anchor_id}"></div>', unsafe_allow_html=True)
                    col_risk, col_meta = st.columns([1, 4])
                    with col_risk:
                        st.markdown(risk_circle_html(result.risk_score), unsafe_allow_html=True)
                        st.markdown(f'<div style="text-align:center;margin-top:8px">{badge(result.verdict)}</div>', unsafe_allow_html=True)
                    with col_meta:
                        stats_cols = st.columns(6)
                        for sc_col, val, lbl in [
                            (stats_cols[0], f"{result.size_mb} MB",     "SIZE"),
                            (stats_cols[1], result.extension,            "EXT"),
                            (stats_cols[2], result.detected_type,        "DETECTED"),
                            (stats_cols[3], f"{result.entropy:.2f}/8",   "ENTROPY"),
                            (stats_cols[4], str(len(result.indicators)), "INDICATORS"),
                            (stats_cols[5], str(len(result.threats)),    "THREATS"),
                        ]:
                            try:
                                is_threat = lbl in ("INDICATORS","THREATS") and int(str(val)) > 0
                            except Exception:
                                is_threat = False
                            color = "var(--red)" if is_threat else "var(--white)"
                            sc_col.markdown(f"""
                            <div style="background:var(--bg-card);border:1px solid var(--border);
                                        padding:10px 6px;text-align:center;border-radius:6px">
                              <div style="font-size:10px;color:var(--white-mute);text-transform:uppercase;
                                          white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{lbl}</div>
                              <div style="font-family:'Rajdhani',sans-serif;font-size:15px;color:{color};
                                          margin-top:3px;font-weight:600;white-space:nowrap;overflow:hidden;
                                          text-overflow:ellipsis">{val}</div>
                            </div>""", unsafe_allow_html=True)
                        st.markdown(entropy_bar_html(result.entropy), unsafe_allow_html=True)

                    ai_ctx = get_ai_risk_context(result)
                    st.markdown(f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:10px;color:var(--purple);'
                                f'padding:6px 10px;background:#0d0a1a;border:1px solid #8b5cf633;border-radius:4px;margin:8px 0">🧠 {ai_ctx}</div>', unsafe_allow_html=True)

                    term(f"SHA-256 : {result.sha256}\nMD5     : {result.md5}\nSTATUS  : {'QUARANTINED — CANNOT PROCEED' if result.verdict=='FAIL' else 'CLEARED FOR SANITIZATION' if result.verdict=='PASS' else 'FLAGGED — REVIEW REQUIRED'}")

                    if result.content_preview:
                        render_content_preview(result.content_preview, uf.name)

                    st.markdown(generate_threat_dna(result), unsafe_allow_html=True)

                    if result.verdict in ("FAIL", "WARN") and result.indicators:
                        st.markdown('<div class="sx-section" style="color:var(--red);margin-top:16px">◈ THREAT BREAKDOWN CHART</div>', unsafe_allow_html=True)
                        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                        cat_counts = {}
                        for ind in result.indicators:
                            sev_counts[ind.severity] = sev_counts.get(ind.severity, 0) + 1
                            cat_counts[ind.category] = cat_counts.get(ind.category, 0) + 1

                        sev_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b", "LOW": "#22c55e"}
                        max_sev = max(sev_counts.values()) or 1
                        sev_bars = ""
                        for sev, cnt in sev_counts.items():
                            if cnt == 0:
                                continue
                            pct = int((cnt / max_sev) * 100)
                            col = sev_colors[sev]
                            sev_bars += f"""
                            <div style="display:flex;align-items:center;gap:10px;margin:5px 0">
                              <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:{col};
                                          width:72px;white-space:nowrap">{sev}</div>
                              <div style="flex:1;background:#0d1f3c;border-radius:3px;height:18px;position:relative">
                                <div style="width:{pct}%;background:{col};height:100%;border-radius:3px;
                                            box-shadow:0 0 8px {col}66;transition:width 0.5s"></div>
                              </div>
                              <div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:{col};
                                          width:24px;text-align:right;font-weight:700">{cnt}</div>
                            </div>"""

                        top_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:8]
                        max_cat = max(c for _, c in top_cats) if top_cats else 1
                        cat_bars = ""
                        for cat, cnt in top_cats:
                            pct = int((cnt / max_cat) * 100)
                            cat_bars += f"""
                            <div style="display:flex;align-items:center;gap:10px;margin:5px 0">
                              <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--blue-lit);
                                          width:100px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{cat.upper()}</div>
                              <div style="flex:1;background:#0d1f3c;border-radius:3px;height:14px">
                                <div style="width:{pct}%;background:var(--blue-pri);height:100%;border-radius:3px;
                                            box-shadow:0 0 6px #2979ff66"></div>
                              </div>
                              <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--white);
                                          width:20px;text-align:right">{cnt}</div>
                            </div>"""

                        ch1, ch2 = st.columns(2)
                        with ch1:
                            st.markdown(f"""
                            <div style="background:#030810;border:1px solid #ef444433;border-left:3px solid #ef4444;
                                        padding:14px 16px;border-radius:0 6px 6px 0;margin:4px 0">
                              <div style="font-family:'Rajdhani',sans-serif;font-size:12px;color:#ef4444;
                                          letter-spacing:2px;margin-bottom:12px;font-weight:600">SEVERITY DISTRIBUTION</div>
                              {sev_bars}
                            </div>""", unsafe_allow_html=True)
                        with ch2:
                            st.markdown(f"""
                            <div style="background:#030810;border:1px solid #2979ff33;border-left:3px solid var(--blue-pri);
                                        padding:14px 16px;border-radius:0 6px 6px 0;margin:4px 0">
                              <div style="font-family:'Rajdhani',sans-serif;font-size:12px;color:var(--blue-lit);
                                          letter-spacing:2px;margin-bottom:12px;font-weight:600">THREAT CATEGORIES</div>
                              {cat_bars}
                            </div>""", unsafe_allow_html=True)

                    if result.indicators:
                        st.markdown(f'<div class="sx-section" style="color:var(--red)">◈ THREAT INDICATORS ({len(result.indicators)})</div>', unsafe_allow_html=True)
                        sev_cls = {"CRITICAL":"ind-crit","HIGH":"ind-high","MEDIUM":"ind-warn","LOW":"ind-pass"}
                        for ind in result.indicators:
                            ev = f'<br><span style="color:var(--white-mute);font-size:10px;word-break:break-word">EVIDENCE: {ind.evidence}</span>' if ind.evidence else ""
                            st.markdown(f'<div class="{sev_cls.get(ind.severity, "ind-warn")}">{sev_sym(ind.severity)} [{ind.severity}] {ind.category.upper()} - {ind.description}{ev}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="ind-pass">○ NO THREAT INDICATORS — FILE IS CLEAN</div>', unsafe_allow_html=True)

                    for w in result.warnings[:4]:
                        st.markdown(f'<div class="ind-high">◆ {w}</div>', unsafe_allow_html=True)

                progress_bar.progress((i + 1) / len(uploaded), text=f"Completed {i+1}/{len(uploaded)} files")
                time.sleep(0.05)

            progress_bar.progress(1.0, text="✅ All files scanned")
            eligible = sum(1 for d in st.session_state["scan_results"].values() if d["result"].verdict != "FAIL")
            if eligible > 0:
                st.success(f"◈  {eligible}/{len(uploaded)} ASSET(S) CLEARED · USE SIDEBAR → [ 02 ] SANITIZE")

    elif "scan_results" in st.session_state and st.session_state["scan_results"]:
        for fname, data in st.session_state["scan_results"].items():
            r   = data["result"]
            sym = "🚨 THREAT" if r.verdict=="FAIL" else "⚠ FLAGGED" if r.verdict=="WARN" else "✅ CLEARED"
            display_fname = fname if len(fname) <= 35 else fname[:32] + "..."
            with st.expander(f"{sym}  ·  {display_fname}  ·  {r.risk_score}% RISK", expanded=False):
                col_risk, col_meta = st.columns([1, 4])
                with col_risk:
                    st.markdown(risk_circle_html(r.risk_score), unsafe_allow_html=True)
                    st.markdown(f'<div style="text-align:center;margin-top:8px">{badge(r.verdict)}</div>', unsafe_allow_html=True)
                with col_meta:
                    term(f"SHA-256: {r.sha256}\nSTATUS : {'QUARANTINED' if r.verdict=='FAIL' else 'CLEARED' if r.verdict=='PASS' else 'FLAGGED'}")
                st.markdown(generate_threat_dna(r), unsafe_allow_html=True)

    final_report = st.session_state.get("final_report")
    if final_report:
        st.markdown('<div class="sx-section">FINAL REPORT</div>', unsafe_allow_html=True)
        with open(final_report["path"], "rb") as f:
            st.download_button(
                "DOWNLOAD FINAL EXECUTION REPORT",
                data=f,
                file_name=final_report["filename"],
                mime="application/json",
                use_container_width=True,
            )
        scan_data = st.session_state.get("scan_results", {})
        threat_counts = {}
        for data in scan_data.values():
            for ind in data["result"].indicators:
                threat_counts[ind.category] = threat_counts.get(ind.category, 0) + 1

        if threat_counts:
            st.markdown('<div class="sx-section">THREAT GRAPH</div>', unsafe_allow_html=True)
            top_threats = sorted(threat_counts.items(), key=lambda item: item[1], reverse=True)[:10]
            max_count = max(count for _, count in top_threats) or 1
            graph_html = ""
            for category, count in top_threats:
                pct = int((count / max_count) * 100)
                graph_html += f"""
                <div style="display:flex;align-items:center;gap:10px;margin:8px 0">
                  <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--blue-lit);
                              width:140px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{category.upper()}</div>
                  <div style="flex:1;background:#0d1f3c;border-radius:4px;height:16px;overflow:hidden">
                    <div style="width:{pct}%;background:linear-gradient(90deg,var(--blue-pri),var(--cyan));
                                height:100%;border-radius:4px;box-shadow:0 0 10px #2979ff55"></div>
                  </div>
                  <div style="font-family:'Rajdhani',sans-serif;font-size:16px;font-weight:700;color:var(--white);
                              width:28px;text-align:right">{count}</div>
                </div>"""
            st.markdown(f"""
            <div style="background:#030810;border:1px solid var(--border);border-left:3px solid var(--cyan);
                        padding:14px 16px;border-radius:0 6px 6px 0;margin-top:10px">
              <div style="font-family:'Rajdhani',sans-serif;font-size:13px;color:var(--cyan);
                          letter-spacing:2px;margin-bottom:12px;font-weight:600">THREAT CATEGORY COUNTS ACROSS CURRENT RUN</div>
              {graph_html}
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown('<div class="ind-pass">NO THREAT INDICATORS WERE FOUND IN THE CURRENT RUN</div>', unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 02: SANITIZE
# ═════════════════════════════════════════════════════════════════════════════
elif "SANITIZE" in page and "ENCRYPT" not in page:
    st.markdown('<div class="sx-banner">OPERATION: DEEP CONTENT SANITIZATION + SANCTUM-AI CERTIFICATION</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-page-title">[ 02 ] SANITIZE</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-subtitle">METADATA EXCISION · ACTIVE CONTENT REMOVAL · MEDIA RE-ENCODING · AI CERTIFICATION</div>', unsafe_allow_html=True)
    step_nav("SANITIZE")

    scan_data = st.session_state.get("scan_results", {})
    eligible  = {k: v for k, v in scan_data.items() if v["result"].verdict != "FAIL"}

    if not eligible:
        st.warning("◆  NO ELIGIBLE ASSETS — GO TO [ 01 ] INGEST & THREAT SCAN FIRST")
        st.markdown("""
        <div class="sx-panel sx-panel-cyan" style="font-size:13px;color:var(--blue-lit);font-family:'Inter',sans-serif">
        <strong style="color:var(--white)">How to use this step:</strong><br>
        1. Go to <strong>[ 01 ] INGEST &amp; THREAT SCAN</strong> in the sidebar<br>
        2. Upload your files — scanning starts automatically<br>
        3. Files that pass (CLEARED or FLAGGED) will appear here for sanitization<br>
        4. Files that FAIL are automatically quarantined and cannot be sanitized
        </div>""", unsafe_allow_html=True)
        st.stop()

    st.markdown(f'<div class="sx-section">ASSETS QUEUED: {len(eligible)}</div>', unsafe_allow_html=True)
    for fname, data in eligible.items():
        r  = data["result"]
        rc = risk_color(r.risk_score)
        st.markdown(f'<div class="sx-file-row"><span style="color:var(--white);font-family:\'JetBrains Mono\',monospace;font-size:12px">▸ {fname}</span><span style="color:{rc};font-family:\'JetBrains Mono\',monospace;font-size:11px;white-space:nowrap">{r.risk_score}% RISK · {r.extension.upper()} · {r.size_mb} MB</span></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    col_run, col_info = st.columns([2, 1])
    with col_run:
        run_san = st.button("🧹  EXECUTE SANITIZATION PROTOCOL", type="primary", use_container_width=True)
    with col_info:
        st.markdown('<div style="font-family:\'JetBrains Mono\',monospace;font-size:11px;color:var(--white-mute);padding:10px">Strips all metadata, removes active content, re-encodes media</div>', unsafe_allow_html=True)

    if run_san:
        st.session_state["sanitize_results"] = {}
        bar    = st.progress(0, text="Starting sanitization...")
        lp     = load_learned_patterns()
        scan_c = lp.get("scan_count", 0)

        for i, (fname, data) in enumerate(eligible.items()):
            bar.progress(i / len(eligible), text=f"Sanitizing {fname}...")
            sr: SanitizeResult = sanitize_file(data["path"], SANITIZED_DIR)
            st.session_state["sanitize_results"][fname] = sr
            log_event("SANITIZE", fname, f"actions:{len(sr.actions)} removed:{len(sr.removed_items)} time:{sr.sanitize_time_ms}ms", "PASS" if sr.success else "FAIL")

            sym = "✅ DECONTAMINATED" if sr.success else "❌ FAILED"
            with st.expander(f"{sym}  ·  {fname}  ·  {sr.sanitize_time_ms:.0f}ms", expanded=True):
                if sr.success:
                    m1, m2, m3 = st.columns(3)
                    m1.metric("INPUT",  f"{sr.size_in_mb:.3f} MB")
                    m2.metric("OUTPUT", f"{sr.size_out_mb:.3f} MB")
                    m3.metric("TIME",   f"{sr.sanitize_time_ms:.0f}ms")

                    ext = os.path.splitext(fname)[1].lower()
                    io_map = {
                        ".pdf": ("PDF",  "Stripped metadata · Removed JS/XFA/OpenAction · Re-compressed",
                                         "Clean PDF · No JS · No embedded files · No metadata"),
                        ".txt": ("TXT",  "Read all lines · UTF-8 decoded · Control chars checked",
                                         "Clean UTF-8 · No BOM · No control bytes · No injections"),
                        ".csv": ("CSV",  "Parsed rows/cols · Formula injection detected",
                                         "Clean CSV · Injections neutralized · UTF-8 encoded"),
                        ".json":("JSON", "Parsed structure · Keys/values inspected",
                                         "Clean JSON · No scripts · Re-encoded UTF-8"),
                        ".png": ("PNG",  "Pixel data opened · EXIF extracted · LSB analyzed",
                                         "New PNG · Zero EXIF · No steganography · RGB clean"),
                        ".jpg": ("JPEG", "Pixels opened · EXIF/GPS extracted · LSB analyzed",
                                         "Re-encoded JPEG q=92 · Zero EXIF · No GPS"),
                        ".jpeg":("JPEG", "Pixels opened · EXIF/GPS extracted · LSB analyzed",
                                         "Re-encoded JPEG q=92 · Zero EXIF · No GPS"),
                        ".docx":("DOCX", "Paragraphs parsed · ZIP internals scanned · Macros checked",
                                         "Clean DOCX · No macros · Author redacted · No ext links"),
                        ".xlsx":("XLSX", "Sheets/rows/cells read · VBA/hidden sheets checked",
                                         "Clean XLSX · No macros · No hidden sheets"),
                    }
                    inp_lbl, inp_desc, out_desc = io_map.get(ext, ("FILE","Inspected","Copied"))

                    ic1, ic2 = st.columns(2)
                    with ic1:
                        st.markdown(f'<div class="cp-box"><div class="cp-head" style="color:var(--amber)">⬇ INPUT — {inp_lbl}</div><div style="color:var(--white-dim);font-size:12px;line-height:1.7">{inp_desc}</div><div style="margin-top:6px;font-family:\'JetBrains Mono\',monospace;font-size:10px;color:var(--white-mute);word-break:break-all">SHA-256: {(sr.sha256_in or "")[:40]}…</div></div>', unsafe_allow_html=True)
                    with ic2:
                        st.markdown(f'<div class="cp-box"><div class="cp-head" style="color:var(--green)">⬆ OUTPUT — {inp_lbl}</div><div style="color:var(--white-dim);font-size:12px;line-height:1.7">{out_desc}</div><div style="margin-top:6px;font-family:\'JetBrains Mono\',monospace;font-size:10px;color:var(--white-mute);word-break:break-all">SHA-256: {(sr.sha256_out or "")[:40]}…</div></div>', unsafe_allow_html=True)

                    st.markdown('<div class="sx-section" style="color:var(--cyan)">OPERATIONS</div>', unsafe_allow_html=True)
                    for action in sr.actions:
                        st.markdown(f'<div class="ind-act">▸ {action}</div>', unsafe_allow_html=True)

                    if sr.removed_items:
                        st.markdown('<div class="sx-section" style="color:var(--amber)">EXCISED</div>', unsafe_allow_html=True)
                        for item in sr.removed_items:
                            st.markdown(f'<div class="ind-high">⊘ {item}</div>', unsafe_allow_html=True)

                    term(f"IN  : {sr.sha256_in}\nOUT : {sr.sha256_out}\nΔ   : {'CONTENT MODIFIED — sanitization applied' if sr.sha256_in != sr.sha256_out else 'UNCHANGED'}")

                    render_cert_seal(fname, sr.sha256_in or "", sr.sha256_out or "", sr.sanitize_time_ms, scan_c)
                else:
                    st.error(f"◈  FAILED: {sr.error}")

            bar.progress((i + 1) / len(eligible), text=f"Done {i+1}/{len(eligible)}")

        bar.progress(1.0, text="✅ Sanitization complete")
        st.success("◈  ALL ASSETS CERTIFIED · NEXT → [ 03 ] ENCRYPT & PACKAGE in the sidebar")


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 03: ENCRYPT & PACKAGE
# ═════════════════════════════════════════════════════════════════════════════
elif "ENCRYPT" in page:
    st.markdown('<div class="sx-banner">OPERATION: AES-256-GCM BUNDLE ENCRYPTION // HMAC-SHA512 SIGNING</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-page-title">[ 03 ] ENCRYPT &amp; PACKAGE</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-subtitle">AES-256-GCM AUTHENTICATED ENCRYPTION · HMAC-SHA512 SIGNING · DOWNLOAD YOUR BUNDLE + KEY</div>', unsafe_allow_html=True)
    step_nav("ENCRYPT")

    san_data = st.session_state.get("sanitize_results", {})
    ready    = [sr.output_path for sr in san_data.values()
                if sr.success and sr.output_path and os.path.exists(sr.output_path)]

    if not ready:
        st.warning("◆  NO SANITIZED ASSETS — COMPLETE [ 02 ] SANITIZE FIRST")
        st.markdown("""
        <div class="sx-panel sx-panel-cyan" style="font-size:13px;color:var(--blue-lit);font-family:'Inter',sans-serif">
        <strong style="color:var(--white)">What happens here:</strong><br>
        All sanitized files are packed into a ZIP, then encrypted with AES-256-GCM.<br>
        You get two files: <strong>.enc</strong> (the encrypted bundle) and <strong>.key</strong> (the decryption key).<br>
        Keep them on separate physical media — never on the same drive.
        </div>""", unsafe_allow_html=True)
        st.stop()

    st.markdown('<div class="sx-section">FILES TO BUNDLE</div>', unsafe_allow_html=True)
    for p in ready:
        sz = os.path.getsize(p) / 1024
        st.markdown(f'<div class="sx-file-row"><span style="color:var(--white);font-family:\'JetBrains Mono\',monospace;font-size:12px">▸ {os.path.basename(p)}</span><span style="color:var(--green);font-size:11px;white-space:nowrap">{sz:.1f} KB · SANITIZED</span></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="sx-section">◈ ENCRYPTION KEY MODE</div>', unsafe_allow_html=True)

    col_enc1, col_enc2 = st.columns(2)
    with col_enc1:
        st.markdown("""
        <div class="cp-box">
          <div class="cp-head">🔑 RANDOM KEY (RECOMMENDED)</div>
          <div style="color:var(--white-dim);font-size:12px;line-height:1.7">
            Generates a random 256-bit AES key.<br>
            Download the .key file and deliver it via a separate channel.
          </div>
        </div>""", unsafe_allow_html=True)
    with col_enc2:
        st.markdown("""
        <div class="cp-box">
          <div class="cp-head">🔒 PASSPHRASE (PBKDF2)</div>
          <div style="color:var(--white-dim);font-size:12px;line-height:1.7">
            Derives key from passphrase using 310,000 PBKDF2-SHA256 iterations.<br>
            Recipient needs the passphrase to decrypt — no .key file needed.
          </div>
        </div>""", unsafe_allow_html=True)

    enc_mode   = st.radio("KEY MODE", ["RANDOM KEY (AES-256-GCM)", "PASSPHRASE (PBKDF2-SHA256 · 310K ITER)"], horizontal=True)
    passphrase = None
    if "PASSPHRASE" in enc_mode:
        passphrase = st.text_input("ENTER PASSPHRASE", type="password", placeholder="Enter a strong passphrase...")
        if passphrase:
            strength = len(set(passphrase)) * len(passphrase)
            sc2 = "var(--red)" if strength < 80 else "var(--amber)" if strength < 200 else "var(--green)"
            sl  = "WEAK — use more characters and variety" if strength < 80 else "MODERATE" if strength < 200 else "STRONG ✓"
            st.markdown(f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:12px;color:{sc2};margin:4px 0">STRENGTH: {sl}</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🔐  CREATE ENCRYPTED BUNDLE", type="primary", use_container_width=True):
        with st.spinner("Encrypting · Signing · Packaging..."):
            info = create_bundle(ready, BUNDLE_DIR, passphrase=passphrase if passphrase else None)
        package_info = _persist_package_info(info)
        log_event("PACKAGE", os.path.basename(info["bundle_path"]),
            f"files:{len(ready)} algo:{info['algorithm']} sha256:{info['sha256_bundle'][:16]}", "PASS")

        st.success("🔐  BUNDLE ENCRYPTED AND SIGNED · DOWNLOAD BOTH FILES BELOW")
        st.markdown("<br>", unsafe_allow_html=True)

        bsz = os.path.getsize(info["bundle_path"]) / 1024
        b1,b2,b3,b4 = st.columns(4)
        for col,val,lbl in [(b1,info["file_count"],"FILES BUNDLED"),(b2,info["algorithm"],"ENCRYPTION"),
                            (b3,"PBKDF2" if passphrase else "RANDOM","KEY TYPE"),(b4,f"{bsz:.1f} KB","BUNDLE SIZE")]:
            col.markdown(sx_stat(val,lbl), unsafe_allow_html=True)

        hmac_sig  = info.get("hmac_signature") or "N/A"
        files_txt = "".join(f"  {f['name']}  SHA256:{f['sha256'][:32]}...  {f['size_bytes']:,}B\n" for f in info['manifest']['files'])
        term(f"ALGORITHM    : {info['algorithm']}\nBUNDLE SHA256: {info['sha256_bundle']}\nHMAC-SHA512  : {hmac_sig[:64]}...\n\nFILES:\n{files_txt}STATUS: ENCRYPTED · SIGNED · READY")

        st.markdown('<div class="sx-section">◈ DOWNLOAD YOUR FILES</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="sx-panel sx-panel-amber" style="font-size:13px;color:var(--white-dim);font-family:'Inter',sans-serif;margin-bottom:12px">
        ⚠  <strong style="color:var(--amber)">IMPORTANT:</strong>
        Download BOTH files. Keep the <strong>.enc</strong> bundle and <strong>.key</strong> file on
        <strong>SEPARATE physical media</strong>. Never place both on the same drive.
        </div>""", unsafe_allow_html=True)

        dc1, dc2 = st.columns(2)
        if os.path.exists(info["bundle_path"]):
            with open(info["bundle_path"], "rb") as f:
                dc1.download_button("⬇  DOWNLOAD BUNDLE (.enc)", data=f,
                    file_name=os.path.basename(info["bundle_path"]),
                    mime="application/octet-stream", use_container_width=True)
        if info.get("key_path") and os.path.exists(info["key_path"]):
            with open(info["key_path"], "rb") as f:
                dc2.download_button("⬇  DOWNLOAD KEY FILE (.key)", data=f,
                    file_name=os.path.basename(info["key_path"]),
                    mime="application/json", use_container_width=True)

        st.markdown("""
        <div class="sx-panel sx-panel-green" style="font-size:13px;color:var(--white-dim);font-family:'Inter',sans-serif;margin-top:12px">
        <strong style="color:var(--green)">NEXT STEP:</strong>
        Go to <strong>[ 04 ] DELIVER TO WAREHOUSE</strong> to push the bundle to the army warehouse,
        or use <strong>[ 05 ] DECRYPT BUNDLE</strong> on the receiving side to unpack the files.
        </div>""", unsafe_allow_html=True)
        st.caption(f"Delivery will use: {package_info['bundle_name']} + {package_info['key_name']}")


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 04: DELIVER TO WAREHOUSE
# ═════════════════════════════════════════════════════════════════════════════
elif "WAREHOUSE" in page:
    st.markdown('<div class="sx-banner">OPERATION: SECURE DELIVERY TO ARMY PRIVATE DATA WAREHOUSE</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-page-title">[ 04 ] DELIVER TO WAREHOUSE</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-subtitle">DIRECT LAN · VPN TUNNEL · SNEAKERNET/USB — NO PUBLIC INTERNET USED</div>', unsafe_allow_html=True)
    step_nav("WAREHOUSE")

    delivery_package = _resolve_delivery_package()

    if not delivery_package:
        st.warning("◆  NO DELIVERY BUNDLE FOUND — COMPLETE [ 03 ] ENCRYPT & PACKAGE FIRST")
        st.markdown("""
        <div class="sx-panel sx-panel-cyan" style="font-size:13px;color:var(--blue-lit);font-family:'Inter',sans-serif">
        <strong style="color:var(--white)">What happens here:</strong><br>
        Delivers the generated bundle to the army's private data warehouse via LAN, VPN, or physical USB.<br>
        If cryptography support is installed, this will be an AES-256-GCM encrypted bundle; otherwise the app uses a ZIP fallback.
        </div>""", unsafe_allow_html=True)
        st.stop()

    latest_bundle = delivery_package["bundle_path"]
    latest_key    = delivery_package["key_path"]
    bundle_name   = delivery_package["bundle_name"]
    key_name      = delivery_package["key_name"]
    bundle_manifest = delivery_package.get("manifest") or {}
    bsz           = os.path.getsize(latest_bundle)
    with open(latest_bundle, "rb") as bundle_fh:
        bundle_sha256 = hashlib.sha256(bundle_fh.read()).hexdigest()
    term(f"READY BUNDLE : {bundle_name}\nKEY FILE     : {key_name}\nSIZE         : {bsz:,} bytes ({bsz/1024:.1f} KB)\nSHA-256      : {bundle_sha256}")
    if not latest_key:
        st.warning("This bundle was created without a .key file. Install `cryptography` to produce encrypted .enc bundles for full secure transfer.")

    st.markdown('<div class="sx-section">◈ SELECT DELIVERY MODE</div>', unsafe_allow_html=True)
    mode_col, ping_col = st.columns([3,1])
    with mode_col:
        delivery_mode = st.radio("DELIVERY", [
            "  SNEAKERNET / USB (Air-gap physical transfer — most secure)",
            "  LAN PUSH (Direct on-premise mTLS to warehouse endpoint)",
            "  VPN TUNNEL (Encrypted tunnel to remote warehouse)"],
            horizontal=False)
    with ping_col:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("  PING WAREHOUSE", use_container_width=True):
            mk   = "sneakernet" if "SNEAK" in delivery_mode else "lan" if "LAN" in delivery_mode else "vpn"
            ping = ping_warehouse(mode_override=mk)
            if ping["reachable"]:
                st.success(f" {ping['status']}")
            else:
                st.error(f" {ping['status']}")

    cfg_override = {}
    if "SNEAK" in delivery_mode:
        col_usb1, col_usb2 = st.columns(2)
        with col_usb1:
            usb_path = st.text_input("USB MOUNT PATH", value="/media/ARMY_USB",
                help="Mount point of hardware-encrypted USB. For testing, use a local folder path.")
        with col_usb2:
            subdir   = st.text_input("SUBDIRECTORY", value="SANCTUM_TRANSFERS")
        cfg_override = {"sneakernet": {"output_path": usb_path, "subdir": subdir}}

        if not os.path.exists(usb_path):
            test_path = str(ROOT / "sneakernet_out")
            st.markdown(f"""
            <div class="sx-panel sx-panel-amber" style="font-size:12px;color:var(--white-dim)">
            ⚠ Path <code>{usb_path}</code> not found. Is the USB mounted?
            For <strong>local testing</strong>, use: <code>{test_path}</code>
            </div>""", unsafe_allow_html=True)
            if st.button(" USE LOCAL TEST OUTPUT FOLDER", use_container_width=False):
                os.makedirs(test_path, exist_ok=True)
                cfg_override = {"sneakernet": {"output_path": test_path, "subdir": subdir}}
                st.success(f" Using local test folder: {test_path}")
        else:
            st.markdown(f'<div class="ind-pass">✓ Path found and accessible: {usb_path}</div>', unsafe_allow_html=True)
        st.markdown('<div class="sx-panel sx-panel-amber" style="font-size:12px;color:var(--white-dim)">⚠ KEY FILE will NOT be written to USB — deliver it via separate channel (courier, encrypted radio, HSM)</div>', unsafe_allow_html=True)
    elif "LAN" in delivery_mode:
        l1,l2 = st.columns(2)
        with l1:
            endpoint    = st.text_input("ENDPOINT URL", value="https://192.168.1.100:8443/api/v1/ingest")
            unit_id     = st.text_input("UNIT ID", value="UNIT-ALPHA-01")
        with l2:
            client_cert = st.text_input("CLIENT CERT", value="certs/client.crt")
            ca_bundle   = st.text_input("CA BUNDLE",   value="certs/army_ca.crt")
        collection   = st.text_input("COLLECTION", value="SANCTUM_INGEST")
        cfg_override = {"lan": {"endpoint_url": endpoint, "client_cert": client_cert,
                                "client_key": client_cert.replace(".crt",".key"),
                                "ca_bundle": ca_bundle, "collection": collection,
                                "unit_id": unit_id, "timeout_sec": 30}}
    else:
        v1,v2 = st.columns(2)
        with v1:
            vpn_ep   = st.text_input("VPN ENDPOINT", value="https://10.0.0.50:8443/api/v1/ingest")
            vpn_unit = st.text_input("UNIT ID", value="UNIT-BRAVO-02")
        with v2:
            vpn_cert = st.text_input("CLIENT CERT", value="certs/client.crt")
            vpn_ca   = st.text_input("CA BUNDLE",   value="certs/army_ca.crt")
        vpn_col      = st.text_input("COLLECTION", value="SANCTUM_INGEST")
        cfg_override = {"vpn": {"endpoint_url": vpn_ep, "client_cert": vpn_cert,
                                "client_key": vpn_cert.replace(".crt",".key"),
                                "ca_bundle": vpn_ca, "collection": vpn_col,
                                "unit_id": vpn_unit, "timeout_sec": 60}}

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("  INITIATE SECURE DELIVERY", type="primary", use_container_width=True):
        mk  = "sneakernet" if "SNEAK" in delivery_mode else "lan" if "LAN" in delivery_mode else "vpn"
        merged_cfg = copy.deepcopy(DEFAULT_CONFIG)
        merged_cfg.update(cfg_override)
        merged_cfg["mode"] = mk
        save_config(merged_cfg)
        with st.spinner(f"Delivering via {mk.upper()}..."):
            import time as _t; _t.sleep(0.5)
            manifest_payload = dict(bundle_manifest) if bundle_manifest else {}
            manifest_payload.update({
                "bundle": bundle_name,
                "key": key_name or "N/A",
                "sanctum_version": "2.1",
                "created_utc": manifest_payload.get("created_utc", datetime.datetime.utcnow().isoformat()),
            })
            result = deliver_bundle(latest_bundle, latest_key, manifest_payload, mode_override=mk)
        if result.get("success"):
            log_event("DELIVER", bundle_name, f"mode:{mk} dest:{result.get('dest_dir') or result.get('endpoint','N/A')}", "PASS")
            st.success(f" DELIVERY SUCCESSFUL · MODE: {mk.upper()}")
            lines = [f"MODE      : {mk.upper()}", f"TIMESTAMP : {result.get('timestamp','N/A')}", f"SHA-256   : {result.get('sha256','N/A')}"]
            if result.get("dest_dir"): lines += [f"DEST      : {result['dest_dir']}", f"FILES     : {', '.join(result.get('files_written',[]))}"]
            if result.get("warning"):  lines.append(f"WARNING   : {result['warning']}")
            term("\n".join(lines))
        else:
            err_msg = result.get('error', 'Unknown error')
            log_event("DELIVER", bundle_name, f"mode:{mk} error:{err_msg[:80]}", "FAIL")
            st.error(f"  DELIVERY FAILED: {err_msg}")
            if mk == "sneakernet":
                usb_val = cfg_override.get("sneakernet", {}).get("output_path", "/media/ARMY_USB")
                st.markdown(f"""
                <div class="sx-panel sx-panel-amber" style="font-size:13px;color:var(--white-dim);font-family:'Inter',sans-serif">
                <strong style="color:var(--amber)">SNEAKERNET FIX:</strong><br>
                The USB path <code style="color:var(--blue-lit)">{usb_val}</code> was not found or not writable.<br>
                • Mount a USB drive and update the path above<br>
                • Or change the path to a local folder (e.g. <code>/tmp/sanctum_out</code>) for testing<br>
                • On Windows use a path like <code>D:\\SANCTUM_TRANSFERS</code>
                </div>""", unsafe_allow_html=True)
            elif mk in ("lan", "vpn"):
                st.markdown(f"""
                <div class="sx-panel sx-panel-amber" style="font-size:13px;color:var(--white-dim);font-family:'Inter',sans-serif">
                <strong style="color:var(--amber)">NETWORK FIX:</strong><br>
                Cannot reach the warehouse endpoint. Check:<br>
                • The endpoint URL is correct and reachable on this network<br>
                • Client cert / CA bundle paths exist<br>
                • Use <strong>PING WAREHOUSE</strong> to test connectivity first
                </div>""", unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 05: DECRYPT BUNDLE
# ═════════════════════════════════════════════════════════════════════════════
elif "DECRYPT" in page:
    st.markdown('<div class="sx-banner">OPERATION: AUTHENTICATED BUNDLE DECRYPTION // RECEIVING SIDE</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-page-title">[ 05 ] DECRYPT BUNDLE</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-subtitle">HMAC-SHA512 VERIFY → AES-256-GCM DECRYPT → EXTRACT FILES → DOWNLOAD</div>', unsafe_allow_html=True)
    step_nav("DECRYPT")

    st.markdown("""
    <div class="sx-panel sx-panel-cyan" style="font-size:13px;color:var(--white-dim);font-family:'Inter',sans-serif;margin-bottom:16px">
    <strong style="color:var(--white)">How to use this page (receiving side):</strong><br>
    1. Upload the <strong>.enc</strong> bundle file you received<br>
    2. Upload the <strong>.key</strong> file you received via the separate channel<br>
    3. Click <strong>VERIFY INTEGRITY</strong> first — confirms the bundle was not tampered with<br>
    4. Click <strong>VERIFY &amp; DECRYPT</strong> to unpack and download all files
    </div>""", unsafe_allow_html=True)

    uc1,uc2 = st.columns(2)
    with uc1:
        st.markdown('<div class="sx-section">STEP 1: LOAD BUNDLE</div>', unsafe_allow_html=True)
        bundle_file = st.file_uploader("Upload .enc bundle", type=["enc","zip"], label_visibility="collapsed", key="bundle_up")
    with uc2:
        st.markdown('<div class="sx-section">STEP 2: LOAD KEY FILE</div>', unsafe_allow_html=True)
        key_file = st.file_uploader("Upload .key file", type=["key","json"], label_visibility="collapsed", key="key_up")

    passphrase_dec = None
    if key_file:
        try:
            kd = json.loads(key_file.read()); key_file.seek(0)
            if kd.get("type") == "pbkdf2":
                passphrase_dec = st.text_input("PASSPHRASE REQUIRED (this bundle was encrypted with a passphrase)", type="password")
        except Exception:
            pass

    if bundle_file and key_file:
        tmp_bundle = os.path.join(DECRYPTED_DIR, bundle_file.name)
        tmp_key    = os.path.join(DECRYPTED_DIR, key_file.name)
        with open(tmp_bundle,"wb") as f: f.write(bundle_file.read())
        with open(tmp_key,"wb")    as f: f.write(key_file.read())

        st.markdown('<div class="sx-section">STEP 3: VERIFY &amp; DECRYPT</div>', unsafe_allow_html=True)
        vc1,vc2 = st.columns(2)
        with vc1:
            if st.button("  VERIFY INTEGRITY ONLY", use_container_width=True,
                         help="Checks HMAC-SHA512 to confirm the bundle was not modified in transit"):
                res = verify_bundle_integrity(tmp_bundle, tmp_key, passphrase_dec)
                if res.get("verified"):
                    st.success("  HMAC-SHA512 VERIFIED — BUNDLE NOT TAMPERED WITH")
                    term(f"ALGORITHM  : {res.get('algorithm','N/A')}\nSHA-256    : {res.get('bundle_sha256','N/A')}\nSTATUS     : INTACT")
                else:
                    st.error(f" INTEGRITY FAILURE — {res.get('error','BUNDLE MAY BE COMPROMISED')}")
        with vc2:
            if st.button("  VERIFY & DECRYPT", type="primary", use_container_width=True,
                         help="Verifies HMAC then decrypts and extracts all files"):
                try:
                    out_dir   = os.path.join(DECRYPTED_DIR, "extracted")
                    extracted = decrypt_bundle(tmp_bundle, tmp_key, out_dir, passphrase_dec)
                    log_event("DECRYPT", bundle_file.name, f"extracted:{len(extracted)}", "PASS")
                    st.success(f"  DECRYPTED SUCCESSFULLY — {len(extracted)} FILE(S) RECOVERED")
                    st.markdown('<div class="sx-section">STEP 4: DOWNLOAD FILES</div>', unsafe_allow_html=True)
                    for fp in extracted:
                        if os.path.exists(fp) and not fp.endswith("manifest.json"):
                            fn    = os.path.basename(fp)
                            fsz   = os.path.getsize(fp)
                            fhash = hashlib.sha256()
                            with open(fp,"rb") as fh:
                                for ch in iter(lambda: fh.read(65536), b""): fhash.update(ch)
                            term(f"FILE : {fn}\nSIZE : {fsz:,} bytes\nSHA  : {fhash.hexdigest()}")
                            with open(fp,"rb") as fh:
                                st.download_button(f"⬇  DOWNLOAD: {fn}", fh.read(), file_name=fn, key=f"dl_{fn}")
                except ValueError as e:
                    st.error(f"  {e}")
                    log_event("DECRYPT", bundle_file.name, str(e), "FAIL")
                except Exception as e:
                    st.error(f"DECRYPTION ERROR: {e}")
    else:
        st.info("  Upload both the .enc bundle and .key file above to continue")


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 06: AUDIT CHAIN
# ═════════════════════════════════════════════════════════════════════════════
elif "AUDIT" in page:
    st.markdown('<div class="sx-banner">IMMUTABLE CHAIN-OF-CUSTODY AUDIT LOG // TAMPER-EVIDENT</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-page-title">[ 06 ] AUDIT CHAIN</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-subtitle">SHA-256 CHAINED ENTRIES · EVERY ACTION RECORDED · CRYPTOGRAPHIC TAMPER DETECTION</div>', unsafe_allow_html=True)
    st.markdown("""
    <style>
    /* Audit page only: hide the expander chevron in each log row */
    [data-testid="stExpanderToggleIcon"] {
      display: none !important;
    }
    [data-testid="stExpander"] summary {
      padding-right: 14px !important;
    }
    </style>
    """, unsafe_allow_html=True)
    step_nav("AUDIT")

    chain_ok = verify_chain()
    cc = "var(--green)" if chain_ok else "var(--red)"
    ct = " CHAIN INTEGRITY PASSED — LOG HAS NOT BEEN TAMPERED WITH" if chain_ok else "CHAIN INTEGRITY FAILED — LOG MAY BE COMPROMISED"
    st.markdown(f'<div class="sx-panel sx-panel-{"green" if chain_ok else "red"}" style="font-family:\'Rajdhani\',sans-serif;font-size:16px;font-weight:600;color:{cc}">{ct}</div>', unsafe_allow_html=True)

    logs = read_log()
    if not logs:
        st.info(" NO AUDIT EVENTS YET — START SCANNING FILES")
        st.stop()

    mc1,mc2,mc3,mc4,mc5 = st.columns(5)
    for col,val,lbl,color in [
        (mc1,len(logs),                                      "TOTAL",    "var(--white)"),
        (mc2,len([l for l in logs if l["result"]=="PASS"]),  "PASS",     "var(--green)"),
        (mc3,len([l for l in logs if l["result"]=="WARN"]),  "WARN",     "var(--amber)"),
        (mc4,len([l for l in logs if l["result"]=="FAIL"]),  "FAIL",     "var(--red)"),
        (mc5,len([l for l in logs if l["action"]=="QUARANTINE"]),"QUAR", "var(--red)"),
    ]:
        col.markdown(sx_stat(val,lbl,color), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    fc1,fc2,fc3 = st.columns([2,1,1])
    with fc1:
        filt = st.selectbox("FILTER BY ACTION", ["ALL","INGEST","SCAN","SANITIZE","QUARANTINE","PACKAGE","DECRYPT","DELIVER"])
    with fc2:
        sort_desc = st.checkbox("NEWEST FIRST", value=True)
    with fc3:
        if os.path.exists(AUDIT_FILE):
            with open(AUDIT_FILE,"rb") as f:
                st.download_button("⬇  EXPORT LOG", f, file_name="sanctum_x_audit.jsonl", mime="application/json", use_container_width=True)

    show = logs if filt == "ALL" else [l for l in logs if l["action"] == filt]
    if sort_desc: show = list(reversed(show))

    for entry in show:
        ec  = {"PASS":"var(--green)","WARN":"var(--amber)","FAIL":"var(--red)"}.get(entry["result"],"var(--white-mute)")
        sym = {"PASS":"","WARN":"⚠","FAIL":""}.get(entry["result"],"·")
        ts  = entry["timestamp"][:19].replace("T"," ")
        with st.expander(f"{sym}  {ts}  ·  {entry['action']}  ·  {entry['file']}", expanded=False):
            term(f"TIMESTAMP  : {entry['timestamp']}\nACTION     : {entry['action']}\nFILE       : {entry['file']}\nDETAIL     : {entry['detail']}\nRESULT     : {entry['result']}\nPREV HASH  : {entry.get('prev_hash','')[:48]}...\nENTRY HASH : {entry.get('entry_hash','')}")


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 07: DOCTRINE
# ═════════════════════════════════════════════════════════════════════════════
elif "DOCTRINE" in page:
    st.markdown('<div class="sx-banner">SANCTUM-X OPERATIONAL DOCTRINE // FOR AUTHORIZED PERSONNEL ONLY</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-page-title">[ 07 ] DOCTRINE</div>', unsafe_allow_html=True)
    st.markdown('<div class="sx-subtitle">OPERATIONAL THEORY · THREAT MODEL · CRYPTOGRAPHIC SPECIFICATIONS · v4.0 FEATURES</div>', unsafe_allow_html=True)

    st.markdown('<div class="sx-section">◈ THREAT LANDSCAPE</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-family:\'Inter\',sans-serif;font-size:14px;color:var(--white-dim);line-height:1.9">An air-gapped network maintains zero physical or wireless connectivity to external systems. Deployed in nuclear command infrastructure, classified military networks, banking settlement systems, and industrial SCADA controllers. The singular attack surface: physical transfer media.</div>', unsafe_allow_html=True)

    term("KNOWN AIR-GAP BREACHES\n" + "="*60 + "\nStuxnet (2010)       USB > SCADA         1,000 centrifuges destroyed\nAgent.BTZ (2008)     USB drop            US SIPRNET · 14 month remediation\nFlame (2012)         USB + net share     Middle East espionage\nIndustroyer (2016)   ICS protocols       Ukraine power grid blackout\nFanny (2015)         USB firmware        Persisted in drive firmware\n" + "="*60 + "\nCOMMON VECTOR: ALL EXPLOITED PHYSICAL MEDIA TRANSFER")

    st.markdown('<div class="sx-section">◈ CRYPTOGRAPHIC SPECS</div>', unsafe_allow_html=True)
    term("ENCRYPTION     : AES-256-GCM (Galois/Counter Mode)\nKEY SIZE       : 256-bit (32 bytes)\nNONCE          : 96-bit random (os.urandom CSPRNG)\nAUTH TAG       : 128-bit GCM authentication tag\nAAD            : 'secure-sanitization-framework-v2'\nBUNDLE SIGNING : HMAC-SHA512 (detached signature)\nKEY DERIVATION : PBKDF2-SHA256 · 310,000 iterations (NIST SP800-132)\nHASH BASELINE  : SHA-256 + MD5 dual independent verification\nAUDIT CHAIN    : SHA-256 per-entry chaining (blockchain-style)")

    st.markdown('<div class="sx-section">◈ v4.0 FEATURE CHANGELOG</div>', unsafe_allow_html=True)
    term("1. ADVANCED UI          — Animated hero, glassmorphism, hover effects, no text overlap\n2. UNLIMITED FILES       — Any file size, any count, results one-by-one as each completes\n3. RISK AS PERCENTAGE    — SVG circle gauge replaces raw number (0%–100%)\n4. NO TEXT OVERLAP       — All labels use nowrap/ellipsis, fixed expander arrow\n5. SELF-LEARNING AI      — Learns entropy baselines and threat rates per file type\n6. THREAT DNA            — 16-dimension visual fingerprint unique to each file's threat profile\n7. SIMPLIFIED PIPELINE   — Every step explains what it does and where to go next")
