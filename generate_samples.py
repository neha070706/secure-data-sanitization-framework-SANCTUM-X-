"""
generate_samples.py  —  SANCTUM-X v2.1
---------------------------------------
Generates realistic demo assets every run with:
  - Timestamp-suffixed filenames so each run produces fresh files
  - Randomised content (names, coords, dates) so scan results vary
  - One threat-injected file per run to exercise quarantine
  - Military-flavoured data: GIS coords, personnel records, SIGINT reports

Usage:
    python generate_samples.py
    python generate_samples.py --out uploads/   # custom output dir
"""

import argparse
import csv
import json
import os
import random
from datetime import datetime, timezone, timedelta

# ── timestamp suffix ──────────────────────────────────────────────────────────
TS = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
SEED = int(datetime.now(timezone.utc).timestamp())
random.seed(SEED)

# ── randomised data pools ─────────────────────────────────────────────────────
FIRST_NAMES = ["James", "Maria", "Chen", "Fatima", "Arjun", "Yusuf",
               "Elena", "David", "Priya", "Omar", "Sarah", "Kwame"]
LAST_NAMES  = ["Morrison", "Petrov", "Singh", "Al-Hassan", "Nowak",
               "Okafor", "Tanaka", "Andersen", "Reyes", "Fischer"]
UNITS       = ["2nd Battalion", "7th Brigade", "Delta Force", "FOB Kilo",
               "Alpha Company", "SIGINT Unit 4", "Forward Recon Group"]
LOCATIONS   = [
    ("Kandahar",    31.6085,  65.7372),
    ("Kabul",       34.5260,  69.1763),
    ("Mosul",       36.3400,  43.1340),
    ("Erbil",       36.1901,  44.0090),
    ("Jalalabad",   34.4300,  70.4500),
    ("Basra",       30.5085,  47.7804),
    ("Fallujah",    33.3506,  43.7742),
]
THREAT_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CLASSIFICATIONS = ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP SECRET"]
MISSION_TYPES = [
    "route clearance", "border monitoring", "signals capture", "forward observation",
    "infrastructure assessment", "convoy overwatch", "perimeter hardening"
]
EQUIPMENT = [
    "AN/PRC-152 radio", "Harris Falcon IV", "thermal monocular", "Blue Force Tracker",
    "rugged tablet", "encrypted SSD", "UAV relay kit", "field server node"
]
INCIDENTS = [
    "unidentified drone overflight", "radio silence deviation", "checkpoint delay",
    "power fluctuation at relay mast", "unexpected convoy reroute", "sensor jitter spike",
    "unauthorized access attempt", "intermittent SATCOM degradation"
]

def _rname():
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"

def _runit():
    return random.choice(UNITS)

def _rloc():
    return random.choice(LOCATIONS)

def _rdate(days_back=90):
    d = datetime.now(timezone.utc) - timedelta(days=random.randint(0, days_back))
    return d.strftime("%Y-%m-%d")

def _rtime():
    h = random.randint(0, 23)
    m = random.randint(0, 59)
    return f"{h:02d}{m:02d}Z"

def _rid(prefix="ID", n=8):
    return f"{prefix}-{random.randint(10**(n-1), 10**n - 1)}"


def _grid_ref(lat: float, lon: float) -> str:
    return f"GRID {int(abs(lat) * 100):04d}-{int(abs(lon) * 100):04d}"


def _callsign():
    return f"{random.choice(['RAVEN', 'VIPER', 'FALCON', 'NOMAD', 'ORBIT', 'SENTRY'])}-{random.randint(11, 99)}"


def _risk_note():
    return random.choice([
        "persistent low-volume chatter on secondary channel",
        "asset moved without prior route confirmation",
        "routine patrol with no anomaly escalation",
        "minor signal drift resolved by field recalibration",
        "operator reported intermittent static at relay boundary",
    ])


def _clear_previous_generated(out_dir: str) -> int:
    removed = 0
    prefixes = (
        "sigint_report_", "personnel_roster_", "sensor_telemetry_", "field_image_",
        "field_intel_brief_", "logistics_manifest_", "THREAT_malicious_doc_",
        "THREAT_suspicious_script_", "THREAT_formula_roster_", "THREAT_sensor_alert_",
    )
    for name in os.listdir(out_dir):
        if name.startswith(prefixes):
            try:
                os.remove(os.path.join(out_dir, name))
                removed += 1
            except OSError:
                pass
    return removed


# ── file generators ───────────────────────────────────────────────────────────

def gen_txt(out_dir: str) -> str:
    """SIGINT / field intelligence report."""
    loc_name, lat, lon = _rloc()
    analyst = _rname()
    subject = _rname()
    threat  = random.choice(THREAT_LEVELS)
    cls     = random.choice(CLASSIFICATIONS)
    report_id = _rid("RPT")
    date    = _rdate()
    mission = random.choice(MISSION_TYPES)
    callsign = _callsign()
    content = f"""CLASSIFICATION: {cls}
REPORT ID   : {report_id}
DATE        : {date} {_rtime()}
ANALYST     : {analyst}
UNIT        : {_runit()}
CALLSIGN    : {callsign}
SUBJECT     : {subject}
LOCATION    : {loc_name} ({lat:.4f}N, {lon:.4f}E)
GRID REF    : {_grid_ref(lat, lon)}
THREAT LEVEL: {threat}
MISSION     : {mission}

EXECUTIVE SUMMARY
=================
Intelligence gathered from signals intercept at {loc_name} on {date}.
Subject ({subject}) was observed at grid reference {lat:.4f}N {lon:.4f}E
operating in the vicinity of {_runit()} assets.

SIGINT ASSESSMENT
=================
Three intercepts collected between {_rtime()} and {_rtime()}.
Communication pattern consistent with {threat.lower()} threat activity.
No encryption detected on primary channel. Secondary channel encrypted —
further analysis pending.

RECOMMENDED ACTION
==================
{"Continue monitoring. No immediate action required." if threat in ("LOW","MEDIUM") else "Escalate to command. Immediate tasking recommended."}

ANALYST NOTES
=============
Report compiled by {analyst}, {_runit()}.
Cross-reference with report {_rid("RPT")} and {_rid("RPT")}.
Equipment referenced: {random.choice(EQUIPMENT)}.
Field note: {_risk_note()}.
Next review: {_rdate(days_back=7)}.

END OF REPORT — {cls}
"""
    path = os.path.join(out_dir, f"sigint_report_{TS}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  [CLEAN]  {os.path.basename(path)}")
    return path


def gen_csv(out_dir: str) -> str:
    """Personnel roster with GIS coordinates."""
    path = os.path.join(out_dir, f"personnel_roster_{TS}.csv")
    rows = []
    for i in range(random.randint(18, 32)):
        loc_name, lat, lon = _rloc()
        rows.append({
            "ID":             _rid("PID", 6),
            "Name":           _rname(),
            "Unit":           _runit(),
            "Rank":           random.choice(["PVT","CPL","SGT","SSG","SFC","MSG","2LT","1LT","CPT"]),
            "Clearance":      random.choice(["NONE","SECRET","TOP SECRET"]),
            "Location":       loc_name,
            "Latitude":       f"{lat + random.uniform(-0.05,0.05):.6f}",
            "Longitude":      f"{lon + random.uniform(-0.05,0.05):.6f}",
            "Last_Check_In":  f"{_rdate()} {_rtime()}",
            "Status":         random.choice(["ACTIVE","STANDBY","ON LEAVE","DEPLOYED"]),
            "Callsign":       _callsign(),
            "Assigned_Gear":  random.choice(EQUIPMENT),
        })
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"  [CLEAN]  {os.path.basename(path)}")
    return path


def gen_json(out_dir: str) -> str:
    """Sensor / IoT telemetry data."""
    loc_name, lat, lon = _rloc()
    records = []
    base_time = datetime.now(timezone.utc)
    for i in range(random.randint(20, 40)):
        t = base_time - timedelta(minutes=i * random.randint(5, 15))
        records.append({
            "sensor_id":     _rid("SEN", 6),
            "timestamp":     t.isoformat(),
            "location":      {"name": loc_name, "lat": lat + random.uniform(-0.01,0.01),
                              "lon": lon + random.uniform(-0.01,0.01)},
            "readings": {
                "temperature_c": round(random.uniform(18.0, 48.0), 2),
                "humidity_pct":  round(random.uniform(10.0, 95.0), 2),
                "pressure_hpa":  round(random.uniform(980.0, 1025.0), 2),
                "vibration_g":   round(random.uniform(0.0, 2.5), 4),
                "radiation_usv": round(random.uniform(0.05, 0.45), 4),
            },
            "alert":         random.choice([None, None, None, "THRESHOLD_EXCEEDED"]),
            "operator_note": random.choice([
                "nominal baseline maintained",
                "relay mast inspected by field tech",
                "battery swap completed",
                "requires manual verification at next patrol window",
            ]),
        })
    payload = {
        "schema_version": "1.2",
        "export_time":    datetime.now(timezone.utc).isoformat(),
        "unit":           _runit(),
        "record_count":   len(records),
        "mission":        random.choice(MISSION_TYPES),
        "site_callsign":  _callsign(),
        "records":        records,
    }
    path = os.path.join(out_dir, f"sensor_telemetry_{TS}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"  [CLEAN]  {os.path.basename(path)}")
    return path


def gen_brief_json(out_dir: str) -> str:
    """Nested operational brief with realistic structured data."""
    loc_name, lat, lon = _rloc()
    payload = {
        "brief_id": _rid("BRF"),
        "classification": random.choice(CLASSIFICATIONS),
        "prepared_utc": datetime.now(timezone.utc).isoformat(),
        "sector": loc_name,
        "grid_ref": _grid_ref(lat, lon),
        "mission_type": random.choice(MISSION_TYPES),
        "reporting_unit": _runit(),
        "lead_analyst": _rname(),
        "watch_items": [
            {
                "incident_id": _rid("INC"),
                "summary": random.choice(INCIDENTS),
                "priority": random.choice(["ROUTINE", "ELEVATED", "IMMEDIATE"]),
                "assigned_team": _callsign(),
            }
            for _ in range(random.randint(3, 6))
        ],
        "recommended_actions": [
            "validate route timing against latest patrol handoff",
            "cross-check badge access with local operator roster",
            "reinspect portable media submitted during current shift",
        ],
    }
    path = os.path.join(out_dir, f"field_intel_brief_{TS}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"  [CLEAN]  {os.path.basename(path)}")
    return path


def gen_logistics_csv(out_dir: str) -> str:
    """Convoy and cargo manifest with realistic movement fields."""
    path = os.path.join(out_dir, f"logistics_manifest_{TS}.csv")
    rows = []
    for _ in range(random.randint(12, 20)):
        loc_name, lat, lon = _rloc()
        rows.append({
            "Manifest_ID": _rid("MAN", 7),
            "Container_ID": _rid("CTR", 6),
            "Origin": loc_name,
            "Destination": random.choice([l[0] for l in LOCATIONS]),
            "Cargo_Type": random.choice(["medical", "comms", "rations", "spare_parts", "battery_cells", "encrypted_media"]),
            "Escort_Unit": _runit(),
            "Departure_UTC": f"{_rdate()}T{_rtime()[:4]}:00Z",
            "Latitude": f"{lat + random.uniform(-0.02, 0.02):.6f}",
            "Longitude": f"{lon + random.uniform(-0.02, 0.02):.6f}",
            "Seal_Status": random.choice(["INTACT", "VERIFIED", "RESEALED"]),
        })
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"  [CLEAN]  {os.path.basename(path)}")
    return path


def gen_png_clean(out_dir: str) -> str:
    """
    Minimal valid PNG (1x1 pixel) — clean, no metadata, no steganography.
    Uses raw bytes to avoid PIL dependency in the generator itself.
    """
    import zlib, struct

    def _chunk(name: bytes, data: bytes) -> bytes:
        c = struct.pack(">I", len(data)) + name + data
        crc = struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)
        return c + crc

    r = random.randint(50, 200)
    g = random.randint(50, 200)
    b = random.randint(50, 200)

    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    raw_row   = b"\x00" + bytes([r, g, b])
    idat_data = zlib.compress(raw_row)
    png = b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr_data) + _chunk(b"IDAT", idat_data) + _chunk(b"IEND", b"")
    path = os.path.join(out_dir, f"field_image_{TS}.png")
    with open(path, "wb") as f:
        f.write(png)
    print(f"  [CLEAN]  {os.path.basename(path)}")
    return path


def gen_threat_pdf(out_dir: str) -> str:
    """
    A file that looks like a PDF but contains a hidden JavaScript action.
    This will be caught by SANCTUM-X's threat scanner and quarantined.
    Demonstrates that the pipeline correctly blocks malicious payloads.
    """
    # Minimal PDF structure with /JS action — will trigger pdf_js_action YARA rule
    content = b"""%PDF-1.4
1 0 obj<</Type /Catalog /Pages 2 0 R /OpenAction 4 0 R>>endobj
2 0 obj<</Type /Pages /Kids [3 0 R] /Count 1>>endobj
3 0 obj<</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>>endobj
4 0 obj<</Type /Action /S /JavaScript /JS (app.alert("SANCTUM-X THREAT TEST");)>>endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000068 00000 n
0000000125 00000 n
0000000206 00000 n
trailer<</Size 5 /Root 1 0 R>>
startxref
300
%%EOF"""
    path = os.path.join(out_dir, f"THREAT_malicious_doc_{TS}.pdf")
    with open(path, "wb") as f:
        f.write(content)
    print(f"  [THREAT] {os.path.basename(path)}  <-- WILL BE QUARANTINED")
    return path


def gen_threat_script(out_dir: str) -> str:
    """
    A .txt file containing patterns matching reverse shell signatures.
    Will be flagged HIGH risk by keyword and pattern scanner.
    """
    content = f"""THREAT SIMULATION FILE — GENERATED BY generate_samples.py
This file contains patterns used to test SANCTUM-X threat detection.
It is NOT a real threat. Generated: {TS}

# The following patterns trigger YARA / keyword scanners:
# reverse_shell indicator:
socket.connect(("192.168.1.{random.randint(100,254)}", {random.randint(4000,9999)}))

# C2 beacon reference:
beacon: {_rid("C2", 10)}
callback: https://10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}/check

# Encoded payload stub:
eval(base64_decode("{_rid('payload', 32)}"))

END THREAT SIMULATION
"""
    path = os.path.join(out_dir, f"THREAT_suspicious_script_{TS}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  [THREAT] {os.path.basename(path)}  <-- WILL BE FLAGGED HIGH")
    return path


def gen_threat_csv(out_dir: str) -> str:
    """Roster CSV containing formula injection and suspicious beacon text."""
    path = os.path.join(out_dir, f"THREAT_formula_roster_{TS}.csv")
    rows = [
        {
            "Operator_ID": _rid("OP", 5),
            "Operator_Name": _rname(),
            "Assignment": _runit(),
            "Badge_State": "ACTIVE",
            "Remarks": "rotation confirmed",
        }
        for _ in range(5)
    ]
    rows.append({
        "Operator_ID": _rid("OP", 5),
        "Operator_Name": _rname(),
        "Assignment": _runit(),
        "Badge_State": "=CMD|' /C calc'!A0",
        "Remarks": "beacon: " + _rid("C2", 8),
    })
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"  [THREAT] {os.path.basename(path)}  <-- WILL BE FLAGGED / SANITIZED")
    return path


def gen_threat_json(out_dir: str) -> str:
    """Suspicious JSON with SSRF and LDAP injection indicators."""
    payload = {
        "device_id": _rid("NODE", 6),
        "submitted_utc": datetime.now(timezone.utc).isoformat(),
        "collector": _callsign(),
        "callback": f"http://169.254.{random.randint(1,254)}.{random.randint(1,254)}/sync",
        "query_filter": ")(|(uid=*)(userPassword=*))",
        "notes": [
            random.choice(INCIDENTS),
            "SSRF test route observed during ingest validation",
            f"internal redirect to 10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        ],
    }
    path = os.path.join(out_dir, f"THREAT_sensor_alert_{TS}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"  [THREAT] {os.path.basename(path)}  <-- WILL BE FLAGGED HIGH")
    return path


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SANCTUM-X demo asset generator")
    parser.add_argument("--out", default="uploads", help="Output directory (default: uploads/)")
    args = parser.parse_args()

    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)
    removed = _clear_previous_generated(out_dir)

    print(f"\n{'='*60}")
    print(f"  SANCTUM-X SAMPLE GENERATOR v2.2")
    print(f"  Run ID   : {TS}")
    print(f"  Seed     : {SEED}")
    print(f"  Output   : {out_dir}/")
    print(f"  Cleared  : {removed} previous generated file(s)")
    print(f"{'='*60}")

    files = []
    files.append(gen_txt(out_dir))
    files.append(gen_csv(out_dir))
    files.append(gen_json(out_dir))
    files.append(gen_brief_json(out_dir))
    files.append(gen_logistics_csv(out_dir))
    files.append(gen_png_clean(out_dir))
    files.append(gen_threat_pdf(out_dir))
    files.append(gen_threat_script(out_dir))
    files.append(gen_threat_csv(out_dir))
    files.append(gen_threat_json(out_dir))

    print(f"\n{'='*60}")
    print(f"  {len(files)} files generated in {out_dir}/")
    print(f"  4 clean assets   → will pass scan")
    print(f"  2 threat assets  → will be quarantined / flagged")
    print(f"  6 clean assets   -> should pass scan")
    print(f"  4 threat assets  -> should be flagged / quarantined")
    print(f"  Each run is unique (timestamp: {TS})")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
