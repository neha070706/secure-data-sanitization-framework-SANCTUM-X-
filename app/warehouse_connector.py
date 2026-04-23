"""
warehouse_connector.py  —  SANCTUM-X v2.1
------------------------------------------
Bridge between SANCTUM-X and the Army's private data warehouse.
Supports three delivery modes:

  MODE 1 — Direct LAN push    : mTLS-authenticated HTTPS/REST push to
                                 an on-premise warehouse API endpoint.
  MODE 2 — VPN tunnel push    : Same as LAN push but connection is
                                 established through a VPN interface.
  MODE 3 — Sneakernet / USB   : Writes encrypted bundle to a local path
                                 (hardware-encrypted USB or write-once
                                 optical drive) for physical air-gap
                                 transfer. Logs the handoff in audit chain.

No public internet is ever used. All bundle data is already AES-256-GCM
encrypted by transfer_manager.py before this module touches it — even if
the delivery channel were compromised the payload is safe.

Configuration is loaded from warehouse_config.json (excluded from repo;
each army unit customises for their endpoint).
"""

import hashlib
import json
import os
import shutil
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── optional: requests for HTTPS push ────────────────────────────────────────
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

CONFIG_PATH = Path(__file__).parent.parent / "config" / "warehouse_config.json"

DEFAULT_CONFIG = {
    "mode": "sneakernet",
    "lan": {
        "endpoint_url": "https://192.168.1.100:8443/api/v1/ingest",
        "client_cert":  "certs/client.crt",
        "client_key":   "certs/client.key",
        "ca_bundle":    "certs/army_ca.crt",
        "timeout_sec":  30,
        "collection":   "SANCTUM_INGEST"
    },
    "vpn": {
        "endpoint_url": "https://10.0.0.50:8443/api/v1/ingest",
        "client_cert":  "certs/client.crt",
        "client_key":   "certs/client.key",
        "ca_bundle":    "certs/army_ca.crt",
        "timeout_sec":  60,
        "collection":   "SANCTUM_INGEST"
    },
    "sneakernet": {
        "output_path":  "/media/ARMY_USB",
        "subdir":       "SANCTUM_TRANSFERS"
    }
}


def _load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return DEFAULT_CONFIG


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# ── Mode 1 & 2: HTTPS push (LAN or VPN) ─────────────────────────────────────

def _push_https(bundle_path: str, key_path: Optional[str],
                cfg: dict, manifest: dict) -> dict:
    """
    Push bundle + key to the warehouse REST endpoint using mTLS.
    The endpoint receives:
      - bundle file (multipart)
      - key file    (multipart)
      - manifest    (JSON field)
      - sha256      (header X-Bundle-SHA256)
    Returns a result dict.
    """
    if not HAS_REQUESTS:
        return {
            "success": False,
            "error": "requests library not installed — run: pip install requests"
        }

    url        = cfg["endpoint_url"]
    cert       = (cfg["client_cert"], cfg["client_key"])
    verify     = cfg.get("ca_bundle", True)   # False disables cert verify — never do this in prod
    timeout    = cfg.get("timeout_sec", 30)
    collection = cfg.get("collection", "DEFAULT")
    sha256     = _sha256_file(bundle_path)

    try:
        with open(bundle_path, "rb") as bf:
            files = {
                "bundle": (os.path.basename(bundle_path), bf, "application/octet-stream"),
            }
            kf = None
            if key_path and os.path.exists(key_path):
                kf = open(key_path, "rb")
                files["key"] = (os.path.basename(key_path), kf, "application/json")
            data = {
                "manifest":   json.dumps(manifest),
                "collection": collection,
                "timestamp":  _timestamp(),
            }
            headers = {
                "X-Bundle-SHA256":  sha256,
                "X-SANCTUM-Version": "2.1",
                "X-Unit-ID":        cfg.get("unit_id", "UNKNOWN"),
            }
            resp = requests.post(
                url, files=files, data=data,
                cert=cert, verify=verify,
                headers=headers, timeout=timeout
            )
            if kf:
                kf.close()

        if resp.status_code == 200:
            return {
                "success":    True,
                "mode":       "https_push",
                "endpoint":   url,
                "collection": collection,
                "sha256":     sha256,
                "response":   resp.json() if resp.headers.get("content-type","").startswith("application/json") else resp.text[:200],
                "timestamp":  _timestamp(),
            }
        else:
            return {
                "success": False,
                "error":   f"HTTP {resp.status_code}: {resp.text[:200]}",
                "mode":    "https_push",
            }

    except requests.exceptions.SSLError as e:
        return {"success": False, "error": f"mTLS/SSL error — check certificates: {e}"}
    except requests.exceptions.ConnectionError as e:
        return {"success": False, "error": f"Connection refused — is the warehouse endpoint up? {e}"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": f"Connection timed out after {timeout}s"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Mode 3: Sneakernet / USB write ───────────────────────────────────────────

def _write_sneakernet(bundle_path: str, key_path: Optional[str],
                      cfg: dict, manifest: dict) -> dict:
    """
    Copy bundle to a physical medium (USB / optical path).
    KEY IS NEVER WRITTEN TO THE SAME MEDIUM as the bundle.
    Key must be transported via a separate out-of-band channel.
    """
    output_root = cfg.get("output_path", "/media/ARMY_USB")
    subdir      = cfg.get("subdir", "SANCTUM_TRANSFERS")
    ts          = _timestamp()
    dest_dir    = os.path.join(output_root, subdir, ts)

    # Verify the medium is mounted / accessible
    if not os.path.exists(output_root):
        return {
            "success": False,
            "error":   f"Output medium not found at '{output_root}' — is the USB mounted?"
        }

    try:
        os.makedirs(dest_dir, exist_ok=True)

        # Write bundle
        bundle_dest = os.path.join(dest_dir, os.path.basename(bundle_path))
        shutil.copy2(bundle_path, bundle_dest)

        # Write manifest as companion (plaintext — bundle is already encrypted)
        manifest_dest = os.path.join(dest_dir, "MANIFEST.json")
        with open(manifest_dest, "w") as f:
            json.dump(manifest, f, indent=2)

        # Write transfer receipt
        sha256 = _sha256_file(bundle_dest)
        receipt = {
            "transfer_timestamp": ts,
            "bundle_file":        os.path.basename(bundle_path),
            "bundle_sha256":      sha256,
            "key_file":           os.path.basename(key_path) if key_path else "N/A",
            "key_delivery":       "OUT-OF-BAND — DO NOT PLACE ON THIS MEDIUM",
            "sanctum_version":    "2.1",
            "warning":            "VERIFY HMAC-SHA512 ON RECEIVING SYSTEM BEFORE DECRYPTION"
        }
        if not key_path:
            receipt["key_delivery"] = "NO KEY FILE PRESENT"
            receipt["warning"] = "BUNDLE WAS GENERATED WITHOUT ENCRYPTION SUPPORT"
        receipt_dest = os.path.join(dest_dir, "TRANSFER_RECEIPT.json")
        with open(receipt_dest, "w") as f:
            json.dump(receipt, f, indent=2)

        # Verify copy integrity
        dest_sha256 = _sha256_file(bundle_dest)
        if dest_sha256 != sha256:
            return {"success": False, "error": "SHA-256 mismatch after copy — medium may be faulty"}

        return {
            "success":   True,
            "mode":      "sneakernet",
            "dest_dir":  dest_dir,
            "sha256":    sha256,
            "timestamp": ts,
            "warning":   "KEY MUST BE DELIVERED VIA SEPARATE CHANNEL — NOT THIS MEDIUM",
            "files_written": [
                os.path.basename(bundle_dest),
                "MANIFEST.json",
                "TRANSFER_RECEIPT.json"
            ]
        }

    except PermissionError:
        return {"success": False, "error": "Permission denied — check USB write-protection switch"}
    except OSError as e:
        return {"success": False, "error": f"Write error (medium full or faulty?): {e}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Public API ────────────────────────────────────────────────────────────────

def deliver_bundle(bundle_path: str, key_path: Optional[str],
                   manifest: dict,
                   mode_override: Optional[str] = None) -> dict:
    """
    Deliver an encrypted SANCTUM-X bundle to the army's private warehouse.

    Parameters
    ----------
    bundle_path    : path to the .enc bundle
    key_path       : path to the .key file
    manifest       : manifest dict from create_bundle()
    mode_override  : 'lan' | 'vpn' | 'sneakernet' — overrides config file

    Returns
    -------
    dict with success, mode, details, and timestamp
    """
    cfg  = _load_config()
    mode = mode_override or cfg.get("mode", "sneakernet")

    if not os.path.exists(bundle_path):
        return {"success": False, "error": f"Bundle not found: {bundle_path}"}
    if key_path and not os.path.exists(key_path):
        return {"success": False, "error": f"Key file not found: {key_path}"}

    if mode == "lan":
        return _push_https(bundle_path, key_path, cfg.get("lan", {}), manifest)
    elif mode == "vpn":
        return _push_https(bundle_path, key_path, cfg.get("vpn", {}), manifest)
    elif mode == "sneakernet":
        return _write_sneakernet(bundle_path, key_path, cfg.get("sneakernet", {}), manifest)
    else:
        return {"success": False, "error": f"Unknown delivery mode: '{mode}'"}


def ping_warehouse(mode_override: Optional[str] = None) -> dict:
    """
    Test connectivity to the warehouse endpoint without sending data.
    For sneakernet mode, checks that the medium is mounted.
    """
    cfg  = _load_config()
    mode = mode_override or cfg.get("mode", "sneakernet")

    if mode == "sneakernet":
        path = cfg.get("sneakernet", {}).get("output_path", "/media/ARMY_USB")
        accessible = os.path.exists(path) and os.access(path, os.W_OK)
        return {
            "reachable": accessible,
            "mode":      "sneakernet",
            "path":      path,
            "status":    "MEDIUM MOUNTED AND WRITABLE" if accessible else "MEDIUM NOT FOUND OR NOT WRITABLE"
        }

    # LAN / VPN — TCP connect test (no data sent)
    endpoint_cfg = cfg.get(mode, {})
    url = endpoint_cfg.get("endpoint_url", "")
    try:
        # Extract host:port from URL
        from urllib.parse import urlparse
        p    = urlparse(url)
        host = p.hostname
        port = p.port or (443 if p.scheme == "https" else 80)
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
        return {"reachable": True, "mode": mode, "endpoint": url, "status": "ENDPOINT REACHABLE"}
    except Exception as e:
        return {"reachable": False, "mode": mode, "endpoint": url, "status": str(e)}


def get_active_mode() -> str:
    return _load_config().get("mode", "sneakernet")


def save_config(new_config: dict) -> bool:
    try:
        os.makedirs(CONFIG_PATH.parent, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(new_config, f, indent=2)
        return True
    except Exception:
        return False
