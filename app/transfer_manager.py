"""
transfer_manager.py  —  v2.0
-----------------------------
AES-256-GCM authenticated encryption for transfer bundles.
- Fernet (AES-128-CBC + HMAC) upgraded to AES-256-GCM (authenticated encryption)
- PBKDF2-derived key option for passphrase-based encryption
- Bundle signing with HMAC-SHA512
- Full manifest with per-file SHA-256 + MD5 dual hashing
- Decryption with integrity pre-check
"""

import hashlib
import hmac
import io
import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    import os as _os
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

BUNDLE_VERSION = "2.0"


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _md5_file(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """Derive AES-256 key from passphrase using PBKDF2-SHA256 (310,000 iterations)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=310_000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _hmac_sign(key: bytes, data: bytes) -> str:
    """HMAC-SHA512 signature for bundle integrity."""
    return hmac.new(key, data, hashlib.sha512).hexdigest()


def create_bundle(
    sanitized_files: List[str],
    out_dir: str,
    bundle_name: Optional[str] = None,
    passphrase: Optional[str] = None,
) -> dict:
    """
    Create an AES-256-GCM authenticated encrypted transfer bundle.

    Parameters
    ----------
    sanitized_files : list of absolute paths to sanitized files
    out_dir         : output directory
    bundle_name     : optional name override
    passphrase      : if provided, derive key from passphrase; else random key

    Returns
    -------
    dict with bundle_path, key_path, manifest, sha256_bundle, hmac_signature
    """
    os.makedirs(out_dir, exist_ok=True)
    ts   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = bundle_name or f"bundle_{ts}"

    # ── 1. Build rich manifest ─────────────────────────────────────────────
    manifest = {
        "version":      BUNDLE_VERSION,
        "created_utc":  ts,
        "file_count":   len(sanitized_files),
        "encryption":   "AES-256-GCM" if HAS_CRYPTO else "none",
        "kdf":          "PBKDF2-SHA256-310k" if passphrase else "random",
        "files": []
    }

    for fp in sanitized_files:
        stat = os.stat(fp)
        manifest["files"].append({
            "name":        os.path.basename(fp),
            "sha256":      _sha256_file(fp),
            "md5":         _md5_file(fp),
            "size_bytes":  stat.st_size,
        })

    manifest_json = json.dumps(manifest, indent=2).encode("utf-8")

    # ── 2. Pack into ZIP in memory ─────────────────────────────────────────
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for fp in sanitized_files:
            zf.write(fp, arcname=os.path.basename(fp))
        zf.writestr(f"{name}_manifest.json", manifest_json)
    zip_bytes = zip_buf.getvalue()

    # ── 3. Encrypt with AES-256-GCM ───────────────────────────────────────
    encrypted_path = os.path.join(out_dir, f"{name}.enc")
    key_path       = os.path.join(out_dir, f"{name}.key")
    key_info       = {}

    if HAS_CRYPTO:
        nonce = _os.urandom(12)  # 96-bit nonce for GCM

        if passphrase:
            salt = _os.urandom(32)
            key  = _derive_key_from_passphrase(passphrase, salt)
            key_info["type"]       = "pbkdf2"
            key_info["salt_hex"]   = salt.hex()
            key_info["iterations"] = 310_000
            key_info["algorithm"]  = "PBKDF2-SHA256"
        else:
            key  = _os.urandom(32)  # AES-256
            salt = None
            key_info["type"]    = "random"
            key_info["key_hex"] = key.hex()

        aesgcm    = AESGCM(key)
        aad       = b"secure-sanitization-framework-v2"  # Additional authenticated data
        ciphertext = aesgcm.encrypt(nonce, zip_bytes, aad)

        # Bundle format: [version(1)] [nonce(12)] [ciphertext+tag]
        bundle_data = b"\x02" + nonce + ciphertext

        # HMAC-SHA512 over entire bundle (authenticate before encrypt for detached sig)
        hmac_sig = _hmac_sign(key, bundle_data)
        key_info["hmac_sha512"] = hmac_sig
        key_info["bundle_version"] = BUNDLE_VERSION

        with open(encrypted_path, "wb") as f:
            f.write(bundle_data)

        with open(key_path, "w") as f:
            json.dump(key_info, f, indent=2)

        bundle_path = encrypted_path
    else:
        # Fallback: plain ZIP
        plain_path = os.path.join(out_dir, f"{name}.zip")
        with open(plain_path, "wb") as f:
            f.write(zip_bytes)
        bundle_path = plain_path
        key_path    = None
        hmac_sig    = None

    sha256_bundle = _sha256_file(bundle_path)
    manifest["bundle_sha256"] = sha256_bundle
    if HAS_CRYPTO:
        manifest["bundle_hmac_sha512"] = hmac_sig

    return {
        "bundle_path":   bundle_path,
        "key_path":      key_path,
        "manifest":      manifest,
        "sha256_bundle": sha256_bundle,
        "encrypted":     HAS_CRYPTO,
        "algorithm":     "AES-256-GCM" if HAS_CRYPTO else "none",
        "hmac_signature": hmac_sig if HAS_CRYPTO else None,
        "file_count":    len(sanitized_files),
    }


def decrypt_bundle(bundle_path: str, key_path: str, out_dir: str,
                   passphrase: Optional[str] = None) -> List[str]:
    """
    Decrypt and verify a bundle on the receiving side.
    Verifies HMAC before decryption (authenticate-then-decrypt).

    Returns list of extracted file paths.
    """
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography package not installed")

    os.makedirs(out_dir, exist_ok=True)

    with open(key_path, "r") as f:
        key_info = json.load(f)

    with open(bundle_path, "rb") as f:
        bundle_data = f.read()

    # Reconstruct key
    if key_info["type"] == "pbkdf2":
        if not passphrase:
            raise ValueError("Passphrase required for PBKDF2-derived key")
        salt = bytes.fromhex(key_info["salt_hex"])
        key  = _derive_key_from_passphrase(passphrase, salt)
    else:
        key = bytes.fromhex(key_info["key_hex"])

    # Verify HMAC before decryption
    expected_hmac = key_info.get("hmac_sha512", "")
    computed_hmac = _hmac_sign(key, bundle_data)
    if not hmac.compare_digest(expected_hmac, computed_hmac):
        raise ValueError("HMAC verification FAILED — bundle has been tampered with!")

    # Decrypt
    version = bundle_data[0]
    if version != 2:
        raise ValueError(f"Unknown bundle version: {version}")

    nonce      = bundle_data[1:13]
    ciphertext = bundle_data[13:]
    aad        = b"secure-sanitization-framework-v2"

    aesgcm   = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)  # raises on tamper

    extracted = []
    with zipfile.ZipFile(io.BytesIO(plaintext), "r") as zf:
        zf.extractall(out_dir)
        extracted = [os.path.join(out_dir, n) for n in zf.namelist()]

    return extracted


def verify_bundle_integrity(bundle_path: str, key_path: str,
                             passphrase: Optional[str] = None) -> dict:
    """
    Verify bundle HMAC without fully decrypting.
    Returns dict with verified, algorithm, details.
    """
    try:
        with open(key_path, "r") as f:
            key_info = json.load(f)
        with open(bundle_path, "rb") as f:
            bundle_data = f.read()

        if key_info["type"] == "pbkdf2":
            if not passphrase:
                return {"verified": False, "error": "Passphrase required"}
            salt = bytes.fromhex(key_info["salt_hex"])
            key  = _derive_key_from_passphrase(passphrase, salt)
        else:
            key = bytes.fromhex(key_info["key_hex"])

        expected = key_info.get("hmac_sha512", "")
        computed = _hmac_sign(key, bundle_data)
        verified = hmac.compare_digest(expected, computed)

        return {
            "verified":   verified,
            "algorithm":  "HMAC-SHA512 + AES-256-GCM",
            "bundle_sha256": _sha256_file(bundle_path),
            "tampered":   not verified,
        }
    except Exception as e:
        return {"verified": False, "error": str(e)}