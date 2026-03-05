import os
import json
import time
import secrets
import hashlib
import hmac
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

import jwt
import firebase_admin
from firebase_admin import credentials, firestore


load_dotenv()

PORT = int(os.environ.get("PORT", "5000"))
EXEC_JWT_SECRET = os.environ.get("EXEC_JWT_SECRET", "")
EXEC_TTL_SECONDS = 600
TS_SKEW_SECONDS = 60
NONCE_TTL_SECONDS = 5 * 60

if not EXEC_JWT_SECRET or len(EXEC_JWT_SECRET) < 24:
    raise RuntimeError("Set EXEC_JWT_SECRET (long random string).")

firebase_credentials = os.environ.get("FIREBASE_CREDENTIALS", "").strip()
if not firebase_credentials:
    raise RuntimeError("Set FIREBASE_CREDENTIALS (service account JSON).")

cred = credentials.Certificate(json.loads(firebase_credentials))
firebase_admin.initialize_app(cred)
db = firestore.client()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})


def now_utc():
    return datetime.now(timezone.utc)


def normalize_license_key(k: str) -> str:
    return (k or "").strip()


def normalize_install_id(x: str) -> str:
    return (x or "").strip()


def get_license_doc(license_key: str):
    return db.collection("licenses").document(license_key)


def is_license_expired(doc_dict) -> bool:
    expiry = doc_dict.get("expiry")
    if not expiry:
        return False
    # Firestore returns a datetime for timestamp fields
    if isinstance(expiry, datetime):
        exp = expiry
    else:
        return False
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return now_utc() > exp


def issue_exec_token(license_key: str, install_id: str):
    iat = int(time.time())
    exp = iat + EXEC_TTL_SECONDS
    payload = {
        "lic": license_key,
        "dev": install_id,
        "iat": iat,
        "exp": exp,
        "type": "nova_exec",
    }
    token = jwt.encode(payload, EXEC_JWT_SECRET, algorithm="HS256")
    return token


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def b64url_to_bytes(s: str) -> bytes:
    # not needed for signatures; kept for future use
    import base64

    pad = "=" * ((4 - (len(s) % 4)) % 4)
    s2 = (s + pad).replace("-", "+").replace("_", "/")
    return base64.b64decode(s2)


def hmac_sha256_base64url(secret: str, msg: str) -> str:
    import base64

    mac = hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).digest()
    b64 = base64.b64encode(mac).decode("ascii")
    return b64.replace("+", "-").replace("/", "_").rstrip("=")


def require_json():
    if not request.is_json:
        return jsonify({"error": "Expected JSON body"}), 400
    return None


def get_device_docref(license_key: str, install_id: str):
    return get_license_doc(license_key).collection("devices").document(install_id)


def register_nonce(install_id: str, nonce: str):
    # Best-effort replay protection. Enable Firestore TTL on `expires_at` if desired.
    doc_id = f"{install_id}:{nonce}"
    ref = db.collection("nonces").document(doc_id)
    try:
        ref.create(
            {
                "install_id": install_id,
                "nonce": nonce,
                "expires_at": now_utc() + timedelta(seconds=NONCE_TTL_SECONDS),
                "created_at": firestore.SERVER_TIMESTAMP,
            }
        )
    except Exception as e:
        # If the doc already exists, Firestore will reject the create.
        msg = str(e).lower()
        if "already exists" in msg or "409" in msg or "conflict" in msg:
            raise ValueError("replay")
        raise


@app.get("/health")
def health():
    return jsonify({"ok": True, "ts": datetime.utcnow().isoformat() + "Z"})


@app.post("/v1/activate")
def activate():
    err = require_json()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    license_key = normalize_license_key(body.get("license_key"))
    install_id = normalize_install_id(body.get("install_id"))
    if len(license_key) < 10 or len(install_id) < 10:
        return jsonify({"error": "Invalid license_key or install_id"}), 400

    lic_ref = get_license_doc(license_key)
    lic_snap = lic_ref.get()
    if not lic_snap.exists:
        return jsonify({"error": "License not found"}), 404

    lic = lic_snap.to_dict() or {}
    # Fill in default fields so you only need to set `expiry` (and optionally `max_devices`) in Firestore UI.
    if not lic.get("created_at"):
        lic_ref.set({"created_at": firestore.SERVER_TIMESTAMP}, merge=True)
    if lic.get("revoked") is True:
        return jsonify({"error": "License revoked"}), 403
    if is_license_expired(lic):
        return jsonify({"error": "License expired"}), 403

    max_devices = int(lic.get("max_devices") or 1)
    if max_devices < 1:
        max_devices = 1

    device_ref = get_device_docref(license_key, install_id)
    device_snap = device_ref.get()
    if device_snap.exists:
        device = device_snap.to_dict() or {}
        if device.get("active") is False:
            return jsonify({"error": "Device disabled"}), 403

        # Reuse existing secret
        device_secret = device.get("device_secret") or ""
        if not device_secret:
            device_secret = secrets.token_urlsafe(32)
            device_ref.set(
                {"device_secret": device_secret, "active": True, "last_seen": firestore.SERVER_TIMESTAMP},
                merge=True,
            )

        exec_token = issue_exec_token(license_key, install_id)
        device_ref.set({"last_seen": firestore.SERVER_TIMESTAMP}, merge=True)
        return jsonify({"device_secret": device_secret, "exec_token": exec_token, "expires_in": EXEC_TTL_SECONDS})

    # New device: enforce max_devices
    active_devices = (
        lic_ref.collection("devices").where(filter=firestore.FieldFilter("active", "==", True)).get()
    )
    if len(active_devices) >= max_devices:
        return jsonify({"error": "Device limit reached"}), 403

    device_secret = secrets.token_urlsafe(32)
    device_ref.set(
        {
            "active": True,
            "device_secret": device_secret,
            "first_seen": firestore.SERVER_TIMESTAMP,
            "last_seen": firestore.SERVER_TIMESTAMP,
        },
        merge=True,
    )
    # Track how many devices ever activated this license (optional; starts from 0 automatically).
    lic_ref.set({"device_count": firestore.Increment(1)}, merge=True)

    exec_token = issue_exec_token(license_key, install_id)
    return jsonify({"device_secret": device_secret, "exec_token": exec_token, "expires_in": EXEC_TTL_SECONDS})


@app.post("/v1/token")
def token():
    err = require_json()
    if err:
        return err

    install_id_h = normalize_install_id(request.headers.get("x-nova-install-id"))
    ts_h = (request.headers.get("x-nova-ts") or "").strip()
    nonce_h = (request.headers.get("x-nova-nonce") or "").strip()
    sig_h = (request.headers.get("x-nova-signature") or "").strip()

    body = request.get_json(silent=True) or {}
    license_key = normalize_license_key(body.get("license_key"))
    install_id_b = normalize_install_id(body.get("install_id"))

    if not install_id_h or not ts_h or not nonce_h or not sig_h:
        return jsonify({"error": "Missing signature headers"}), 400
    if install_id_h != install_id_b:
        return jsonify({"error": "install_id mismatch"}), 400

    try:
        ts_ms = int(ts_h)
    except Exception:
        return jsonify({"error": "Invalid timestamp"}), 400

    now_ms = int(time.time() * 1000)
    if abs(now_ms - ts_ms) > (TS_SKEW_SECONDS * 1000):
        return jsonify({"error": "Timestamp out of range"}), 400

    if len(license_key) < 10 or len(install_id_h) < 10:
        return jsonify({"error": "Invalid license_key or install_id"}), 400

    # Replay protection (best-effort)
    try:
        register_nonce(install_id_h, nonce_h)
    except ValueError:
        return jsonify({"error": "Replay detected"}), 409
    except Exception:
        # If nonce system isn't configured, don't hard-fail for small-scale usage.
        pass

    lic_ref = get_license_doc(license_key)
    lic_snap = lic_ref.get()
    if not lic_snap.exists:
        return jsonify({"error": "License not found"}), 404
    lic = lic_snap.to_dict() or {}
    if lic.get("revoked") is True:
        return jsonify({"error": "License revoked"}), 403
    if is_license_expired(lic):
        return jsonify({"error": "License expired"}), 403

    device_ref = get_device_docref(license_key, install_id_h)
    device_snap = device_ref.get()
    if not device_snap.exists:
        return jsonify({"error": "Device not activated"}), 403
    device = device_snap.to_dict() or {}
    if device.get("active") is False:
        return jsonify({"error": "Device disabled"}), 403

    device_secret = device.get("device_secret") or ""
    if not device_secret:
        return jsonify({"error": "Device secret missing"}), 500

    raw_body = request.get_data(as_text=True) or ""
    # IMPORTANT: the extension hashes its exact JSON.stringify string.
    # Using the raw body here avoids any key-order / whitespace mismatches.
    body_hash = sha256_hex(raw_body)
    msg = f"{ts_h}\n{nonce_h}\nPOST\n/v1/token\n{body_hash}\n{install_id_h}"
    expected = hmac_sha256_base64url(device_secret, msg)

    if not hmac.compare_digest(expected, sig_h):
        return jsonify({"error": "Bad signature"}), 403

    device_ref.set({"last_seen": firestore.SERVER_TIMESTAMP}, merge=True)
    exec_token = issue_exec_token(license_key, install_id_h)
    return jsonify({"exec_token": exec_token, "expires_in": EXEC_TTL_SECONDS})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, threaded=True)

