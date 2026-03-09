import os
import json
import time
import secrets
import hashlib
import hmac
import base64
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
EXEC_TTL = 600
TS_SKEW = 60
NONCE_TTL = 300

if not EXEC_JWT_SECRET or len(EXEC_JWT_SECRET) < 24:
    raise RuntimeError("Set EXEC_JWT_SECRET (long random string).")

cred = credentials.Certificate(json.loads(os.environ["FIREBASE_CREDENTIALS"]))
firebase_admin.initialize_app(cred)
db = firestore.client()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})


def now_utc():
    return datetime.now(timezone.utc)


def lic_ref(key):
    return db.collection("licenses").document(key.strip())


def dev_ref(key, iid):
    return lic_ref(key).collection("devices").document(iid.strip())


def is_expired(doc):
    exp = doc.get("expiry")
    if not isinstance(exp, datetime):
        return False
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return now_utc() > exp


def mint_token(key, iid):
    iat = int(time.time())
    return jwt.encode({"lic": key, "dev": iid, "iat": iat, "exp": iat + EXEC_TTL, "type": "nova_exec"}, EXEC_JWT_SECRET, algorithm="HS256")


def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


def hmac_b64url(secret, msg):
    mac = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
    return base64.b64encode(mac).decode().replace("+", "-").replace("/", "_").rstrip("=")


def check_nonce(iid, nonce):
    ref = db.collection("nonces").document(f"{iid}:{nonce}")
    try:
        ref.create({"expires_at": now_utc() + timedelta(seconds=NONCE_TTL), "created_at": firestore.SERVER_TIMESTAMP})
    except Exception as e:
        msg = str(e).lower()
        if "already exists" in msg or "409" in msg or "conflict" in msg:
            raise ValueError("replay")
        raise


def validate_license(key):
    ref = lic_ref(key)
    snap = ref.get()
    if not snap.exists:
        return None, ("License not found", 404)
    doc = snap.to_dict() or {}
    if not doc.get("created_at"):
        ref.set({"created_at": firestore.SERVER_TIMESTAMP}, merge=True)
    if doc.get("revoked") is True:
        return None, ("License revoked", 403)
    if is_expired(doc):
        return None, ("License expired", 403)
    return doc, None


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/v1/activate")
def activate():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    body = request.get_json(silent=True) or {}
    key = (body.get("license_key") or "").strip()
    iid = (body.get("install_id") or "").strip()
    if len(key) < 3 or len(iid) < 10:
        return jsonify({"error": "Invalid key or install_id"}), 400

    doc, err = validate_license(key)
    if err:
        return jsonify({"error": err[0]}), err[1]

    max_dev = max(1, int(doc.get("max_devices") or 1))
    dref = dev_ref(key, iid)
    dsnap = dref.get()

    if dsnap.exists:
        d = dsnap.to_dict() or {}
        if d.get("active") is False:
            return jsonify({"error": "Device disabled"}), 403
        ds = d.get("device_secret") or ""
        if not ds:
            ds = secrets.token_urlsafe(32)
            dref.set({"device_secret": ds, "active": True, "last_seen": firestore.SERVER_TIMESTAMP}, merge=True)
        else:
            dref.set({"last_seen": firestore.SERVER_TIMESTAMP}, merge=True)
        return jsonify({"device_secret": ds, "exec_token": mint_token(key, iid), "expires_in": EXEC_TTL})

    active = lic_ref(key).collection("devices").where(filter=firestore.FieldFilter("active", "==", True)).get()
    if len(active) >= max_dev:
        return jsonify({"error": "Device limit reached"}), 403

    ds = secrets.token_urlsafe(32)
    dref.set({"active": True, "device_secret": ds, "first_seen": firestore.SERVER_TIMESTAMP, "last_seen": firestore.SERVER_TIMESTAMP}, merge=True)
    lic_ref(key).set({"device_count": firestore.Increment(1)}, merge=True)
    return jsonify({"device_secret": ds, "exec_token": mint_token(key, iid), "expires_in": EXEC_TTL})


@app.post("/v1/token")
def token():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    iid_h = (request.headers.get("x-nova-install-id") or "").strip()
    ts_h = (request.headers.get("x-nova-ts") or "").strip()
    nonce_h = (request.headers.get("x-nova-nonce") or "").strip()
    sig_h = (request.headers.get("x-nova-signature") or "").strip()

    if not all([iid_h, ts_h, nonce_h, sig_h]):
        return jsonify({"error": "Missing signature headers"}), 400

    body = request.get_json(silent=True) or {}
    key = (body.get("license_key") or "").strip()
    iid_b = (body.get("install_id") or "").strip()

    if iid_h != iid_b:
        return jsonify({"error": "install_id mismatch"}), 400
    if len(key) < 3 or len(iid_h) < 10:
        return jsonify({"error": "Invalid key or install_id"}), 400

    try:
        ts_ms = int(ts_h)
    except Exception:
        return jsonify({"error": "Invalid timestamp"}), 400
    if abs(int(time.time() * 1000) - ts_ms) > TS_SKEW * 1000:
        return jsonify({"error": "Timestamp out of range"}), 400

    try:
        check_nonce(iid_h, nonce_h)
    except ValueError:
        return jsonify({"error": "Replay detected"}), 409
    except Exception:
        pass

    _, err = validate_license(key)
    if err:
        return jsonify({"error": err[0]}), err[1]

    dref = dev_ref(key, iid_h)
    dsnap = dref.get()
    if not dsnap.exists:
        return jsonify({"error": "Device not activated"}), 403
    d = dsnap.to_dict() or {}
    if d.get("active") is False:
        return jsonify({"error": "Device disabled"}), 403

    ds = d.get("device_secret") or ""
    if not ds:
        return jsonify({"error": "Device secret missing"}), 500

    raw = request.get_data(as_text=True) or ""
    msg = f"{ts_h}\n{nonce_h}\nPOST\n/v1/token\n{sha256_hex(raw)}\n{iid_h}"
    if not hmac.compare_digest(hmac_b64url(ds, msg), sig_h):
        return jsonify({"error": "Bad signature"}), 403

    dref.set({"last_seen": firestore.SERVER_TIMESTAMP}, merge=True)
    return jsonify({"exec_token": mint_token(key, iid_h), "expires_in": EXEC_TTL})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, threaded=True)
