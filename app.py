import os
import json
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

import firebase_admin
from firebase_admin import credentials, firestore

load_dotenv()

PORT = int(os.environ.get("PORT", "5000"))

cred = credentials.Certificate(json.loads(os.environ["FIREBASE_CREDENTIALS"]))
firebase_admin.initialize_app(cred)
db = firestore.client()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})


def now_utc():
    return datetime.now(timezone.utc)


def is_expired(doc):
    exp = doc.get("expiry")
    if not isinstance(exp, datetime):
        return False
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return now_utc() > exp


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/v1/validate")
def validate():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    body = request.get_json(silent=True) or {}
    key = (body.get("license_key") or "").strip()
    iid = (body.get("install_id") or "").strip()
    if len(key) < 3 or len(iid) < 10:
        return jsonify({"error": "Invalid key or install_id"}), 400

    lic_ref = db.collection("licenses").document(key)
    lic_snap = lic_ref.get()
    if not lic_snap.exists:
        return jsonify({"error": "License not found"}), 404

    lic = lic_snap.to_dict() or {}

    if not lic.get("created_at"):
        lic_ref.set({"created_at": firestore.SERVER_TIMESTAMP}, merge=True)

    if lic.get("revoked") is True:
        return jsonify({"error": "License revoked"}), 403

    if is_expired(lic):
        return jsonify({"error": "License expired"}), 403

    max_dev = max(1, int(lic.get("max_devices") or 1))

    dev_ref = lic_ref.collection("devices").document(iid)
    dev_snap = dev_ref.get()

    if dev_snap.exists:
        d = dev_snap.to_dict() or {}
        if d.get("active") is False:
            return jsonify({"error": "Device disabled"}), 403
        dev_ref.set({"last_seen": firestore.SERVER_TIMESTAMP}, merge=True)
        return jsonify({"valid": True})

    active = lic_ref.collection("devices").where(filter=firestore.FieldFilter("active", "==", True)).get()
    if len(active) >= max_dev:
        return jsonify({"error": f"Device limit reached ({max_dev})"}), 403

    dev_ref.set({
        "active": True,
        "first_seen": firestore.SERVER_TIMESTAMP,
        "last_seen": firestore.SERVER_TIMESTAMP,
    }, merge=True)
    lic_ref.set({"device_count": firestore.Increment(1)}, merge=True)

    return jsonify({"valid": True})


@app.post("/v1/log")
def receive_log():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    entry = request.get_json(silent=True) or {}
    uuid = entry.get("uuid") or "system"
    action = entry.get("action") or "unknown"

    doc = {
        "uuid": uuid,
        "action": action,
        "detail": entry.get("detail"),
        "url": entry.get("url"),
        "client_ts": entry.get("ts"),
        "server_ts": firestore.SERVER_TIMESTAMP,
    }

    db.collection("session_logs").add(doc)

    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, threaded=True)
