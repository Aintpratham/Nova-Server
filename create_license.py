import os
import json
import argparse
from datetime import datetime, timedelta, timezone

import firebase_admin
from firebase_admin import credentials, firestore


def main():
    p = argparse.ArgumentParser(description="Create/update a license document in Firestore.")
    p.add_argument("license_key")
    p.add_argument("--max-devices", type=int, default=1)
    p.add_argument("--days", type=int, default=0, help="If >0, set expiry to now + days. If 0, no expiry field.")
    p.add_argument("--revoke", action="store_true", help="Set revoked=true")
    args = p.parse_args()

    fb = os.environ.get("FIREBASE_CREDENTIALS", "").strip()
    if not fb:
        raise SystemExit("Set FIREBASE_CREDENTIALS env var first.")

    if not firebase_admin._apps:
        firebase_admin.initialize_app(credentials.Certificate(json.loads(fb)))
    db = firestore.client()

    data = {"max_devices": max(1, int(args.max_devices)), "revoked": bool(args.revoke)}
    if args.days and args.days > 0:
        data["expiry"] = datetime.now(timezone.utc) + timedelta(days=int(args.days))

    db.collection("licenses").document(args.license_key.strip()).set(data, merge=True)
    print("OK:", args.license_key, data)


if __name__ == "__main__":
    main()

