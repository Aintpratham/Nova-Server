# nova-server

Minimal license + execution-token server for the Nova extension.

## Firestore structure

- Collection: `licenses`
  - Document ID: `<license_key>`
  - Fields:
    - `revoked`: boolean (default false)
    - `max_devices`: number (default 1)
    - `expiry`: Firestore timestamp (optional)

- Subcollection: `licenses/<license_key>/devices`
  - Document ID: `<install_id>`
  - Fields:
    - `active`: boolean (default true)
    - `device_secret`: string (random; returned to the extension on activation)
    - `first_seen`: timestamp
    - `last_seen`: timestamp

- Collection: `nonces` (optional replay protection)
  - Document ID: `<install_id>:<nonce>`
  - Fields:
    - `install_id`: string
    - `nonce`: string
    - `expires_at`: timestamp (enable Firestore TTL on this field if you want auto-cleanup)

## Endpoints

- `POST /v1/activate`
  - Body: `{ "license_key": "...", "install_id": "..." }`
  - Response: `{ "device_secret": "...", "exec_token": "...", "expires_in": 600 }`

- `POST /v1/token` (HMAC signed)
  - Headers:
    - `X-Nova-Install-Id`
    - `X-Nova-Ts` (ms since epoch)
    - `X-Nova-Nonce`
    - `X-Nova-Signature` (base64url)
  - Body: `{ "license_key": "...", "install_id": "..." }`
  - Response: `{ "exec_token": "...", "expires_in": 600 }`

Signature message format (must match extension):

```
{ts}\n{nonce}\nPOST\n/v1/token\n{bodySha256Hex}\n{install_id}
```

## Run locally

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python app.py
```

