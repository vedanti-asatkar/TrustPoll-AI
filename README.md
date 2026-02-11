# TrustPoll-AI
A decentralized, AI-fortified voting protocol for transparent campus governance.

## Current Auth Model
- Student registration: `@vit.edu` email + OTP + password
- Login: email + password
- No student wallet required
- Blockchain anchoring: one backend-controlled Algorand service wallet

## Fairness Index (AI Transparency Layer)
- Computes an election integrity score from:
  - tampering attempts detected
  - duplicate attempts blocked
  - abnormal timing clusters
  - suspicious IP clusters (if IP hashes are provided)
- Uses transparent formula:
  - `score = max(0, 100 - tampering_penalty - duplicate_penalty - timing_penalty - ip_penalty)`
- Generates deterministic computation hash and can anchor it on Algorand via backend service wallet.
- Admin endpoint:
  - `GET /admin/fairness-index?election_id=demo-1` (latest or live preview)
  - `POST /admin/fairness-index` with `{ "election_id": "demo-1", "anchor": true }`

## Insider Threat Detection And Governance Audit
- High-risk/critical admin events are logged in `admin_audit_log`.
- Critical/high events are hashed and anchored on Algorand (hash-only, no sensitive data).
- Tamper check compares anchored admin hashes vs DB records and flags:
  - `CRITICAL_ADMIN_LOG_TAMPERING`
- Governance compromise forces Fairness Index below `70%` and surfaces warning in published results.
- Endpoints:
  - `GET /admin/governance-audit?election_id=demo-1`
- Background monitor:
  - periodically retries anchoring pending HIGH/CRITICAL admin audit rows
  - periodically runs blockchain-vs-DB tampering detection
  - configure interval with `AUDIT_MONITOR_INTERVAL_SECONDS` (default `300`)

## Run With Algorand TestNet

### 1) Backend env
Use `backend/.env.testnet.example` as reference and set:

- `DATABASE_URL=<postgres connection string>`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_EMAIL`, `SMTP_PASSWORD`
- `ALGOD_ADDRESS=https://testnet-api.algonode.cloud`
- `INDEXER_ADDRESS=https://testnet-idx.algonode.cloud`
- `ANCHOR_SENDER=<funded testnet wallet>`
- `ANCHOR_MNEMONIC=<25-word mnemonic>` (or `ANCHOR_PRIVATE_KEY`)
- `USER_HASH_SALT=<long random secret>`

### 2) Start backend
```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Backend runs on `http://localhost:5000`.

### 3) Start frontend
```powershell
cd trustpoll-frontend
npm install
npm run dev
```

Frontend runs on `http://localhost:3000`.

### 4) Funding estimate
Each anchor is a 0-ALGO self-payment with network fee (`~0.001 ALGO/tx`).
With `10 ALGO`, you can typically support around `9,800-9,900` anchored vote events.
