from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify
from flask_cors import CORS
from db import get_connection, release_connection
from ai import analyze_vote
from algorand_anchor import anchor_decision_hash, fetch_tx_note, count_wallet_anchors
from consensus import run_consensus
import psycopg2
from datetime import datetime, timedelta
from email_service import send_verification_otp
import random


app = Flask(__name__)
CORS(app)

OTP_STORE = {}
OTP_EXPIRY_MINUTES = 10
OTP_MAX_ATTEMPTS = 3
OTP_RESEND_COOLDOWN_SECONDS = 30


def ensure_schema():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                wallet TEXT UNIQUE NOT NULL,
                blocked_until TIMESTAMP,
                email_verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS candidates (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS votes (
                id SERIAL PRIMARY KEY,
                candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
                wallet TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS vote_attempts (
                id SERIAL PRIMARY KEY,
                wallet TEXT NOT NULL,
                election_id TEXT,
                result TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS ai_flags (
                id SERIAL PRIMARY KEY,
                wallet TEXT NOT NULL,
                reason TEXT NOT NULL,
                severity INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS ai_decisions (
                id SERIAL PRIMARY KEY,
                email TEXT,
                wallet TEXT NOT NULL,
                has_voted BOOLEAN DEFAULT FALSE,
                decision TEXT NOT NULL,
                risk_score NUMERIC(3,2) NOT NULL,
                rules_triggered TEXT[] NOT NULL,
                model_version TEXT NOT NULL,
                payload_json JSONB NOT NULL,
                payload_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS consensus_votes (
                id SERIAL PRIMARY KEY,
                wallet TEXT NOT NULL,
                validator TEXT NOT NULL,
                verdict TEXT NOT NULL,
                decision_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS consensus_results (
                id SERIAL PRIMARY KEY,
                wallet TEXT NOT NULL,
                decision_hash TEXT NOT NULL,
                final_verdict TEXT NOT NULL,
                votes_json JSONB NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS results_publication (
                id INTEGER PRIMARY KEY,
                published BOOLEAN DEFAULT FALSE,
                published_at TIMESTAMP
            );
        """)
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked_until TIMESTAMP;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS has_voted BOOLEAN DEFAULT FALSE;")
        cur.execute("ALTER TABLE votes ADD COLUMN IF NOT EXISTS email TEXT;")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS votes_wallet_unique ON votes(wallet);")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS votes_email_unique ON votes(email) WHERE email IS NOT NULL;")
        cur.execute("ALTER TABLE ai_decisions ADD COLUMN IF NOT EXISTS email TEXT;")
        cur.execute("ALTER TABLE ai_decisions ADD COLUMN IF NOT EXISTS has_voted BOOLEAN DEFAULT FALSE;")
        cur.execute("ALTER TABLE ai_decisions ADD COLUMN IF NOT EXISTS algorand_tx_id TEXT;")
        # Normalize election_id to TEXT to allow human-friendly IDs in demos/tests.
        cur.execute("ALTER TABLE vote_attempts ALTER COLUMN election_id TYPE TEXT USING election_id::text;")
        cur.execute("INSERT INTO results_publication (id, published) VALUES (1, FALSE) ON CONFLICT (id) DO NOTHING;")
        conn.commit()
    finally:
        cur.close()
        release_connection(conn)

def is_valid_vit_email(email):
    return isinstance(email, str) and email.endswith("@vit.edu")

def _otp_key(email, wallet):
    return f"{email}|{wallet}"


@app.route("/register/start", methods=["POST"])
def register_start():
    data = request.json or {}
    email = data.get("email")
    raw_wallet = data.get("wallet")
    wallet = raw_wallet.strip().upper() if isinstance(raw_wallet, str) else None

    if not is_valid_vit_email(email):
        return jsonify({"error": "Only @vit.edu emails are allowed."}), 400
    if not wallet:
        return jsonify({"error": "Wallet is required."}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT 1 FROM users WHERE wallet = %s", (wallet,))
        if cur.fetchone():
            return jsonify({"error": "Wallet already registered"}), 409
        cur.execute("SELECT 1 FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            return jsonify({"error": "Email already registered"}), 409
    finally:
        cur.close()
        release_connection(conn)

    key = _otp_key(email, wallet)
    now = datetime.utcnow()
    existing = OTP_STORE.get(key)
    if existing and existing.get("last_sent"):
        cooldown_until = existing["last_sent"] + timedelta(seconds=OTP_RESEND_COOLDOWN_SECONDS)
        if now < cooldown_until:
            return jsonify({"error": "Please wait before requesting another code."}), 429

    otp = f"{random.randint(0, 999999):06d}"
    OTP_STORE[key] = {
        "otp": otp,
        "expires_at": now + timedelta(minutes=OTP_EXPIRY_MINUTES),
        "attempts": 0,
        "last_sent": now,
    }

    send_verification_otp(email, otp)
    return jsonify({"message": "Verification code sent"}), 200


@app.route("/register/verify", methods=["POST"])
def register_verify():
    data = request.json or {}
    email = data.get("email")
    raw_wallet = data.get("wallet")
    wallet = raw_wallet.strip().upper() if isinstance(raw_wallet, str) else None
    otp = data.get("otp")

    key = _otp_key(email, wallet)
    record = OTP_STORE.get(key)
    if not record:
        return jsonify({"error": "Verification code not found. Please request a new code."}), 400

    if record["attempts"] >= OTP_MAX_ATTEMPTS:
        return jsonify({"error": "Too many attempts. Please request a new code."}), 429

    if datetime.utcnow() > record["expires_at"]:
        return jsonify({"error": "Verification code expired. Please request a new code."}), 400

    if otp != record["otp"]:
        record["attempts"] += 1
        return jsonify({"error": "Invalid verification code."}), 400

    conn = None
    cur = None
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (email, wallet, email_verified) VALUES (%s, %s, %s)",
            (email, wallet, True)
        )
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        if conn:
            conn.rollback()
        return jsonify({"error": "Email or wallet already registered"}), 409
    except Exception:
        if conn:
            conn.rollback()
        return jsonify({"error": "Database error"}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            release_connection(conn)

    OTP_STORE.pop(key, None)
    return jsonify({"message": "Email verified and registration complete"}), 200


@app.route("/register", methods=["POST"])
def register():
    return jsonify({"error": "Use /register/start and /register/verify for email verification."}), 410


@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email")
    wallet = data.get("wallet")

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT blocked_until, email_verified FROM users WHERE email = %s AND wallet = %s", (email, wallet))
        user = cur.fetchone()
        if user:
            blocked_until, email_verified = user
            if blocked_until and blocked_until > datetime.utcnow():
                return jsonify({"error": "Account temporarily blocked. Please try again later."}), 403
            if not email_verified:
                return jsonify({"error": "Please verify your email before logging in."}), 403
            return jsonify({"message": "Login successful"})
        return jsonify({"error": "Invalid credentials"}), 401
    finally:
        cur.close()
        release_connection(conn)


@app.route("/candidates", methods=["GET"])
def get_candidates():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, name FROM candidates ORDER BY name")
        rows = cur.fetchall()
        return jsonify([{"id": r[0], "name": r[1]} for r in rows])
    finally:
        cur.close()
        release_connection(conn)


@app.route("/vote", methods=["POST"])
def vote():
    data = request.json or {}
    email = data.get("email")
    wallet = data.get("wallet")
    candidate_id = data.get("candidate_id")

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT blocked_until, email_verified, has_voted FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
        blocked_until, email_verified, has_voted = user
        if blocked_until and blocked_until > datetime.utcnow():
            return jsonify({"error": "Account temporarily blocked. Please try again later."}), 403
        if not email_verified:
            return jsonify({"error": "Please verify your email before voting."}), 403
        if has_voted:
            return jsonify({"error": "You have already voted"}), 400

        cur.execute(
            """
            INSERT INTO votes (candidate_id, wallet, email)
            VALUES (%s, %s, %s)
            ON CONFLICT (email) DO NOTHING
            """,
            (candidate_id, wallet, email),
        )
        if cur.rowcount == 0:
            return jsonify({"error": "You have already voted"}), 400
        cur.execute("UPDATE users SET has_voted = TRUE WHERE email = %s", (email,))
        conn.commit()
        return jsonify({"message": "Vote cast successfully"})
    finally:
        cur.close()
        release_connection(conn)


@app.route("/vote-attempt", methods=["POST"])
def vote_attempt():
    data = request.json or {}
    email = data.get("email")
    wallet = data.get("wallet")
    election_id = data.get("election_id")

    if not email:
        return jsonify({
            "status": "rejected",
            "reason": "Email is required",
            "integrity_status": "OK",
        }), 400

    # Integrity check: compare DB vote record vs on-chain anchors
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT email_verified, has_voted, wallet FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
    finally:
        cur.close()
        release_connection(conn)

    if not user:
        return jsonify({
            "status": "rejected",
            "reason": "User not found",
            "integrity_status": "OK",
        }), 404

    email_verified, has_voted, user_wallet = user
    if not email_verified:
        return jsonify({
            "status": "rejected",
            "reason": "Email not verified",
            "integrity_status": "OK",
        }), 403
    if has_voted:
        return jsonify({
            "status": "rejected",
            "reason": "Email already voted",
            "integrity_status": "OK",
        }), 409

    chain_anchor_count = count_wallet_anchors(user_wallet)
    blockchain_anchor_exists = chain_anchor_count > 0

    if not has_voted and blockchain_anchor_exists:
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO ai_flags (wallet, reason, severity) VALUES (%s, %s, %s)",
                (user_wallet, "CRITICAL_TAMPERING", 10),
            )
            conn.commit()
        finally:
            cur.close()
            release_connection(conn)
        return jsonify({
            "status": "rejected",
            "reason": "On-chain history exists but DB record is missing",
            "integrity_status": "CRITICAL_TAMPERING",
        }), 409

    if has_voted and not blockchain_anchor_exists:
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO ai_flags (wallet, reason, severity) VALUES (%s, %s, %s)",
                (user_wallet, "INCONSISTENT_STATE", 7),
            )
            conn.commit()
        finally:
            cur.close()
            release_connection(conn)
        return jsonify({
            "status": "rejected",
            "reason": "DB record exists but no on-chain anchor found",
            "integrity_status": "INCONSISTENT_STATE",
        }), 409

    if chain_anchor_count > 1:
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO ai_flags (wallet, reason, severity) VALUES (%s, %s, %s)",
                (user_wallet, "DOUBLE_VOTE_ON_CHAIN", 9),
            )
            conn.commit()
        finally:
            cur.close()
            release_connection(conn)
        return jsonify({
            "status": "rejected",
            "reason": "Multiple on-chain anchors detected for wallet",
            "integrity_status": "DOUBLE_VOTE_ON_CHAIN",
        }), 409

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT COUNT(*)
            FROM vote_attempts
            WHERE wallet = %s
            AND timestamp > NOW() - INTERVAL '5 minutes'
        """, (wallet,))
        vote_attempt_count = cur.fetchone()[0]

        cur.execute("""
            SELECT EXTRACT(EPOCH FROM (NOW() - MAX(timestamp)))
            FROM vote_attempts
            WHERE wallet = %s
        """, (wallet,))
        time_between = cur.fetchone()[0]
    finally:
        cur.close()
        release_connection(conn)

    metadata = {
        "email": email,
        "has_voted": has_voted,
        "wallet": user_wallet,
        "vote_attempt_count": int(vote_attempt_count),
        "time_between_attempts_sec": int(time_between or 999999),
        "ip_hash": data.get("ip_hash", "unknown"),
        "device_fingerprint_hash": data.get("device_fingerprint_hash", "unknown"),
        "election_id": election_id,
        "candidate_id": data.get("candidate_id"),
        "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    }

    decision_payload, payload_hash = analyze_vote(metadata)
    consensus_verdict, validators, validators_json = run_consensus(
        decision_payload["decision"], metadata
    )
    algorand_tx_id = None
    try:
        algorand_tx_id = anchor_decision_hash(payload_hash, sender_wallet=wallet)
    except Exception:
        algorand_tx_id = None

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO vote_attempts (wallet, election_id, result)
            VALUES (%s, %s, %s)
        """, (user_wallet, election_id, "flagged" if consensus_verdict != "ALLOW" else "ok"))

        if consensus_verdict != "ALLOW":
            cur.execute("""
                INSERT INTO ai_flags (wallet, reason, severity)
                VALUES (%s, %s, %s)
            """, (user_wallet, "Automated risk detection", 7))

        for name, data in validators.items():
            cur.execute(
                "INSERT INTO consensus_votes (wallet, validator, verdict, decision_hash) VALUES (%s, %s, %s, %s)",
                (user_wallet, name, data["verdict"], payload_hash),
            )
        cur.execute(
            "INSERT INTO consensus_results (wallet, decision_hash, final_verdict, votes_json) VALUES (%s, %s, %s, %s)",
            (user_wallet, payload_hash, consensus_verdict, validators_json),
        )

        if algorand_tx_id:
            cur.execute(
                "UPDATE ai_decisions SET algorand_tx_id = %s WHERE payload_hash = %s",
                (algorand_tx_id, payload_hash),
            )

        if consensus_verdict == "ALLOW":
            cur.execute("UPDATE users SET has_voted = TRUE WHERE email = %s", (email,))

        conn.commit()
        return jsonify({
            "status": "accepted" if consensus_verdict == "ALLOW" else "rejected",
            "reason": "Risk evaluation completed",
            "integrity_status": "OK",
            "decision": decision_payload,
            "decision_hash": payload_hash,
            "algorand_tx_id": algorand_tx_id,
            "consensus": {
                "final_verdict": consensus_verdict,
                "validators": validators,
            }
        })
    finally:
        cur.close()
        release_connection(conn)


@app.route("/admin/add-candidate", methods=["POST"])
def add_candidate():
    data = request.json or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Candidate name is required"}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO candidates (name) VALUES (%s) RETURNING id", (name,))
        candidate_id = cur.fetchone()[0]
        conn.commit()
        return jsonify({"message": "Candidate added", "id": candidate_id, "name": name})
    finally:
        cur.close()
        release_connection(conn)


@app.route("/admin/candidates", methods=["GET"])
def admin_candidates():
    conn = get_connection()
    cur = conn.cursor()
    try:
        query = "SELECT c.id, c.name, COUNT(v.wallet) FROM candidates c LEFT JOIN votes v ON c.id = v.candidate_id GROUP BY c.id ORDER BY c.name"
        cur.execute(query)
        rows = cur.fetchall()
        return jsonify([{"id": r[0], "name": r[1], "votes": r[2]} for r in rows])
    finally:
        cur.close()
        release_connection(conn)


@app.route("/admin/stats", methods=["GET"])
def admin_stats():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM users")
        users = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM vote_attempts")
        vote_attempts = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM ai_flags")
        ai_flags = cur.fetchone()[0]
        return jsonify({"users": users, "vote_attempts": vote_attempts, "ai_flags": ai_flags})
    finally:
        cur.close()
        release_connection(conn)


@app.route("/admin/delete-candidate", methods=["POST"])
def delete_candidate():
    data = request.json or {}
    candidate_id = data.get("id")
    if not candidate_id:
        return jsonify({"error": "Candidate id is required"}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM candidates WHERE id = %s", (candidate_id,))
        if cur.rowcount == 0:
            return jsonify({"error": "Candidate not found"}), 404
        conn.commit()
        return jsonify({"message": "Candidate deleted"})
    finally:
        cur.close()
        release_connection(conn)


@app.route("/admin/results-status", methods=["GET"])
def admin_results_status():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT published, published_at FROM results_publication WHERE id = 1")
        row = cur.fetchone()
        published = bool(row[0]) if row else False
        published_at = row[1].isoformat() if row and row[1] else None
        return jsonify({"published": published, "published_at": published_at})
    finally:
        cur.close()
        release_connection(conn)


@app.route("/admin/publish-results", methods=["POST"])
def admin_publish_results():
    data = request.json or {}
    publish = bool(data.get("published"))
    conn = get_connection()
    cur = conn.cursor()
    try:
        if publish:
            cur.execute(
                "UPDATE results_publication SET published = TRUE, published_at = NOW() WHERE id = 1"
            )
        else:
            cur.execute(
                "UPDATE results_publication SET published = FALSE, published_at = NULL WHERE id = 1"
            )
        conn.commit()
        return jsonify({"published": publish})
    finally:
        cur.close()
        release_connection(conn)


@app.route("/results", methods=["GET"])
def public_results():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT published FROM results_publication WHERE id = 1")
        row = cur.fetchone()
        if not row or not row[0]:
            return jsonify({"published": False, "results": []})

        query = """
            SELECT c.id, c.name, COUNT(v.wallet)
            FROM candidates c
            LEFT JOIN votes v ON c.id = v.candidate_id
            GROUP BY c.id
            ORDER BY COUNT(v.wallet) DESC, c.name
        """
        cur.execute(query)
        rows = cur.fetchall()
        results = [{"id": r[0], "name": r[1], "votes": r[2]} for r in rows]
        return jsonify({"published": True, "results": results})
    finally:
        cur.close()
        release_connection(conn)


@app.route("/admin/ai-flags", methods=["GET"])
def admin_ai_flags():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT wallet, reason, severity, created_at FROM ai_flags ORDER BY created_at DESC")
        rows = cur.fetchall()
        return jsonify([
            {"wallet": r[0], "reason": r[1], "severity": r[2], "created_at": r[3].isoformat()}
            for r in rows
        ])
    finally:
        cur.close()
        release_connection(conn)


@app.route("/admin/acknowledge-flag", methods=["POST"])
def admin_acknowledge_flag():
    data = request.json or {}
    wallet = data.get("wallet")
    if not wallet:
        return jsonify({"error": "Wallet is required"}), 400
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM ai_flags WHERE wallet = %s", (wallet,))
        conn.commit()
        return jsonify({"message": "Flag acknowledged"})
    finally:
        cur.close()
        release_connection(conn)


@app.route("/admin/block-wallet", methods=["POST"])
def admin_block_wallet():
    data = request.json or {}
    wallet = data.get("wallet")
    minutes = data.get("minutes", 30)
    try:
        minutes = int(minutes)
    except Exception:
        minutes = 30
    if not wallet:
        return jsonify({"error": "Wallet is required"}), 400
    if minutes <= 0:
        return jsonify({"error": "Minutes must be positive"}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        blocked_until = datetime.utcnow() + timedelta(minutes=minutes)
        cur.execute("UPDATE users SET blocked_until = %s WHERE wallet = %s", (blocked_until, wallet))
        if cur.rowcount == 0:
            return jsonify({"error": "Wallet not found"}), 404
        conn.commit()
        return jsonify({"message": "Wallet blocked", "blocked_until": blocked_until.isoformat()})
    finally:
        cur.close()
        release_connection(conn)


@app.route("/health")
def health():
    return "Backend running"


@app.route("/verify-decision", methods=["POST"])
def verify_decision():
    data = request.json or {}
    tx_id = data.get("tx_id")
    decision_hash = data.get("decision_hash")
    if not tx_id or not decision_hash:
        return jsonify({"error": "tx_id and decision_hash are required"}), 400

    onchain_note = fetch_tx_note(tx_id)
    if not onchain_note:
        return jsonify({"verified": False, "reason": "No note found on transaction"}), 404

    verified = onchain_note == decision_hash
    return jsonify({
        "verified": verified,
        "onchain_note": onchain_note,
        "decision_hash": decision_hash,
    })


if __name__ == "__main__":
    ensure_schema()
    app.run(debug=True)
