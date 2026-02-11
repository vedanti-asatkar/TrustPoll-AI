import hashlib
import json
import os
import random
import re
import threading
from datetime import datetime, timedelta

import psycopg2
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

from ai import analyze_vote
from algorand_anchor import (
    ANCHOR_NOTE_PREFIX,
    anchor_decision_hash,
    count_wallet_anchors,
    fetch_tx_note,
    parse_anchor_note,
)
from admin_audit import backfill_high_risk_anchors, detect_admin_log_tampering, get_governance_audit_summary, log_admin_event
from consensus import run_consensus
from db import get_connection, release_connection
from email_service import send_registration_success_email, send_verification_otp

app = Flask(__name__)
CORS(app)

OTP_STORE = {}
OTP_EXPIRY_MINUTES = 10
OTP_MAX_ATTEMPTS = 3
OTP_RESEND_COOLDOWN_SECONDS = 30
MIN_PASSWORD_LENGTH = 8
PASSWORD_COMPLEXITY_MSG = "Password must be at least 8 characters and include uppercase, lowercase, number, and special character."
FAIRNESS_DEFAULT_ELECTION_ID = "demo-1"
AUDIT_MONITOR_INTERVAL_SECONDS = int(os.getenv("AUDIT_MONITOR_INTERVAL_SECONDS", "300"))

_audit_monitor_stop_event = threading.Event()
_audit_monitor_started = False


def ensure_schema():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                wallet TEXT UNIQUE,
                voter_id TEXT UNIQUE,
                user_ref TEXT UNIQUE,
                password_hash TEXT,
                blocked_until TIMESTAMP,
                email_verified BOOLEAN DEFAULT FALSE,
                has_voted BOOLEAN DEFAULT FALSE,
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
                ip_hash TEXT,
                device_fingerprint_hash TEXT,
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
            CREATE TABLE IF NOT EXISTS fairness_reports (
                id SERIAL PRIMARY KEY,
                election_id TEXT NOT NULL,
                fairness_payload JSONB NOT NULL,
                fairness_hash TEXT NOT NULL,
                fairness_score NUMERIC(5,2) NOT NULL,
                algorand_tx_id TEXT,
                computed_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS admin_audit_log (
                id SERIAL PRIMARY KEY,
                admin_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_details JSONB,
                risk_level TEXT CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
                decision_hash TEXT,
                algorand_tx_id TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
        """
        )
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked_until TIMESTAMP;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS has_voted BOOLEAN DEFAULT FALSE;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS voter_id TEXT;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS user_ref TEXT;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;")
        cur.execute("ALTER TABLE users ALTER COLUMN wallet DROP NOT NULL;")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_voter_id_unique ON users(voter_id) WHERE voter_id IS NOT NULL;")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_user_ref_unique ON users(user_ref) WHERE user_ref IS NOT NULL;")
        cur.execute("ALTER TABLE votes ADD COLUMN IF NOT EXISTS email TEXT;")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS votes_wallet_unique ON votes(wallet);")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS votes_email_unique ON votes(email) WHERE email IS NOT NULL;")
        cur.execute("ALTER TABLE ai_decisions ADD COLUMN IF NOT EXISTS email TEXT;")
        cur.execute("ALTER TABLE ai_decisions ADD COLUMN IF NOT EXISTS has_voted BOOLEAN DEFAULT FALSE;")
        cur.execute("ALTER TABLE ai_decisions ADD COLUMN IF NOT EXISTS algorand_tx_id TEXT;")
        cur.execute("ALTER TABLE vote_attempts ALTER COLUMN election_id TYPE TEXT USING election_id::text;")
        cur.execute("ALTER TABLE vote_attempts ADD COLUMN IF NOT EXISTS ip_hash TEXT;")
        cur.execute("ALTER TABLE vote_attempts ADD COLUMN IF NOT EXISTS device_fingerprint_hash TEXT;")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vote_attempts_election_result ON vote_attempts(election_id, result);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vote_attempts_election_ip ON vote_attempts(election_id, ip_hash);")
        cur.execute(
            """
            CREATE OR REPLACE FUNCTION prevent_high_critical_audit_delete()
            RETURNS trigger AS $$
            BEGIN
                IF OLD.risk_level IN ('HIGH', 'CRITICAL') THEN
                    RAISE EXCEPTION 'Deletion of HIGH/CRITICAL admin audit records is blocked';
                END IF;
                RETURN OLD;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        cur.execute("DROP TRIGGER IF EXISTS trg_prevent_high_critical_audit_delete ON admin_audit_log;")
        cur.execute(
            """
            CREATE TRIGGER trg_prevent_high_critical_audit_delete
            BEFORE DELETE ON admin_audit_log
            FOR EACH ROW
            EXECUTE FUNCTION prevent_high_critical_audit_delete();
            """
        )
        cur.execute("INSERT INTO results_publication (id, published) VALUES (1, FALSE) ON CONFLICT (id) DO NOTHING;")
        conn.commit()
    finally:
        cur.close()
        release_connection(conn)


def is_valid_vit_email(email):
    return isinstance(email, str) and bool(re.fullmatch(r"[^@\s]+@vit\.edu", email.strip().lower()))


def _normalize_email(email):
    return email.strip().lower() if isinstance(email, str) else ""


def _otp_key(email):
    return _normalize_email(email)


def _derive_user_ref(email):
    salt = os.getenv("USER_HASH_SALT", "trustpoll-change-me")
    return hashlib.sha256(f"{_normalize_email(email)}|{salt}".encode("utf-8")).hexdigest()


def _is_strong_password(password):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return False
    has_upper = any(ch.isupper() for ch in password)
    has_lower = any(ch.islower() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_special = any(not ch.isalnum() for ch in password)
    return has_upper and has_lower and has_digit and has_special


def _deterministic_hash(payload):
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _record_vote_attempt(user_ref, election_id, result, ip_hash, device_fingerprint_hash):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO vote_attempts (wallet, election_id, result, ip_hash, device_fingerprint_hash)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_ref, election_id, result, ip_hash, device_fingerprint_hash),
        )
        conn.commit()
    finally:
        cur.close()
        release_connection(conn)


def _compute_fairness_index(election_id):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM vote_attempts WHERE election_id = %s", (election_id,))
        total_attempts = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM votes WHERE email IS NOT NULL")
        total_votes_cast = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM vote_attempts
            WHERE election_id = %s
            AND result IN ('tampering_blocked', 'inconsistent_state', 'double_vote_blocked')
            """,
            (election_id,),
        )
        tampering_attempts = cur.fetchone()[0]

        cur.execute(
            "SELECT COUNT(*) FROM vote_attempts WHERE election_id = %s AND result = 'duplicate_blocked'",
            (election_id,),
        )
        duplicate_attempts_blocked = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM (
                SELECT DATE_TRUNC('minute', timestamp) AS minute_bucket, COUNT(*) AS bucket_count
                FROM vote_attempts
                WHERE election_id = %s
                GROUP BY DATE_TRUNC('minute', timestamp)
                HAVING COUNT(*) >= 4
            ) AS suspicious_bursts
            """,
            (election_id,),
        )
        abnormal_timing_clusters = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM (
                SELECT ip_hash, COUNT(*) AS ip_count
                FROM vote_attempts
                WHERE election_id = %s
                  AND ip_hash IS NOT NULL
                  AND ip_hash NOT IN ('', 'unknown', 'client')
                GROUP BY ip_hash
                HAVING COUNT(*) >= 3
            ) AS suspicious_ips
            """,
            (election_id,),
        )
        suspicious_ip_clusters = cur.fetchone()[0]
    finally:
        cur.close()
        release_connection(conn)

    penalties = {
        "tampering_penalty": min(35.0, tampering_attempts * 3.0),
        "duplicate_penalty": min(25.0, duplicate_attempts_blocked * 2.5),
        "timing_penalty": min(20.0, abnormal_timing_clusters * 4.0),
        "ip_penalty": min(20.0, suspicious_ip_clusters * 4.0),
    }
    raw_score = 100.0 - sum(penalties.values())
    fairness_score = round(max(0.0, raw_score), 2)
    governance_summary = get_governance_audit_summary(election_id)
    governance_compromised = governance_summary.get("governance_integrity_status") == "COMPROMISED"
    if governance_compromised:
        fairness_score = min(fairness_score, 69.0)

    formula = {
        "base_score": 100.0,
        "equation": "score = max(0, 100 - tampering_penalty - duplicate_penalty - timing_penalty - ip_penalty)",
        "weights": {
            "tampering_attempt": 3.0,
            "duplicate_attempt_blocked": 2.5,
            "abnormal_timing_cluster": 4.0,
            "suspicious_ip_cluster": 4.0,
        },
        "caps": {
            "tampering_penalty": 35.0,
            "duplicate_penalty": 25.0,
            "timing_penalty": 20.0,
            "ip_penalty": 20.0,
        },
    }

    metrics = {
        "total_attempts": int(total_attempts),
        "total_votes_cast": int(total_votes_cast),
        "tampering_attempts_detected": int(tampering_attempts),
        "duplicate_attempts_blocked": int(duplicate_attempts_blocked),
        "abnormal_timing_clusters": int(abnormal_timing_clusters),
        "suspicious_ip_clusters": int(suspicious_ip_clusters),
        "admin_high_risk_events": int(governance_summary.get("total_admin_high_risk_events", 0)),
        "admin_critical_events": int(governance_summary.get("total_admin_critical_events", 0)),
        "governance_missing_anchor_records": int(governance_summary.get("missing_hash_count", 0)),
    }

    payload = {
        "election_id": election_id,
        "fairness_score": fairness_score,
        "metrics": metrics,
        "penalties": penalties,
        "formula": formula,
        "governance": governance_summary,
        "governance_risk_flag": governance_compromised,
        "computed_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    }
    return payload


def _is_voting_window_active():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT published FROM results_publication WHERE id = 1")
        row = cur.fetchone()
        published = bool(row[0]) if row else False
        if published:
            return False
        cur.execute("SELECT COUNT(*) FROM vote_attempts WHERE election_id = %s", (FAIRNESS_DEFAULT_ELECTION_ID,))
        attempts = cur.fetchone()[0]
        return attempts > 0
    finally:
        cur.close()
        release_connection(conn)


def _has_any_anchoring_activity():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM ai_decisions WHERE algorand_tx_id IS NOT NULL")
        ai_anchor_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM fairness_reports WHERE algorand_tx_id IS NOT NULL")
        fairness_anchor_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM admin_audit_log WHERE algorand_tx_id IS NOT NULL")
        admin_anchor_count = cur.fetchone()[0]
        return (ai_anchor_count + fairness_anchor_count + admin_anchor_count) > 0
    finally:
        cur.close()
        release_connection(conn)


def _run_governance_monitor():
    while not _audit_monitor_stop_event.is_set():
        try:
            backfill_high_risk_anchors(batch_size=100)
            detect_admin_log_tampering(FAIRNESS_DEFAULT_ELECTION_ID)
        except Exception:
            pass
        _audit_monitor_stop_event.wait(AUDIT_MONITOR_INTERVAL_SECONDS)


def _start_governance_monitor_if_needed():
    global _audit_monitor_started
    if _audit_monitor_started:
        return
    # In Flask debug mode, avoid starting monitor in the reloader parent process.
    if os.getenv("WERKZEUG_RUN_MAIN") not in (None, "true"):
        return
    _audit_monitor_started = True
    thread = threading.Thread(target=_run_governance_monitor, name="governance-audit-monitor", daemon=True)
    thread.start()


def _get_user_by_email(cur, email):
    clean = _normalize_email(email)
    cur.execute(
        "SELECT email, voter_id, user_ref, password_hash, blocked_until, email_verified FROM users WHERE email = %s",
        (clean,),
    )
    return cur.fetchone()


@app.route("/register/start", methods=["POST"])
def register_start():
    data = request.json or {}
    email = _normalize_email(data.get("email"))

    if not is_valid_vit_email(email):
        return jsonify({"error": "Only @vit.edu emails are allowed."}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT 1 FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            return jsonify({"error": "Email already registered"}), 409
    finally:
        cur.close()
        release_connection(conn)

    key = _otp_key(email)
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
    email = _normalize_email(data.get("email"))
    otp = (data.get("otp") or "").strip()
    password = data.get("password") or ""

    if not is_valid_vit_email(email):
        return jsonify({"error": "Only @vit.edu emails are allowed."}), 400
    if not _is_strong_password(password):
        return jsonify({"error": PASSWORD_COMPLEXITY_MSG}), 400

    key = _otp_key(email)
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
        user_ref = _derive_user_ref(email)
        password_hash = generate_password_hash(password)

        cur.execute(
            """
            INSERT INTO users (email, wallet, voter_id, user_ref, password_hash, email_verified)
            VALUES (%s, %s, %s, %s, %s, TRUE)
            """,
            (email, user_ref, None, user_ref, password_hash),
        )
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        if conn:
            conn.rollback()
        return jsonify({"error": "Email already registered"}), 409
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
    try:
        send_registration_success_email(email)
    except Exception:
        pass

    return jsonify({"message": "Email verified and registration complete"}), 200


@app.route("/register", methods=["POST"])
def register():
    return jsonify({"error": "Use /register/start and /register/verify."}), 410


@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    identifier = data.get("email") or data.get("identifier")
    password = data.get("password") or ""

    if not identifier or not password:
        return jsonify({"error": "Email and password are required."}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        user = _get_user_by_email(cur, identifier)
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        email, voter_id, _user_ref, password_hash, blocked_until, email_verified = user
        if blocked_until and blocked_until > datetime.utcnow():
            return jsonify({"error": "Account temporarily blocked. Please try again later."}), 403
        if not email_verified:
            return jsonify({"error": "Please verify your email before logging in."}), 403
        if not password_hash or not check_password_hash(password_hash, password):
            return jsonify({"error": "Invalid credentials"}), 401

        return jsonify({"message": "Login successful", "email": email})
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
    email = _normalize_email(data.get("email"))
    candidate_id = data.get("candidate_id")

    if not email or not candidate_id:
        return jsonify({"error": "Email and candidate_id are required"}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT blocked_until, email_verified, has_voted, user_ref FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
        blocked_until, email_verified, has_voted, user_ref = user
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
            (candidate_id, user_ref, email),
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
    email = _normalize_email(data.get("email"))
    election_id = data.get("election_id") or FAIRNESS_DEFAULT_ELECTION_ID
    ip_hash = data.get("ip_hash", "unknown")
    device_fingerprint_hash = data.get("device_fingerprint_hash", "unknown")

    if not email:
        return jsonify({"status": "rejected", "reason": "Email is required", "integrity_status": "OK"}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT email_verified, has_voted, user_ref FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
    finally:
        cur.close()
        release_connection(conn)

    if not user:
        return jsonify({"status": "rejected", "reason": "User not found", "integrity_status": "OK"}), 404

    email_verified, has_voted, user_ref = user
    if not email_verified:
        return jsonify({"status": "rejected", "reason": "Email not verified", "integrity_status": "OK"}), 403
    if has_voted:
        _record_vote_attempt(user_ref, election_id, "duplicate_blocked", ip_hash, device_fingerprint_hash)
        return jsonify({"status": "rejected", "reason": "Email already voted", "integrity_status": "OK"}), 409

    chain_anchor_count = count_wallet_anchors(user_ref)
    blockchain_anchor_exists = chain_anchor_count > 0

    if not has_voted and blockchain_anchor_exists:
        _record_vote_attempt(user_ref, election_id, "tampering_blocked", ip_hash, device_fingerprint_hash)
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO ai_flags (wallet, reason, severity) VALUES (%s, %s, %s)",
                (user_ref, "CRITICAL_TAMPERING", 10),
            )
            conn.commit()
        finally:
            cur.close()
            release_connection(conn)
        return jsonify(
            {
                "status": "rejected",
                "reason": "On-chain history exists but DB record is missing",
                "integrity_status": "CRITICAL_TAMPERING",
            }
        ), 409

    if has_voted and not blockchain_anchor_exists:
        _record_vote_attempt(user_ref, election_id, "inconsistent_state", ip_hash, device_fingerprint_hash)
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO ai_flags (wallet, reason, severity) VALUES (%s, %s, %s)",
                (user_ref, "INCONSISTENT_STATE", 7),
            )
            conn.commit()
        finally:
            cur.close()
            release_connection(conn)
        return jsonify(
            {
                "status": "rejected",
                "reason": "DB record exists but no on-chain anchor found",
                "integrity_status": "INCONSISTENT_STATE",
            }
        ), 409

    if chain_anchor_count > 1:
        _record_vote_attempt(user_ref, election_id, "double_vote_blocked", ip_hash, device_fingerprint_hash)
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO ai_flags (wallet, reason, severity) VALUES (%s, %s, %s)",
                (user_ref, "DOUBLE_VOTE_ON_CHAIN", 9),
            )
            conn.commit()
        finally:
            cur.close()
            release_connection(conn)
        return jsonify(
            {
                "status": "rejected",
                "reason": "Multiple on-chain anchors detected for user",
                "integrity_status": "DOUBLE_VOTE_ON_CHAIN",
            }
        ), 409

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT COUNT(*)
            FROM vote_attempts
            WHERE wallet = %s
            AND timestamp > NOW() - INTERVAL '5 minutes'
            """,
            (user_ref,),
        )
        vote_attempt_count = cur.fetchone()[0]

        cur.execute(
            """
            SELECT EXTRACT(EPOCH FROM (NOW() - MAX(timestamp)))
            FROM vote_attempts
            WHERE wallet = %s
            """,
            (user_ref,),
        )
        time_between = cur.fetchone()[0]
    finally:
        cur.close()
        release_connection(conn)

    metadata = {
        "email": email,
        "has_voted": has_voted,
        "voter_ref": user_ref,
        "vote_attempt_count": int(vote_attempt_count),
        "time_between_attempts_sec": int(time_between or 999999),
        "ip_hash": ip_hash,
        "device_fingerprint_hash": device_fingerprint_hash,
        "election_id": election_id,
        "candidate_id": data.get("candidate_id"),
        "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    }

    decision_payload, payload_hash = analyze_vote(metadata)
    consensus_verdict, validators, validators_json = run_consensus(decision_payload["decision"], metadata)
    algorand_tx_id = None
    try:
        algorand_tx_id = anchor_decision_hash(payload_hash, voter_ref=user_ref)
    except Exception:
        algorand_tx_id = None

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO vote_attempts (wallet, election_id, result, ip_hash, device_fingerprint_hash)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                user_ref,
                election_id,
                "flagged" if consensus_verdict != "ALLOW" else "ok",
                ip_hash,
                device_fingerprint_hash,
            ),
        )

        if consensus_verdict != "ALLOW":
            cur.execute(
                """
                INSERT INTO ai_flags (wallet, reason, severity)
                VALUES (%s, %s, %s)
                """,
                (user_ref, "Automated risk detection", 7),
            )

        for name, validator_data in validators.items():
            cur.execute(
                "INSERT INTO consensus_votes (wallet, validator, verdict, decision_hash) VALUES (%s, %s, %s, %s)",
                (user_ref, name, validator_data["verdict"], payload_hash),
            )
        cur.execute(
            "INSERT INTO consensus_results (wallet, decision_hash, final_verdict, votes_json) VALUES (%s, %s, %s, %s)",
            (user_ref, payload_hash, consensus_verdict, validators_json),
        )

        if algorand_tx_id:
            cur.execute("UPDATE ai_decisions SET algorand_tx_id = %s WHERE payload_hash = %s", (algorand_tx_id, payload_hash))

        if consensus_verdict == "ALLOW":
            cur.execute("UPDATE users SET has_voted = TRUE WHERE email = %s", (email,))

        conn.commit()
        return jsonify(
            {
                "status": "accepted" if consensus_verdict == "ALLOW" else "rejected",
                "reason": "Risk evaluation completed",
                "integrity_status": "OK",
                "decision": decision_payload,
                "decision_hash": payload_hash,
                "algorand_tx_id": algorand_tx_id,
                "consensus": {
                    "final_verdict": consensus_verdict,
                    "validators": validators,
                },
            }
        )
    finally:
        cur.close()
        release_connection(conn)


@app.route("/admin/add-candidate", methods=["POST"])
def add_candidate():
    data = request.json or {}
    admin_id = (data.get("admin_id") or "unknown-admin").strip()
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Candidate name is required"}), 400

    voting_active = _is_voting_window_active()
    has_anchor = _has_any_anchoring_activity()
    risk_level = "LOW"
    event_type = "CANDIDATE_ADDED"
    if voting_active:
        risk_level = "HIGH"
        event_type = "CANDIDATE_ADDED_DURING_VOTING_WINDOW"
    elif has_anchor:
        risk_level = "HIGH"
        event_type = "CANDIDATE_ADDED_AFTER_ANCHORING"
    log_admin_event(
        admin_id=admin_id,
        event_type=event_type,
        election_id=FAIRNESS_DEFAULT_ELECTION_ID,
        event_details={"candidate_name": name, "voting_window_active": voting_active, "anchoring_active": has_anchor},
        risk_level=risk_level,
    )

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
    admin_id = (request.args.get("admin_id") or "unknown-admin").strip()
    if _has_any_anchoring_activity():
        log_admin_event(
            admin_id=admin_id,
            event_type="VOTE_TABLE_ACCESSED_AFTER_ANCHORING",
            election_id=FAIRNESS_DEFAULT_ELECTION_ID,
            event_details={"action": "admin_candidates_vote_count_query"},
            risk_level="HIGH",
        )

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


@app.route("/admin/fairness-index", methods=["GET", "POST"])
def admin_fairness_index():
    if request.method == "GET":
        election_id = (request.args.get("election_id") or FAIRNESS_DEFAULT_ELECTION_ID).strip()
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                SELECT fairness_payload, fairness_hash, fairness_score, algorand_tx_id, computed_at
                FROM fairness_reports
                WHERE election_id = %s
                ORDER BY computed_at DESC
                LIMIT 1
                """,
                (election_id,),
            )
            row = cur.fetchone()
        finally:
            cur.close()
            release_connection(conn)

        if not row:
            payload = _compute_fairness_index(election_id)
            return jsonify(
                {
                    "election_id": election_id,
                    "fairness_score": payload["fairness_score"],
                    "metrics": payload["metrics"],
                    "penalties": payload["penalties"],
                    "formula": payload["formula"],
                    "governance": payload.get("governance", {}),
                    "governance_risk_flag": bool(payload.get("governance_risk_flag")),
                    "fairness_hash": _deterministic_hash(payload),
                    "algorand_tx_id": None,
                    "anchored": False,
                    "computed_at": payload["computed_at"],
                }
            )

        payload, fairness_hash, fairness_score, algorand_tx_id, computed_at = row
        if isinstance(payload, str):
            payload = json.loads(payload)
        return jsonify(
            {
                "election_id": election_id,
                "fairness_score": float(fairness_score),
                "metrics": payload.get("metrics", {}),
                "penalties": payload.get("penalties", {}),
                "formula": payload.get("formula", {}),
                "governance": payload.get("governance", {}),
                "governance_risk_flag": bool(payload.get("governance_risk_flag")),
                "fairness_hash": fairness_hash,
                "algorand_tx_id": algorand_tx_id,
                "anchored": bool(algorand_tx_id),
                "computed_at": computed_at.isoformat() if computed_at else None,
            }
        )

    data = request.json or {}
    election_id = (data.get("election_id") or FAIRNESS_DEFAULT_ELECTION_ID).strip()
    should_anchor = bool(data.get("anchor", True))
    admin_id = (data.get("admin_id") or "unknown-admin").strip()
    payload = _compute_fairness_index(election_id)
    fairness_hash = _deterministic_hash(payload)
    algorand_tx_id = None

    if should_anchor:
        try:
            algorand_tx_id = anchor_decision_hash(fairness_hash, voter_ref=f"fairness:{election_id}")
        except Exception:
            algorand_tx_id = None

    log_admin_event(
        admin_id=admin_id,
        event_type="FAIRNESS_INDEX_COMPUTED",
        election_id=election_id,
        event_details={"anchoring_requested": should_anchor, "anchored": bool(algorand_tx_id), "fairness_hash": fairness_hash},
        risk_level="MEDIUM",
    )

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO fairness_reports (election_id, fairness_payload, fairness_hash, fairness_score, algorand_tx_id)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (election_id, json.dumps(payload, sort_keys=True), fairness_hash, payload["fairness_score"], algorand_tx_id),
        )
        conn.commit()
    finally:
        cur.close()
        release_connection(conn)

    return jsonify(
        {
            "election_id": election_id,
            "fairness_score": payload["fairness_score"],
            "metrics": payload["metrics"],
            "penalties": payload["penalties"],
            "formula": payload["formula"],
            "governance": payload.get("governance", {}),
            "governance_risk_flag": bool(payload.get("governance_risk_flag")),
            "fairness_hash": fairness_hash,
            "algorand_tx_id": algorand_tx_id,
            "anchored": bool(algorand_tx_id),
            "computed_at": payload["computed_at"],
        }
    )


@app.route("/admin/delete-candidate", methods=["POST"])
def delete_candidate():
    data = request.json or {}
    admin_id = (data.get("admin_id") or "unknown-admin").strip()
    candidate_id = data.get("id")
    if not candidate_id:
        return jsonify({"error": "Candidate id is required"}), 400

    voting_active = _is_voting_window_active()
    has_anchor = _has_any_anchoring_activity()
    risk_level = "MEDIUM"
    event_type = "CANDIDATE_DELETED"
    if voting_active:
        risk_level = "CRITICAL"
        event_type = "CANDIDATE_DELETED_DURING_VOTING_WINDOW"
    elif has_anchor:
        risk_level = "HIGH"
        event_type = "CANDIDATE_DELETED_AFTER_ANCHORING"
    log_admin_event(
        admin_id=admin_id,
        event_type=event_type,
        election_id=FAIRNESS_DEFAULT_ELECTION_ID,
        event_details={"candidate_id": candidate_id, "voting_window_active": voting_active, "anchoring_active": has_anchor},
        risk_level=risk_level,
    )

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
    admin_id = (data.get("admin_id") or "unknown-admin").strip()
    publish = bool(data.get("published"))
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT published FROM results_publication WHERE id = 1")
        row = cur.fetchone()
        currently_published = bool(row[0]) if row else False

        voting_active = _is_voting_window_active()
        has_anchor = _has_any_anchoring_activity()
        risk_level = "LOW"
        event_type = "ELECTION_STATE_MODIFIED"
        if voting_active:
            risk_level = "HIGH"
            event_type = "ELECTION_METADATA_CHANGED_DURING_VOTE_WINDOW"
        if has_anchor:
            risk_level = "HIGH"
            event_type = "ELECTION_STATE_MODIFIED_AFTER_ANCHORING"
        if currently_published and not publish:
            risk_level = "CRITICAL"
            event_type = "RESULTS_UNPUBLISHED_AFTER_PUBLICATION"

        log_admin_event(
            admin_id=admin_id,
            event_type=event_type,
            election_id=FAIRNESS_DEFAULT_ELECTION_ID,
            event_details={
                "from_published": currently_published,
                "to_published": publish,
                "voting_window_active": voting_active,
                "anchoring_active": has_anchor,
            },
            risk_level=risk_level,
        )

        if publish:
            cur.execute("UPDATE results_publication SET published = TRUE, published_at = NOW() WHERE id = 1")
        else:
            cur.execute("UPDATE results_publication SET published = FALSE, published_at = NULL WHERE id = 1")
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
        governance_summary = get_governance_audit_summary(FAIRNESS_DEFAULT_ELECTION_ID)
        governance_compromised = governance_summary.get("governance_integrity_status") == "COMPROMISED"
        cur.execute(
            """
            SELECT fairness_payload, fairness_hash, fairness_score, algorand_tx_id, computed_at
            FROM fairness_reports
            WHERE election_id = %s
            ORDER BY computed_at DESC
            LIMIT 1
            """,
            (FAIRNESS_DEFAULT_ELECTION_ID,),
        )
        fairness_row = cur.fetchone()
        fairness_public = None
        if fairness_row:
            fairness_payload, fairness_hash, fairness_score, fairness_tx_id, fairness_computed_at = fairness_row
            if isinstance(fairness_payload, str):
                fairness_payload = json.loads(fairness_payload)
            fairness_public = {
                "fairness_score": float(fairness_score),
                "formula": fairness_payload.get("formula", {}),
                "metrics": fairness_payload.get("metrics", {}),
                "governance_risk_flag": bool(fairness_payload.get("governance_risk_flag")),
                "fairness_hash": fairness_hash,
                "algorand_tx_id": fairness_tx_id,
                "computed_at": fairness_computed_at.isoformat() if fairness_computed_at else None,
            }
        return jsonify(
            {
                "published": True,
                "results": results,
                "fairness_index": fairness_public,
                "governance_integrity_audit": governance_summary,
                "governance_integrity_status": "COMPROMISED" if governance_compromised else "HEALTHY",
                "governance_warning": "Governance Integrity Compromised" if governance_compromised else None,
            }
        )
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
        return jsonify(
            [
                {"wallet": r[0], "reason": r[1], "severity": r[2], "created_at": r[3].isoformat()}
                for r in rows
            ]
        )
    finally:
        cur.close()
        release_connection(conn)


@app.route("/admin/acknowledge-flag", methods=["POST"])
def admin_acknowledge_flag():
    data = request.json or {}
    admin_id = (data.get("admin_id") or "unknown-admin").strip()
    wallet = data.get("wallet")
    if not wallet:
        return jsonify({"error": "User key is required"}), 400

    if _has_any_anchoring_activity():
        log_admin_event(
            admin_id=admin_id,
            event_type="AI_FLAG_ACKNOWLEDGED_AFTER_ANCHORING",
            election_id=FAIRNESS_DEFAULT_ELECTION_ID,
            event_details={"user_key": wallet},
            risk_level="HIGH",
        )
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
    admin_id = (data.get("admin_id") or "unknown-admin").strip()
    wallet = data.get("wallet")
    minutes = data.get("minutes", 30)
    try:
        minutes = int(minutes)
    except Exception:
        minutes = 30
    if not wallet:
        return jsonify({"error": "User key is required"}), 400
    if minutes <= 0:
        return jsonify({"error": "Minutes must be positive"}), 400

    voting_active = _is_voting_window_active()
    risk_level = "MEDIUM"
    event_type = "USER_BLOCKED_BY_ADMIN"
    if voting_active:
        risk_level = "HIGH"
        event_type = "USER_BLOCKED_DURING_VOTING_WINDOW"
    log_admin_event(
        admin_id=admin_id,
        event_type=event_type,
        election_id=FAIRNESS_DEFAULT_ELECTION_ID,
        event_details={"user_key": wallet, "minutes": minutes},
        risk_level=risk_level,
    )

    conn = get_connection()
    cur = conn.cursor()
    try:
        blocked_until = datetime.utcnow() + timedelta(minutes=minutes)
        cur.execute("UPDATE users SET blocked_until = %s WHERE user_ref = %s OR wallet = %s", (blocked_until, wallet, wallet))
        if cur.rowcount == 0:
            return jsonify({"error": "User not found"}), 404
        conn.commit()
        return jsonify({"message": "User blocked", "blocked_until": blocked_until.isoformat()})
    finally:
        cur.close()
        release_connection(conn)


@app.route("/admin/governance-audit", methods=["GET"])
def admin_governance_audit():
    election_id = (request.args.get("election_id") or FAIRNESS_DEFAULT_ELECTION_ID).strip()
    summary = get_governance_audit_summary(election_id)
    return jsonify({"election_id": election_id, "audit": summary})


@app.route("/health")
def health():
    return "Backend running"


@app.route("/verify-decision", methods=["POST"])
def verify_decision():
    data = request.json or {}
    tx_id = data.get("tx_id")
    decision_hash = data.get("decision_hash")
    voter_ref = data.get("voter_ref") or data.get("wallet")
    if not tx_id or not decision_hash:
        return jsonify({"error": "tx_id and decision_hash are required"}), 400

    onchain_note = fetch_tx_note(tx_id)
    if not onchain_note:
        return jsonify({"verified": False, "reason": "No note found on transaction"}), 404

    note_voter_ref, note_hash = parse_anchor_note(onchain_note)
    if note_voter_ref and note_hash:
        verified = note_hash == decision_hash and (not voter_ref or voter_ref == note_voter_ref)
    else:
        verified = onchain_note == decision_hash

    return jsonify(
        {
            "verified": verified,
            "onchain_note": onchain_note,
            "decision_hash": decision_hash,
            "note_prefix": ANCHOR_NOTE_PREFIX,
            "voter_ref_match": (note_voter_ref == voter_ref) if voter_ref and note_voter_ref else None,
        }
    )


if __name__ == "__main__":
    ensure_schema()
    _start_governance_monitor_if_needed()
    app.run(debug=True)
