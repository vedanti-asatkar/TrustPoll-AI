import hashlib
import json
from datetime import datetime

from algorand_anchor import anchor_decision_hash, list_anchor_hashes
from db import get_connection, release_connection

ADMIN_AUDIT_VOTER_REF = "admin_audit"
SYSTEM_AUDITOR_ID = "SYSTEM_AUDITOR"
HIGH_RISK_LEVELS = {"HIGH", "CRITICAL"}


def _deterministic_hash(payload):
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _normalized_risk(risk_level):
    level = (risk_level or "LOW").upper()
    if level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return "LOW"
    return level


def log_admin_event(admin_id, event_type, election_id, event_details=None, risk_level="LOW"):
    risk_level = _normalized_risk(risk_level)
    event_payload = {
        "event_type": event_type,
        "admin_id": admin_id or "unknown-admin",
        "election_id": election_id,
        "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "risk_level": risk_level,
        "event_details": event_details or {},
    }

    decision_hash = _deterministic_hash(event_payload)
    algorand_tx_id = None
    if risk_level in HIGH_RISK_LEVELS:
        try:
            algorand_tx_id = anchor_decision_hash(decision_hash, voter_ref=ADMIN_AUDIT_VOTER_REF)
        except Exception:
            algorand_tx_id = None

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO admin_audit_log
                (admin_id, event_type, event_details, risk_level, decision_hash, algorand_tx_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, created_at
            """,
            (
                event_payload["admin_id"],
                event_type,
                json.dumps(event_payload, sort_keys=True),
                risk_level,
                decision_hash,
                algorand_tx_id,
            ),
        )
        row = cur.fetchone()
        conn.commit()
    finally:
        cur.close()
        release_connection(conn)

    return {
        "id": row[0] if row else None,
        "created_at": row[1].isoformat() if row and row[1] else None,
        "event_payload": event_payload,
        "decision_hash": decision_hash,
        "algorand_tx_id": algorand_tx_id,
        "risk_level": risk_level,
    }


def detect_admin_log_tampering(election_id):
    try:
        chain_hashes = set(list_anchor_hashes(ADMIN_AUDIT_VOTER_REF, limit=4000))
        chain_lookup_error = None
    except Exception as exc:
        chain_hashes = set()
        chain_lookup_error = str(exc)

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT decision_hash
            FROM admin_audit_log
            WHERE decision_hash IS NOT NULL
              AND algorand_tx_id IS NOT NULL
            """
        )
        db_hashes = {row[0] for row in cur.fetchall()}

        cur.execute(
            """
            SELECT COUNT(*)
            FROM admin_audit_log
            WHERE event_type = 'CRITICAL_ADMIN_LOG_TAMPERING'
            """
        )
        previous_critical_tampering_events = cur.fetchone()[0]
    finally:
        cur.close()
        release_connection(conn)

    missing_hashes = sorted(chain_hashes - db_hashes)
    tampering_detected_now = len(missing_hashes) > 0

    if tampering_detected_now and previous_critical_tampering_events == 0:
        log_admin_event(
            admin_id=SYSTEM_AUDITOR_ID,
            event_type="CRITICAL_ADMIN_LOG_TAMPERING",
            election_id=election_id,
            event_details={
                "missing_hash_count": len(missing_hashes),
                "missing_hashes_sample": missing_hashes[:10],
                "detection_scope": "anchored_admin_hashes_without_matching_db_rows",
            },
            risk_level="CRITICAL",
        )

    return {
        "tampering_detected_now": tampering_detected_now,
        "missing_hash_count": len(missing_hashes),
        "missing_hashes_sample": missing_hashes[:10],
        "previous_critical_tampering_events": int(previous_critical_tampering_events),
        "governance_compromised": tampering_detected_now or previous_critical_tampering_events > 0,
        "chain_lookup_error": chain_lookup_error,
        "chain_hash_count": len(chain_hashes),
    }


def get_governance_audit_summary(election_id):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE risk_level IN ('HIGH', 'CRITICAL')) AS high_risk_events,
                COUNT(*) FILTER (WHERE risk_level = 'CRITICAL') AS critical_events,
                COUNT(*) FILTER (WHERE risk_level IN ('HIGH', 'CRITICAL') AND algorand_tx_id IS NOT NULL) AS anchored_high_risk_events
            FROM admin_audit_log
            """
        )
        row = cur.fetchone()
        high_risk_events = int(row[0] or 0)
        critical_events = int(row[1] or 0)
        anchored_high_risk_events = int(row[2] or 0)
    finally:
        cur.close()
        release_connection(conn)

    tamper_check = detect_admin_log_tampering(election_id)
    if tamper_check.get("chain_lookup_error"):
        chain_hash_count = 0
        blockchain_verification_status = "UNAVAILABLE"
    else:
        chain_hash_count = int(tamper_check.get("chain_hash_count", 0))
        blockchain_verification_status = "VERIFIED"
        if tamper_check["missing_hash_count"] > 0:
            blockchain_verification_status = "MISMATCH_DETECTED"

    return {
        "total_admin_high_risk_events": high_risk_events,
        "total_admin_critical_events": critical_events,
        "anchored_high_risk_events": anchored_high_risk_events,
        "blockchain_admin_anchor_count": chain_hash_count,
        "blockchain_verification_status": blockchain_verification_status,
        "tampering_detection_result": "CRITICAL_ADMIN_LOG_TAMPERING" if tamper_check["governance_compromised"] else "CLEAR",
        "missing_hash_count": tamper_check["missing_hash_count"],
        "missing_hashes_sample": tamper_check["missing_hashes_sample"],
        "chain_lookup_error": tamper_check.get("chain_lookup_error"),
        "governance_integrity_status": "COMPROMISED" if tamper_check["governance_compromised"] else "HEALTHY",
    }


def backfill_high_risk_anchors(batch_size=50):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT id, decision_hash
            FROM admin_audit_log
            WHERE risk_level IN ('HIGH', 'CRITICAL')
              AND decision_hash IS NOT NULL
              AND algorand_tx_id IS NULL
            ORDER BY created_at ASC
            LIMIT %s
            """,
            (batch_size,),
        )
        rows = cur.fetchall()
    finally:
        cur.close()
        release_connection(conn)

    anchored_count = 0
    for row_id, decision_hash in rows:
        try:
            tx_id = anchor_decision_hash(decision_hash, voter_ref=ADMIN_AUDIT_VOTER_REF)
        except Exception:
            tx_id = None
        if not tx_id:
            continue

        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "UPDATE admin_audit_log SET algorand_tx_id = %s WHERE id = %s AND algorand_tx_id IS NULL",
                (tx_id, row_id),
            )
            conn.commit()
            if cur.rowcount > 0:
                anchored_count += 1
        finally:
            cur.close()
            release_connection(conn)

    return {"pending_checked": len(rows), "anchored_count": anchored_count}
