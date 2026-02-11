import json
import hashlib
from db import get_connection, release_connection

MODEL_VERSION = "ai-v1.0"


def _deterministic_hash(payload):
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _score_from_rules(rules):
    score = 0.1
    if "RAPID_ATTEMPTS" in rules:
        score += 0.4
    if "RETRY_PATTERN" in rules:
        score += 0.2
    if "HIGH_FREQUENCY" in rules:
        score += 0.2
    return max(0.0, min(1.0, score))


def _decision_from_score(score):
    if score < 0.40:
        return "ALLOW"
    if score < 0.70:
        return "FLAG"
    return "BLOCK"


def generate_decision_payload(metadata, rules_triggered):
    risk_score = _score_from_rules(rules_triggered)
    decision = _decision_from_score(risk_score)
    payload = {
        "email": metadata["email"],
        "action": "vote",
        "has_voted": metadata["has_voted"],
        "wallet": metadata["wallet"],
        "decision": decision,
        "risk_score": round(risk_score, 2),
        "rules_triggered": rules_triggered,
        "model_version": MODEL_VERSION,
        "timestamp": metadata["timestamp"],
    }
    return payload, _deterministic_hash(payload)


def analyze_vote(metadata):
    rules = []
    if metadata["vote_attempt_count"] >= 3 and metadata["time_between_attempts_sec"] <= 20:
        rules.append("RAPID_ATTEMPTS")
    if metadata["vote_attempt_count"] >= 5:
        rules.append("HIGH_FREQUENCY")
    if metadata["time_between_attempts_sec"] <= 10:
        rules.append("RETRY_PATTERN")

    payload, payload_hash = generate_decision_payload(metadata, rules)

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO ai_decisions
                (email, wallet, has_voted, decision, risk_score, rules_triggered, model_version, payload_json, payload_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                payload["email"],
                payload["wallet"],
                payload["has_voted"],
                payload["decision"],
                payload["risk_score"],
                payload["rules_triggered"],
                payload["model_version"],
                json.dumps(payload, sort_keys=True),
                payload_hash,
            ),
        )
        conn.commit()
    finally:
        cur.close()
        release_connection(conn)

    return payload, payload_hash
