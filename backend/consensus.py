import json


def validator_rule_based(metadata):
    count = metadata["vote_attempt_count"]
    delta = metadata["time_between_attempts_sec"]
    if count >= 5 and delta <= 10:
        return "BLOCK", ["HIGH_FREQUENCY", "RETRY_PATTERN"]
    if count >= 3 and delta <= 20:
        return "FLAG", ["RAPID_ATTEMPTS"]
    return "ALLOW", []


def validator_statistical(metadata):
    # Deterministic heuristic proxy for "statistical" behavior
    count = metadata["vote_attempt_count"]
    delta = metadata["time_between_attempts_sec"]
    score = 0.1
    if count >= 4:
        score += 0.3
    if delta <= 15:
        score += 0.3
    if count >= 7:
        score += 0.3

    if score >= 0.7:
        return "BLOCK", ["STAT_OUTLIER"]
    if score >= 0.4:
        return "FLAG", ["STAT_OUTLIER"]
    return "ALLOW", []


def run_consensus(ai_verdict, metadata):
    validators = {
        "ai": {"verdict": ai_verdict, "rules": ["AI_DECISION"]},
        "rule_based": {},
        "statistical": {},
    }

    rule_verdict, rule_rules = validator_rule_based(metadata)
    stat_verdict, stat_rules = validator_statistical(metadata)
    validators["rule_based"] = {"verdict": rule_verdict, "rules": rule_rules}
    validators["statistical"] = {"verdict": stat_verdict, "rules": stat_rules}

    votes = [v["verdict"] for v in validators.values()]
    if votes.count("BLOCK") >= 2:
        final_verdict = "BLOCK"
    elif votes.count("FLAG") >= 2:
        final_verdict = "FLAG"
    else:
        final_verdict = "ALLOW"

    return final_verdict, validators, json.dumps(validators, sort_keys=True)
