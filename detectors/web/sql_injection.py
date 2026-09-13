from models.finding import Finding

STRONG_SQLI_PATTERNS = [
    "union select",
    "waitfor delay",
    "sleep(",
    "benchmark(",
]
BOOLEAN_SQLI_PATTERNS = [
    " or 1=1",
    " and 1=1",
    "' or '",
    '" or "',
    "' and '",
    '" and "',
]
def detect_sql_injection(events):
    findings = []

    for event in events:
        if event.event_type != "web":
            continue
        decoded_query = event.attributes.get("decoded_query", "")
        query_lower = decoded_query.lower()
        
        has_strong_sqli = any(
            pattern in query_lower
            for pattern in STRONG_SQLI_PATTERNS
        )

        has_boolean_sqli = any(
            pattern in query_lower
            for pattern in BOOLEAN_SQLI_PATTERNS
        )
        if not has_strong_sqli and not has_boolean_sqli:
            continue
        risk_score = 0

        if has_strong_sqli:
            risk_score += 3

        if has_boolean_sqli:
            risk_score += 2

        if "--" in query_lower:
            risk_score += 1
        
        if risk_score >= 4:
            severity = "CRITICAL"
        else:
            severity = "HIGH"
        details = {
            "raw_target": event.attributes.get("raw_target", ""),
            "decoded_query": decoded_query,
            "strong_sqli": has_strong_sqli,
            "boolean_sqli": has_boolean_sqli,
            "sql_comment": "--" in query_lower,
            "risk_score": risk_score,
            "status_code": event.attributes.get("status_code"),
        }
        finding=Finding(
            finding_type="sql_injection",
            title="SQL Injection Attempt Detected",
            description=f"Source IP {event.src_ip} sent a suspicious SQL injection payload.",
            severity=severity,
            source="web",
            host=event.host,
            user=event.user,
            src_ip=event.src_ip,
            start_time=event.timestamp,
            end_time=event.timestamp,
            event_count=1,
            events=[event],
            attributes=details
        )
        findings.append(finding)
    return findings