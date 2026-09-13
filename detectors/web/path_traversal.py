from models.finding import Finding

TRAVERSAL_PATTERNS = [
    "../",
    "..\\",
]
SENSITIVE_TARGETS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh",
    "/root/.ssh",
    "windows/system32",
    "boot.ini",
    "/proc/version",
    "/proc/self/",
]
def detect_path_traversal(events):
    findings = []
  
    for event in events:
        risk_score=0
        severity="LOW"
        if event.event_type != "web":
            continue

        decoded_path = event.attributes.get("decoded_path", "")
        path_lower = decoded_path.lower()
        
        has_traversal = any(
                    pattern in path_lower
                    for pattern in TRAVERSAL_PATTERNS
                )
        
        if not has_traversal:
            continue
        traversal_count = (
                    path_lower.count("../")
                    + path_lower.count("..\\")
                )
        risk_score += 2

        if traversal_count >= 2:
            risk_score += 1

        if traversal_count >= 5:
            risk_score += 1
       
        has_sensitive_target = any(
                        target in path_lower
                        for target in SENSITIVE_TARGETS
                    )
        if has_sensitive_target:
            risk_score += 2
        if risk_score >= 5:
            severity = "CRITICAL"
        elif risk_score >= 3:
            severity = "HIGH"
        else:
            severity = "MEDIUM"
        details = {
            "raw_target": event.attributes.get("raw_target", ""),
            "decoded_path": decoded_path,
            "traversal_count": traversal_count,
            "sensitive_target": has_sensitive_target,
            "risk_score": risk_score,
            "status_code": event.attributes.get("status_code"),
        }
        finding = Finding(
            finding_type="path_traversal",
            title="Path Traversal Attempt Detected",
            description=f"Source IP {event.src_ip} attempted path traversal.",
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