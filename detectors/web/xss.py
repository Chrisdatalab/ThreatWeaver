from models.finding import Finding

STRONG_XSS_PATTERNS = [
    "<script",
    "</script>",
    "javascript:",
    "data:text/html",
]

EVENT_HANDLER_PATTERNS = [
    "onerror=",
    "onload=",
    "onfocus=",
    "onclick=",
    "onmouseover=",
    "onmouseenter=",
]

HTML_TAG_PATTERNS = [
    "<img",
    "<svg",
    "<iframe",
    "<object",
    "<embed",
    "<body",
    "<video",
    "<audio",
]

SCRIPT_PATTERNS = [
    "alert(",
    "prompt(",
    "confirm(",
    "document.cookie",
    "document.domain",
    "window.location",
]
def detect_xss(events):
    findings = []
    
    for event in events:
        if event.event_type != "web":
            continue
        risk_score=0
        decoded_path = event.attributes.get("decoded_path", "")
        decoded_query = event.attributes.get("decoded_query", "")

        xss_text = (decoded_path + " " + decoded_query).lower()
   
        has_strong_xss = any(v in xss_text for v in STRONG_XSS_PATTERNS)
        has_event_handler = any(v in xss_text for v in EVENT_HANDLER_PATTERNS)
        has_html_tag = any(v in xss_text for v in HTML_TAG_PATTERNS)
        has_script_pattern = any(v in xss_text for v in SCRIPT_PATTERNS)
        if has_strong_xss:
            risk_score += 4

        if has_event_handler:
            risk_score += 3

        if has_html_tag:
            risk_score += 2

        if has_script_pattern:
            risk_score += 1
        if risk_score <= 3:
            continue
        if risk_score >= 6:
            severity = "CRITICAL"
        else:
            severity = "HIGH"
        details = {
            "raw_target": event.attributes.get("raw_target", ""),
            "decoded_path": decoded_path,
            "decoded_query": decoded_query,
            "strong_xss": has_strong_xss,
            "event_handler": has_event_handler,
            "html_tag": has_html_tag,
            "script_pattern": has_script_pattern,
            "risk_score": risk_score,
            "status_code": event.attributes.get("status_code"),
        }


        finding=Finding(
                finding_type="xss",
                title="Cross-Site Scripting Attempt Detected",
                description=f"Source IP {event.src_ip} sent a suspicious XSS payload.",
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