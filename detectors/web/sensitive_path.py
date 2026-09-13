from models.finding import Finding

SENSITIVE_PATHS = [
    "/wp-login.php",
    "/wp-admin",
    "/administrator",
    "/phpmyadmin",
    "/.env",
    "/.git",
    "/server-status",
]
def detect_sensitive_path(events):
    findings = []
    hits_by_ip = {}
    
    for event in events:
        if event.event_type != "web":
            continue
        
        
        decoded_path = event.attributes.get("decoded_path", "")
        path_lower = decoded_path.lower()
    
        for sensitive_path in SENSITIVE_PATHS:
            if sensitive_path in path_lower:
                key=event.src_ip
                if key not in hits_by_ip:
                    hits_by_ip[key] = {
                        "s_events": [],
                        "paths": []
                    }
             
                hits_by_ip[key]["s_events"].append(event)
                hits_by_ip[key]["paths"].append(path_lower)
                break
                
    for key,value in hits_by_ip.items():
        
        group_events = value["s_events"]

        if len(group_events) <= 2:
            continue
        sample_event = group_events[0]
        start_time = min(event.timestamp for event in group_events)
        end_time = max(event.timestamp for event in group_events)
        details={}

        severity="HIGH"
        hit_count = len(value["s_events"])
        unique_paths = list(set(value["paths"]))
        details["hit_count"]=hit_count
        details["unique_paths"]=unique_paths
        finding=Finding(
                finding_type="sensitive_path_probing",
                title="Sensitive Path Probing Detected",
                description=f"Source IP {key} repeatedly accessed sensitive web paths.",
                severity=severity,
                source="web",
                host=sample_event.host,
                user=sample_event.user,
                src_ip=key,
                start_time=start_time,
                end_time=end_time,
                event_count=hit_count,
                events=group_events,
                attributes=details
            )
        findings.append(finding)


    return findings