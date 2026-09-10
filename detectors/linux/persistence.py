from models.finding import Finding
import shlex,os

def detect_persistence(events):
    findings = []
    for event in events:
        if event.event_type != "sudo_command":
            continue
        command = event.attributes.get("command", "")   
        parts=shlex.split(command)
        if not parts:
            continue
        details={}
        action=None
        service = None

        executable = os.path.basename(parts[0])
        if "crontab" in executable and "-e" in parts:
            persistence_type = "cron"
            action="edit_crontab"
        elif  "crontab -" in command:
            persistence_type = "cron"
            action="install_crontab"
        if executable == "systemctl" and "enable" in parts:

            action = "enable_systemd_service"
            persistence_type = "systemd"
            index=parts.index("enable")
            service = parts[index+1]
            
        if action:
            if action in ["install_crontab", "enable_systemd_service"]:
                severity = "high"
            else:
                severity = "medium"
           
            details["persistence_type"]=persistence_type
            details["action"]=action
            details["raw_command"]= command
            if persistence_type=="systemd":
                details["service"]=service
            finding = Finding(
                        finding_type="persistence",
                        title="Persistence Activity Detected",
                        description=f"User {event.user} performed {action} using sudo.",
                        severity=severity,
                        source="linux",
                        host=event.host,
                        user=event.user,
                        src_ip=event.src_ip,
                        start_time=event.timestamp,
                        event_count=1,
                        end_time=event.timestamp,
                        events=[event],
                        attributes=details
                        
                    )
            findings.append(finding)
    return findings
    