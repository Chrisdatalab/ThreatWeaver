from models.finding import Finding

SENSITIVE_PATHS = [
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/root/.ssh/",
]
READ_COMMANDS = ["cat", "less", "more", "head", "tail"]
ARCHIVE_COMMANDS = ["tar", "zip", "gzip"]
MODIFY_COMMANDS = ["vim", "nano", "chmod", "chown"]
DELETE_COMMANDS = ["rm", "shred"]

def detect_sensitive_file_access(events):
    findings = []
    for event in events:
        if event.event_type != "sudo_command":
            continue
        command = event.attributes.get("command", "")
        for path in SENSITIVE_PATHS:
            if path in command:
                
                if any(cmd in command for cmd in READ_COMMANDS):
                    attributes={
                        "action": "read",
                        "sensitive_path": path,
                        "raw_command": command
                    }
                elif any(cmd in command for cmd in ARCHIVE_COMMANDS):
                    attributes={
                            "action": "archive",
                            "sensitive_path": path,
                            "raw_command": command
                        }
                elif any(cmd in command for cmd in MODIFY_COMMANDS):
                    attributes={
                            "action": "modify",
                            "sensitive_path": path,
                            "raw_command": command
                        }
                elif any(cmd in command for cmd in DELETE_COMMANDS):
                    
                    attributes={
                            "action": "delete",
                            "sensitive_path": path,
                            "raw_command": command
                        }
                else:
                    
                    attributes={
                        "action": "access",
                        "sensitive_path": path,
                        "raw_command": command
                        }
                
                   
                finding = Finding(
                    finding_type="sensitive_file_access",
                    title="Sensitive File Access Detected",
                    description=f"User {event.user} accessed sensitive file {path} using sudo.",
                    severity="high",
                    source="linux",
                    host=event.host,
                    user=event.user,
                    src_ip=event.src_ip,
                    start_time=event.timestamp,
                    event_count=1,
                    end_time=event.timestamp,
                    events=[event],
                    attributes=attributes
                )
                findings.append(finding)
                break

                
    return findings