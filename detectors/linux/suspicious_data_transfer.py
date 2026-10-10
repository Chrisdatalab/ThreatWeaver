from models.finding import Finding
import shlex,os

def detect_suspicious_data_transfer(events):
    findings=[]
    for event in events:
        if event.event_type != "sudo_command":
            continue

        command = event.attributes.get("command", "")
        try:
            parts=shlex.split(command)
        except ValueError:
            continue

        if not parts:
            continue
        has_suspicious = False
        details={}
        executable = os.path.basename(parts[0])
        if executable in ["scp","rsync"]:
            has_suspicious=True
            security="MEDIUM"
        elif executable == "curl":
            for a in parts[1:]:
                if a in ["-T","--upload-file"]:
                    has_suspicious=True
                    security="MEDIUM"
                elif a== "-F":
                    index=parts.index(a)
                    if index+1<len(parts):
                        for b in parts[index+1:]:
                            if b.startswith("file=@"):
                                has_suspicious=True
                                security="MEDIUM"
        if not has_suspicious:
            continue
        details["command"]=command
        finding = Finding(
                finding_type="suspicious_data_transfer",
                title="Suspicious Data Transfer Detected",
                description=f"User {event.user} performed a potentially suspicious file transfer.",
                severity=security,
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