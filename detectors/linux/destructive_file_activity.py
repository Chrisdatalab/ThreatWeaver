from models.finding import Finding
import shlex,os

SUS_PATH = [
    "/var/www",
    "/home",
    "/etc",
    "/etc/passwd"
    ]
def detect_destructive_file_activity(events):
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
        if executable == "rm":
            for a in parts[1:]:
                if a in ["-rf","-f"]:
                    index=parts.index(a)
                    if index+1<len(parts):
                        for c in parts[index+1:]:
                            if c.endswith(p) for any p in SUS_PATH:
                                security="HIGH"
                                has_suspicious=True
        elif executable == "shred":
            for a in parts[1:]:
                if a in ["-u","-z"]:
                    index=parts.index(a)
                    if index+1<len(parts):
                        for c in parts[index+1:]:
                            if c.endswith("/home/admin/secret.txt") or c.endswith("/etc/shadow"):
                                security="HIGH"
                                has_suspicious=True
        elif executable == "find":
            for a in parts[1:]:
                if a in SUS_PATH:
                    index=parts.index(a)
                    if index+1<len(parts):
                        for c in parts[index+1:]:
                            if c=="-delete":
                                security="HIGH"
                                has_suspicious=True
        elif executable == "truncate":
            for a in parts[1:]:
                if a == "s":
                    index=parts.index(a)
                    if index+1<len(parts):
                        if parts[index+1]==0:
                            for n in parts[index+1:]:
                                if n in SUS_PATH:
                                    security="HIGH"
                                    has_suspicious=True
        elif executable == "dd":
            for a in parts[1:]:
                if a.startswith("of="):
                    b=a.lstrip("of=")
                    if b in IM_PATH:
                        security="HIGH"
                        has_suspicious=True
        if not has_suspicious:
            continue
        details["command"]=command
        finding = Finding(
                finding_type="detect_destructive_file_activity",
                title="Destructive file activity Detected",
                description=f"User {event.user} performed a potentially suspicious detect destructive file activity.",
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

