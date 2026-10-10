from models.finding import Finding
import shlex,os

def detect_ld_preload_tampering(events):
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
        for n in parts:
            if "LD_PRELOAD=" in n:
                has_suspicious=True
                security="MEDIUM"
        if executable in ["rm","truncate"]:
            for a in parts[1:]:
                if a.endswith("/etc/ld.so.preload"):
                    has_suspicious=True
                    security="MEDIUM"
        elif executable in ["cp", "mv"]:
            a = parts[-1]
            if a.endswith("/etc/ld.so.preload"):
                has_suspicious=True
                security="HIGH"
        elif executable == "sed":
            for a in parts[1:]:
                if a == "-i":
                    index=parts.index(a)
                    if index+1<len(parts):
                        for b in parts[index+1:]:
                            if b.endswith("/etc/ld.so.preload"):
                                has_suspicious=True
                                security="HIGH"
        elif executable in ["bash","sh"]:
            for a in parts[1:]:
                if a=="-c":
                    index=parts.index(a)
                    if index+1<len(parts):
                        b = parts[index+1]
                        try:
                            p=shlex.split(b)
                        
                        except ValueError:
                            continue
                        for n in p:
                            if p[0]=="echo" or p[0]=="printf":
                                for c in p[1:]:
                                    if c in [">",">>"]:
                                        index=p.index(c)
                                        if index+1<len(p):
                                            for d in p[index+1:]:
                                                if d.endswith("/etc/ld.so.preload"):
                                                    has_suspicious=True
                                                    security="HIGH"
                                    elif c.startswith(">/") or c.startswith(">>/"):
                                        d=c.lstrip(">")
                                        if "/etc/ld.so.preload"==d:
                                            has_suspicious=True
                                            security="HIGH"

        elif executable == "tee":
            for a in parts[1:]:
                if a.endswith("/etc/ld.so.preload"):
                    has_suspicious=True
                    security="HIGH"
        if not has_suspicious:
            continue
        details["command"]=command
        finding = Finding(
                finding_type="ld_preload_tampering",
                title="LD_PRELOAD Tampering Detected",
                description=f"User {event.user} performed suspicious LD_PRELOAD activity.",
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