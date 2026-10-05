from models.finding import Finding
from helper.command_linux_parser import parse_command
import os
# dectects suspicious modifications to systemd service files
# moitors command creat copy install edit or write  .service files
# under /etc/systemd/system/, as well as daemon-reloud activity
# There behaviors may indicate systemd-based persistence or privilege abuse

action = [
    "cp",
    "mv",

    ]
def detect_systemd_service_modification(events):
    findings = []
    for event in events:
        if event.event_type != "sudo_command":
            continue
        command = event.attributes.get("command", "")   
        parts=parse_command(command)
        if not parts:
            continue
        has_sus=False
        details={}
        sus_act=""
        security=""
        service_path=""
        executable = os.path.basename(parts[0])
        if executable in ["touch", "tee"]:
            for v in parts[1:]:
                if v.endswith(".service") and "/etc/systemd/system/" in v:
                    sus_act="change_service_file"
                    security="HIGH"
                    service_path=v
                    has_sus=True
        elif executable in action:
            if parts[-1].endswith(".service") and "/etc/systemd/system/" in parts[-1]:
                sus_act="change_service_file"
                security="HIGH"
                service_path=parts[-1]
                has_sus=True
        elif executable=="install":
            for a in parts[1:]:
                if a.endswith (".service") and "/etc/systemd/system/" in a:
                    sus_act="change_service_file"
                    security="HIGH"
                    service_path=a
                    has_sus=True
                elif a=="-t":
                    index=parts.index(a)
                    if (index+1)<len(parts):
                        
                        if "/etc/systemd/system" in parts[index+1]:
                            sus_act="change_service_file"
                            security="HIGH"
                            service_path=parts[index+1]
                            has_sus=True
        elif executable=="sed":
            if len(parts)>1:
                for a in parts[1:]:
                    if a=="-i" or a.startswith("-i."):
                        index=parts.index(a)
                        for v in parts[index+1:]:
                            if v.endswith(".service") and "/etc/systemd/system/" in v:
                                sus_act="change_service_file"
                                security="HIGH"
                                service_path=v
                                has_sus=True
        elif executable in ["echo","cat","bash"]:
            for v in parts[1:]:
                if v==">" or v==">>":
                    index=parts.index(v)
                    for a in parts[index+1:]:
                        if a.endswith(".service") and "/etc/systemd/system/" in a:
                            sus_act="change_service_file"
                            security="HIGH"
                            service_path=a
                            has_sus=True
        elif executable=="systemctl":
            if len(parts)>1:
                for v in parts[1:]:
                    if v=="daemon-reload":
                        sus_act="reload_systemd_configuration"
                        security="MEDIUM"
                        has_sus=True
                        break
        if not has_sus:
            continue
        details["raw_command"]=command
        details["sus_act"]=sus_act
        details["service_path"]=service_path
        finding = Finding(
                    finding_type="systemd_service_modification",
                    title="Systemd Service Modification Detected",
                    description=f"{event.user} {sus_act}",
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