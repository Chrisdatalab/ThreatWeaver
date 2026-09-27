from models.finding import Finding
import shlex,os

EXEC_PERMISSION_MODES = [
    "+x",
    "u+x",
    "g+x",
    "o+x",
    "a+x",
]
EXEC_NUMERIC_MODES = [
    "700",
    "711",
    "744",
    "755",
    "770",
    "775",
    "777",
]
SUSPICIOUS_DIRS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
]
SUID_SGID_MODES = [
    "u+s",
    "g+s",
    "ug+s",
    "a+s",
]
CAP_ABILITY =[
    "cap_setuid",
    "cap_setgid",
    "cap_sys_admin",
    "cap_dac_override",
    "cap_sys_ptrace",
]

def check_4digit_mode(n):
    v1=n%10
    n=n//10
    v2=n%10
    n=n//10
    v3=n%10
    v4=n//10
    if v1<=7 and v1>=0 and v2<=7 and v2>=0 and v3<=7 and v3>=0 and v4<=7 and v4>=2:
        return True
    return False
def detect_suspicious_permission_change(events):
    findings=[]
    for event in events:
        if event.event_type != "sudo_command":
            continue

        command = event.attributes.get("command", "")
        parts=shlex.split(command)
        if not parts:
            continue
        suspicious_permission=""
        has_special_mode = False
        has_exec_mode = False
        has_suspicious_path = False
        suspicious_path = False
        matched_mode=""
        matched_capability=""
        details={}
        executable = os.path.basename(parts[0])

        if executable=="chmod":
            for v in parts[1:]:
                if v in SUID_SGID_MODES:
                    has_special_mode=True
                    matched_mode=v
                elif v.isdigit() and len(v)==4:
                    if check_4digit_mode(int(v)):
                        has_special_mode=True
                        matched_mode=v
                if v in EXEC_PERMISSION_MODES or v in EXEC_NUMERIC_MODES:
                    has_exec_mode = True
                    
                if any(v.startswith(argument) for argument in SUSPICIOUS_DIRS):
                    has_suspicious_path = True
                if has_exec_mode and has_suspicious_path:
                    break
            if has_special_mode:
                suspicious_permission ="SUID_SGID_MODES"
            elif has_exec_mode and has_suspicious_path:
                suspicious_permission = "executable"
        elif executable == "setcap":
            if len(parts)<3:
                continue
            if parts[1]=="-r":
                continue
            capability_spec = parts[1]
            target_paths = parts[2:]
            for cap in CAP_ABILITY:
                if cap in capability_spec  :
                    security="HIGH"
                    matched_capability=cap
                    suspicious_permission = "CAP"
            for v in target_paths:

                if any(v.startswith(argument) for argument in SUSPICIOUS_DIRS):
                    security="CRITICAL"
                    suspicious_path=True
                        
        if suspicious_permission == "executable" :
            
            security="HIGH"
            details["raw_command"]=command
            finding = Finding(
                    finding_type="suspicious_permission_change",
                    title="Suspicious Permission Change Detected",
                    description=f"User {event.user} added executable permissions to a file in a suspicious directory.",
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
        elif suspicious_permission =="SUID_SGID_MODES":
            security="HIGH"
            details["raw_command"]=command
            details["matched_mode"]=matched_mode
            finding = Finding(
                    finding_type="suid_sgid_permission_change",
                    title="SUID/SGID Permission Change Detected",
                    description=f"User {event.user} configured SUID/SGID special permissions on a file.",
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
        elif suspicious_permission == "CAP" :
                    
                
                details["raw_command"]=command
                details["matched_capability"]=matched_capability
                details["suspicious_path"] = suspicious_path
                details["target_paths"] = target_paths
                finding = Finding(
                        finding_type="suspicious_capability_change",
                        title="Suspicious Linux Capability Change Detected",
                        description=f"User {event.user} assigned a high-risk Linux capability to a file.",
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