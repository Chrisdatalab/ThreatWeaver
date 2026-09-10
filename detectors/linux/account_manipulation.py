from models.finding import Finding
import shlex,os


SUPPORTED_COMMANDS = [
    "useradd",
    "usermod",
    "passwd",
    "userdel",
    "adduser",
    "deluser",
    "groupadd",
    "groupdel",
    "groupmod",
    "gpasswd",
    "chpasswd"
]
def detect_account_manipulation(events):
    findings = []
    for event in events:
        if event.event_type != "sudo_command":
            continue
        command = event.attributes.get("command", "")   
        parts=shlex.split(command)
        if not parts:
            continue
        executable = os.path.basename(parts[0])


        action = None
        target_user = None
        target_group = None
        new_group_name = None



        details = {}
        if executable not in SUPPORTED_COMMANDS:
            continue
        if executable in ["useradd", "adduser"]:
            shell = None
            create_home = False
            action = "create_user"
            if "-s" in parts:
                index = parts.index("-s")
                shell = parts[index + 1]
            if "-m" in parts:
                create_home = True
            details = {
                "shell": shell,
                "create_home": create_home
            }
            target_user=parts[-1]
            
        elif executable == "usermod":
            group = None
            append_group = False
            target_user=parts[-1]
            action = "modify_user"
            
            if "-aG" in parts:
                append_group = True
                index = parts.index("-aG")
                group = parts[index + 1]
            details = {
                "group": group,
                "append_group": append_group
            }
        elif executable == "passwd":
            action = "password_change"
            target_user=parts[-1]
            
        elif executable in ["userdel", "deluser"]:
            action = "delete_user"
            target_user=parts[-1]
        
        elif executable == "groupadd":
            action = "create_group"
            target_group = parts[-1]

        elif executable == "groupdel":
            action = "delete_group"
            target_group = parts[-1]

        elif executable=="groupmod":
            action = "modify_group"
            target_group = parts[-1]
            if "-n" in parts:
                index=parts.index("-n")
                new_group_name=parts[index + 1]
            details = {
                "new_group_name": new_group_name
            }
        elif executable == "gpasswd":
            target_user = None
            target_group = parts[-1]

            if "-a" in parts:
                action = "add_user_to_group"
                index = parts.index("-a")
                target_user = parts[index + 1]

            elif "-d" in parts:
                action = "remove_user_from_group"
                index = parts.index("-d")
                target_user = parts[index + 1]

            else:
                action = "modify_group"

            details = {
                "target_user": target_user,
                "target_group": target_group
            }
        elif executable == "chpasswd":
            action = "bulk_password_change"
            target_user = None

        details["action"]=action
        if target_user:
            target = target_user
        elif target_group:
            target = target_group
        else:
            target = "unknown"
        details["target"]=target
        details["raw_command"] = command

        finding = Finding(
                    finding_type="account_manipulation",
                    title="Account Manipulation Detected",
                    description=f"User {event.user} performed {action} on {target} using sudo.",
                    severity="high",
                    source="linux",
                    host=event.host,
                    user=event.user,
                    src_ip=event.src_ip,
                    start_time=event.timestamp,
                    event_count=1,
                    end_time=event.timestamp,
                    events=[event],
                    attributes=details,
                    
                )
        findings.append(finding)
        

                        
    return findings