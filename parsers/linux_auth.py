import re
from datetime import datetime
from models.event import Event

def parse_line(line: str) -> Event:
   
    event_type = "unknown"
    action = "unknown"
    outcome = "unknown"
    message='unknown'
    timestamp = "unknown"
    host = "unknown"
    process = "unknown"
    pid = None

    user = "unknown"
    src_ip = "unknown"
    src_port = None

    pattern = (

        r"(?P<month>\w+)\s+"
        r"(?P<day>\d+)\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<process>[^\[:]+)"
        r"(?:\[(?P<pid>\d+)\])?:\s*"
        r"(?P<message>.*)"
    )
    
    match = re.match(pattern, line)

    if match:
        timestamp=match.group("month")+" "+match.group("day")+" "+match.group("time")
        host=match.group("host")
        process=match.group("process")
        
        pid=match.group("pid")
        if pid:
            pid = int(pid)
        message=match.group("message")
    
    login_pattern=(
        r"Accepted (?:password|publickey) for "
        r"(?P<user>\S+) "
        r"from (?P<src_ip>\S+) "
        r"port (?P<src_port>\d+)"
    )
    login_search=re.search(login_pattern,message)
    if login_search:
        user=login_search.group("user")
        src_ip=login_search.group("src_ip")
        src_port = int(login_search.group("src_port"))

    session_pattern = (
        r"session (?:opened|closed) for user "
        r"(?P<user>\S+)"
    )

    session_search = re.search(session_pattern, message)
    if session_search:
            user = session_search.group("user")
    failed_pattern = (
        r"Failed password for "
        r"(?:invalid user )?"
        r"(?P<user>\S+) "
        r"from (?P<src_ip>\S+) "
        r"port (?P<src_port>\d+)"
    )
    failed_search=re.search(failed_pattern,message)

    if failed_search:
        user=failed_search.group("user")
        src_ip=failed_search.group("src_ip")
        src_port = int(failed_search.group("src_port"))

    invalid_pattern = (
        r"Invalid user "
        r"(?P<user>\S+) "
        r"from (?P<src_ip>\S+) "
        r"port (?P<src_port>\d+)"
    )

    invalid_search = re.search(invalid_pattern, message)

    if invalid_search:
        user = invalid_search.group("user")
        src_ip = invalid_search.group("src_ip")
        src_port = int(invalid_search.group("src_port"))
    if "Failed password" in line:
        event_type = "ssh_login_failed"
        action = "login"
        outcome = "failure"
    elif process == "sshd" and "Invalid user" in message:
        event_type = "ssh_invalid_user"
        action = "login"
        outcome = "failure"
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "ssh_login_success"
        action = "login"
        outcome = "success"
    elif process == "sshd" and "session opened for user" in message:
        event_type = "ssh_session_open"
        action = "session"
        outcome = "success"

    elif process == "sshd" and "session closed for user" in message:
        event_type = "ssh_session_close"
        action = "session"
        outcome = "success"
    return Event(
        source="linux",
        timestamp=timestamp,
        host=host,
        process=process,
        pid=pid,
        event_type=event_type,
        action=action,
        outcome=outcome,
        message=message,
        user=user,
        src_ip=src_ip,
        src_port=src_port,
        raw=line.strip()
    )