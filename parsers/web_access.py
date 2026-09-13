from datetime import datetime
from urllib.parse import urlsplit, unquote, unquote_plus
from models.event import Event
import re

def parse_line(line: str, year= None) -> Event:
    event_type = "web"
    timestamp = None

    host = "unknown"
    process = "unknown"
    user = "unknown"

    src_ip = "unknown"
    src_port = None
    pid = None
    method = "unknown"
    raw_target = "unknown"
    path = "unknown"
    query_string = ""
    decoded_path = "unknown"
    decoded_query = ""

    protocol = "unknown"
    status_code = None
    bytes_sent = None

    referer = "unknown"
    user_agent = "unknown"
    raw_request = "unknown"

    raw_line  = line.strip()
    line = raw_line
    if line.startswith('"') and line.endswith('"'):
        line = line [1:-1]

   # parts = line.split('"')
    parts = re.split(r'(?<!\\)"', line)
    if len(parts) < 6:
        print("SKIP malformed web log:", raw_line)
        return None
    prefix = parts[0].split()
    if len(prefix) < 5:
        print("BAD PREFIX:", raw_line)
        return None
    src_ip=prefix[0]
    timestamp_text = prefix[3] + " " + prefix[4]
    timestamp_text = timestamp_text.strip("[]")
    timestamp = datetime.strptime(
                            timestamp_text,
                            "%d/%b/%Y:%H:%M:%S %z"
                        )
    raw_request = parts[1]
    request_parts = raw_request.split()
    if len(request_parts) < 3:
        return None
    method = request_parts[0]
    protocol = request_parts[-1]
    raw_target = " ".join(request_parts[1:-1])
    target = urlsplit(raw_target)

    path = target.path
    query_string = target.query

    response_parts = parts[2].split()
    
    if len(response_parts) < 2:
        return None
    status_code = int(response_parts[0])
    if response_parts[1]!="-":
        bytes_sent = int(response_parts[1])
    else:
        bytes_sent = None
    referer = parts[3]
    user_agent = parts[5]

    decoded_path = unquote(path)
    decoded_query = unquote_plus(query_string)
    if status_code < 400:
        outcome = "success"
    else:
        outcome = "failure"

    attributes = {
        "method": method,
        "raw_target": raw_target,
        "path": path,
        "query_string": query_string,
        "decoded_path": decoded_path,
        "decoded_query": decoded_query,
        "protocol": protocol,
        "status_code": status_code,
        "bytes_sent": bytes_sent,
        "referer": referer,
        "user_agent": user_agent,
        "raw_request": raw_request,
    }
    return Event(
            source="Web",
            event_type=event_type,
            timestamp=timestamp,
            host=host,
            src_ip=src_ip,
            process=process,
            pid=pid,
            
            action=method,
            outcome=outcome,
            message=raw_request,
            user=user,
            
            src_port=src_port,
            attributes=attributes,
            raw=raw_line
        )