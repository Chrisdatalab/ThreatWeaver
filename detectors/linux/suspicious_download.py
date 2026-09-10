from models.finding import Finding
import shlex,os
from urllib.parse import urlparse
SUSPICIOUS_DIRS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
]
SUSPICIOUS_EXTENSIONS = [
    ".sh",
    ".py",
    ".pl",
    ".elf",
    ".bin",
    ".so",
]
SUSPICIOUS_NAMES = [
    "payload",
    "backdoor",
    "reverse_shell",
    "implant",
    "shell",
]
def detect_suspicious_download(events):
    findings = []
    for event in events:
        if event.event_type != "sudo_command":
            continue
        command = event.attributes.get("command", "")   
        parts=shlex.split(command)
        if not parts:
            continue
        url=None
        destination=None
        risk_score = 0
        indicators = []
        details={}
        security="LOW"
        executable = os.path.basename(parts[0])
        if executable not in ["wget", "curl"]:
            continue
        for part in parts:
            if part.startswith("http://") or part.startswith("https://"):
                url = part
        if executable=="wget":
            
            if "-O" in parts:
                index=parts.index("-O")
                destination=parts[index+1]
            elif url:
                destination = os.path.basename(url)
            
        if executable == "curl":
            
            if "-o" in parts:
                index=parts.index("-o")
                destination=parts[index+1]
            elif "-O" in parts:
                index=parts.index("-O")
                if url:
                    destination=os.path.basename(url)
            
        filename = None
        extension = None
        if destination:
            filename = os.path.basename(destination)
            extension = os.path.splitext(filename)[1].lower()
            if destination and any(directory in destination for directory in SUSPICIOUS_DIRS):
                risk_score += 2
                indicators.append("suspicious_directory")
            if extension in SUSPICIOUS_EXTENSIONS:
                risk_score += 2
                indicators.append("suspicious_extension")

           
            if any(directory in destination for directory in SUSPICIOUS_DIRS):
                risk_score += 2
                indicators.append("suspicious_filename")

            
            if filename and filename.startswith("."):
                risk_score += 2
                indicators.append("hidden_file")
        if url:
            parsed = urlparse(url)
         #   remote_host = parsed.hostname
            if parsed.scheme == "http":
                risk_score += 1
                indicators.append("insecure_http")
        if risk_score >= 6:
            security = "high"
        elif risk_score >= 2:
            security = "medium"
        else:
            continue
        details["download_tool"] = executable
        details["url"] = url
        details["risk_score"]=risk_score
        details["indicators"]=indicators
        details["destination"] = destination
        details["raw_command"] = command
        finding = Finding(
                    finding_type="suspicious_download",
                    title="Suspicious Download Detected",
                    description=f"User {event.user} downloaded {url} to {destination} using {executable}.",
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