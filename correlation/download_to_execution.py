from datetime import datetime, timedelta
from models.finding import Finding

def correlate_download_to_execution(findings):
    suspicious_download = []
    suspicious_execution =[]
    correlated = []
    for finding in findings:
        if finding.finding_type=="suspicious_download":
            suspicious_download.append(finding)
        if finding.finding_type=="suspicious_execution":
            suspicious_execution.append(finding)
    for d in suspicious_download:
        d_time=d.start_time
        for  e in suspicious_execution:
            e_time=e.start_time
            if d.host!=e.host:
                continue
            if d.user != e.user:
                continue
            if d_time>=e_time:
                continue
            time_gap=e_time-d_time
            if time_gap>timedelta(minutes=15):
                continue
            if d.attributes.get("destination") is not None and e.attributes.get("executed_path") is not None:

                if d.attributes.get("destination")!=e.attributes.get("executed_path"):
                    continue
            else:
                continue
            correlation_finding = Finding(
                        finding_type="possible_payload_execution",
                        title="Suspicious Download Followed by Execution",
                        description=f"User {d.user} downloaded and executed the same suspicious file within a short time window.",
                        severity="critical",
                        source="linux",
                        host=e.host,
                        user=e.user,
                        src_ip=e.src_ip,
                        start_time=d.start_time,
                        event_count=d.event_count+e.event_count,
                        end_time=e.end_time,
                        events=d.events+e.events,
                        attributes={
                            "correlation_type": "download_to_execution",
                            "download_url": d.attributes.get("url"),
                            "download_tool": d.attributes.get("download_tool"),
                            "destination": d.attributes.get("destination"),
                            "executed_path": e.attributes.get("executed_path"),
                            "time_gap_seconds": time_gap.total_seconds()
                        }
                        
                    )
            correlated.append(correlation_finding)
    return correlated
