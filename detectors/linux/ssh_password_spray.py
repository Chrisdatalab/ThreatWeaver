from models.finding import Finding
from collections import defaultdict
from models.event import Event
from datetime import datetime, timedelta

def parse_timestamp(timestamp: str) -> datetime:
    return datetime.strptime(timestamp, "%b %d %H:%M:%S")
def detect_ssh_password_spray(events: list[Event],threshold=5,
    window_minutes=5):
    findings=[]
    failed_events = []
    for event in events:
        if (event.event_type=="ssh_login_failed" 
        and event.src_ip!="unknown"
        and event.host!="unknown"
        and event.user!="unknown"
        and event.timestamp!="unknown"
        ):
            failed_events.append(event)
    groups = defaultdict(list)
    
    for event in failed_events:
        key=(event.host,event.src_ip)
        groups[key].append(event)
    for key,fail_event in groups.items():
        fail_event.sort(key=lambda event: parse_timestamp(event.timestamp))
        left=0
    
        for right in range(len(fail_event)):

            right_time = parse_timestamp(fail_event[right].timestamp)
          
            while left <= right:

                left_time = parse_timestamp(fail_event[left].timestamp)

                time_difference = right_time - left_time

                if time_difference > timedelta(minutes=window_minutes):
                    left += 1
                else:
                    break
            unique_users = {
                                event.user
                                for event in fail_event[left:right + 1]
                            }
            
                

            failed_count = right - left + 1
            if len(unique_users)>=threshold:
                host,src_ip=key
                finding = Finding(
                        finding_type="ssh_password_spray",
                        title="Possible SSH Spray",
                        description="Multiple SSH login failures detected within a short time window by the same ip many user",
                        severity="high",
                        source="linux",
                        host=host,
                       # user=user,
                        src_ip=src_ip,
                        start_time=fail_event[left].timestamp,
                        end_time=fail_event[right].timestamp,
                        event_count=failed_count,
                        events=fail_event[left:right + 1],
                        attributes={
                            "threshold": threshold,
                            "window_minutes": window_minutes,
                            "unique_user_count": len(unique_users),
                            "unique_user": sorted(unique_users)
                        }
                    )
    
                findings.append(finding)
                break
    return findings