from collections import defaultdict
from datetime import datetime, timedelta
from models.finding import Finding

def parse_timestamp(timestamp: str) -> datetime:
    return datetime.strptime(timestamp, "%b %d %H:%M:%S")
def detect_ssh_bruteforce(events,threshold=5,window_minutes=5):
    failed_events = []
#登录失败列表
    for event in events:
         if (
                event.event_type == "ssh_login_failed"
                and event.src_ip != "unknown"
                and event.user != "unknown"
                and event.timestamp != "unknown"
            ):
            failed_events.append(event)
    groups = defaultdict(list)
#host ip user绑定的失败hashmap
    for event in failed_events:
        key = (event.host, event.src_ip, event.user)
        groups[key].append(event)
    findings = []
    for key,group_events in groups.items():
        group_events.sort(key=lambda event: parse_timestamp(event.timestamp))
        #按时间排序
    
        left=0
        for right in range(len(group_events)):

            right_time = parse_timestamp(group_events[right].timestamp)
            

            while left <= right:

                left_time = parse_timestamp(group_events[left].timestamp)

                time_difference = right_time - left_time

                if time_difference <= timedelta(minutes=window_minutes):
                    break

                left += 1

            failed_count = right - left + 1

            # 4. 达到阈值
            if failed_count >= threshold:

                host, src_ip, user = key

                finding = Finding(
                    finding_type="ssh_bruteforce",
                    title="Possible SSH Brute Force",
                    description="Multiple SSH login failures detected within a short time window.",
                    severity="high",
                    source="linux",
                    host=host,
                    user=user,
                    src_ip=src_ip,
                    start_time=group_events[left].timestamp,
                    end_time=group_events[right].timestamp,
                    event_count=failed_count,
                    events=group_events[left:right + 1],
                    attributes={
                        "threshold": threshold,
                        "window_minutes": window_minutes
                    }
                )

                findings.append(finding)
                break

    return findings