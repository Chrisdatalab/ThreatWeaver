
def print_findings(findings):
    for finding in findings:
        print("=" * 50)
        print(f"[{finding.severity.upper()}] {finding.title}")
        print()
        print(f"Type:       {finding.finding_type}")
        print(f"Source:     {finding.source}")
        print(f"Host:       {finding.host}")
        print(f"Source IP:  {finding.src_ip}")
        print(f"User:       {finding.user}")
        print(f"Start Time: {finding.start_time}")
        print(f"End Time:   {finding.end_time}")
        print(f"Events:     {finding.event_count}")

        if finding.attributes:
            print("Attributes:")
            for key, value in finding.attributes.items():
                print(f"  {key}: {value}")

        print()