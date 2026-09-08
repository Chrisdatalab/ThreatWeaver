# ThreatWeaver

ThreatWeaver is a modular security log detection and correlation project.

## Current Features

- Linux authentication log parsing
- Normalized Event and Finding models
- SSH brute-force detection
- Sliding-window detection
- Console reporting

## Architecture

```text
Raw Logs
→ Parser
→ Event
→ Detector
→ Finding
→ Correlation
→ Incident
→ Reporting
```

## Run
```
    python app.py
  ```

## Roadmap

More Linux detections
Windows Event Log analysis
Web log analysis
Cross-event correlation
Incident timelines
JSON / HTML reports
MITRE ATT&CK mapping
AI-assisted analysis
Status

Early development.