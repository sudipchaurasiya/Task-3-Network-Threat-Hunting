# Task 3: Advanced Network Threat Hunting and Incident Investigation

## Overview
This project investigates network traffic using Wireshark and supporting command-line tools.

## Objectives
- Analyze DNS, HTTP, TLS, and TCP traffic.
- Investigate an observed executable download.
- Record indicators of compromise and an event timeline.
- Develop defensive detection filters and rules.

## Key Findings
- An HTTP request downloaded `runner_ilove.exe` from `107.175.82.242:9000`.
- The recovered executable's SHA-256 hash was recorded and compared.
- Additional DNS and HTTP activity was investigated.
- The executable was not run during the investigation.

## Important Limitation
The download was confirmed, but the available evidence does not establish that the executable is malicious or that all suspicious-looking network activity is related.

## Repository Contents
- `Evidence_Screenshots/` — investigation evidence
- `Task3_IOC_Table.csv` — recorded indicators
- `Task3_Detection_Filters_and_Rules.md` — filters and detection-rule examples
- `event_timeline.txt` — observed event sequence
- `static_analysis_notes.txt` — static analysis observations
- `Task3_Final_Report.pdf` — final report, to be added

## Safety
The executable and raw packet capture are intentionally excluded from this public repository.
