# sysmon-parser
My first security tool, built with Claude as part of the Just Hacking Training "Practical AI Cyber Defense Ops" cohort. 

A Python parser that extracts detection-relevant fields from Sysmon event XML into clean JSON.

## Scope

- Input is rendered Sysmon event XML, the kind you get from a SIEM export.
- Current focus is Event ID 1 (Process Creation). The extracted field set is tuned for it.

## Fields extracted (Event ID 1)

```
EventID, UtcTime, Image, CommandLine, User, IntegrityLevel, ParentImage, ParentCommandLine, Computer, Hashes
```
