#!/usr/bin/env python3
"""Parse Sysmon Event ID 1 (Process Creation) XML and emit key fields as JSON."""

import json
import sys
import xml.etree.ElementTree as ET

# Sysmon events use this default namespace on every element.
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Fields pulled from <EventData> <Data Name="..."> entries.
DATA_FIELDS = [
    "UtcTime",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "ParentImage",
    "ParentCommandLine",
    "Hashes",
]


def extract_event(event):
    """Extract the key fields from a single <Event> element into a dict."""
    result = {}

    # EventID and Computer live under <System>.
    event_id = event.find("./e:System/e:EventID", NS)
    result["EventID"] = event_id.text if event_id is not None else None

    # Map every <Data Name="X"> child to its text.
    data = {
        d.get("Name"): d.text
        for d in event.findall("./e:EventData/e:Data", NS)
    }
    result["UtcTime"] = data.get("UtcTime")
    result["Image"] = data.get("Image")
    result["CommandLine"] = data.get("CommandLine")
    result["User"] = data.get("User")
    result["IntegrityLevel"] = data.get("IntegrityLevel")
    result["ParentImage"] = data.get("ParentImage")
    result["ParentCommandLine"] = data.get("ParentCommandLine")

    computer = event.find("./e:System/e:Computer", NS)
    result["Computer"] = computer.text if computer is not None else None

    result["Hashes"] = data.get("Hashes")

    return result


def parse_file(path):
    """Parse an XML file that contains one or more <Event> elements."""
    tree = ET.parse(path)
    root = tree.getroot()

    # The root may itself be an <Event>, or a container of <Event> elements.
    if root.tag == f"{{{NS['e']}}}Event":
        events = [root]
    else:
        events = root.findall(".//e:Event", NS)

    return [extract_event(ev) for ev in events]


def main(argv):
    if len(argv) != 2:
        print(f"Usage: {argv[0]} <sysmon-event.xml>", file=sys.stderr)
        return 2

    try:
        events = parse_file(argv[1])
    except ET.ParseError as exc:
        print(f"Error: failed to parse XML: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # Always emit a JSON array, one object per event.
    print(json.dumps(events, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
