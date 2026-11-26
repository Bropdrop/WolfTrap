"""Record executed synthetic host source lines externally during a single mutation trial."""
import json
from pathlib import Path
import sys

import experiment

target = Path(experiment.host.__file__).resolve()
lines = target.read_text().splitlines()
events = []


def record(frame, event, arg):
    if frame.f_code.co_filename != str(target):
        return None
    if event == "line":
        events.append([frame.f_code.co_name, frame.f_lineno, lines[frame.f_lineno - 1].strip()])
    return record


if __name__ == "__main__":
    sys.settrace(record)
    try:
        result = experiment.run([sys.argv[1]])[0]
    finally:
        sys.settrace(None)
    print(json.dumps({"observation": result, "events": events}))
